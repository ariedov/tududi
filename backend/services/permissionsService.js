const { Op } = require('sequelize');
const { Project, Task, Note, Permission } = require('../models');
const { isAdmin } = require('./rolesService');

const ACCESS = { NONE: 'none', RO: 'ro', RW: 'rw', ADMIN: 'admin' };

async function getSharedUidsForUser(resourceType, userId) {
    const rows = await Permission.findAll({
        where: { user_id: userId, resource_type: resourceType },
        attributes: ['resource_uid'],
        raw: true,
    });
    const set = new Set(rows.map((r) => r.resource_uid));
    return Array.from(set);
}

async function getAccess(userId, resourceType, resourceUid) {
    if (await isAdmin(userId)) return ACCESS.ADMIN;

    // ownership via model
    if (resourceType === 'project') {
        const proj = await Project.findOne({
            where: { uid: resourceUid },
            attributes: ['user_id'],
            raw: true,
        });
        if (!proj) return ACCESS.NONE;
        if (proj.user_id === userId) return ACCESS.RW;
    } else if (resourceType === 'task') {
        const t = await Task.findOne({
            where: { uid: resourceUid },
            attributes: ['user_id', 'project_id'],
            raw: true,
        });
        if (!t) return ACCESS.NONE;
        if (t.user_id === userId) return ACCESS.RW;

        // Check if user has access through the parent project
        if (t.project_id) {
            const project = await Project.findOne({
                where: { id: t.project_id },
                attributes: ['uid'],
                raw: true,
            });
            if (project) {
                const projectAccess = await getAccess(
                    userId,
                    'project',
                    project.uid
                );
                if (projectAccess !== ACCESS.NONE) {
                    return projectAccess; // Inherit access from project
                }
            }
        }
    } else if (resourceType === 'note') {
        const n = await Note.findOne({
            where: { uid: resourceUid },
            attributes: ['user_id', 'project_id'],
            raw: true,
        });
        if (!n) return ACCESS.NONE;
        if (n.user_id === userId) return ACCESS.RW;

        // Check if user has access through the parent project
        if (n.project_id) {
            const project = await Project.findOne({
                where: { id: n.project_id },
                attributes: ['uid'],
                raw: true,
            });
            if (project) {
                const projectAccess = await getAccess(
                    userId,
                    'project',
                    project.uid
                );
                if (projectAccess !== ACCESS.NONE) {
                    return projectAccess; // Inherit access from project
                }
            }
        }
    }

    // shared
    const perm = await Permission.findOne({
        where: {
            user_id: userId,
            resource_type: resourceType,
            resource_uid: resourceUid,
        },
        attributes: ['access_level'],
        raw: true,
    });
    return perm ? perm.access_level : ACCESS.NONE;
}

async function ownershipOrPermissionWhere(resourceType, userId) {
    // Admin users can see all resources
    if (await isAdmin(userId)) {
        return {}; // empty where clause = no restriction
    }

    const sharedUids = await getSharedUidsForUser(resourceType, userId);

    // For tasks and notes, also include items from shared projects
    if (resourceType === 'task' || resourceType === 'note') {
        const sharedProjectUids = await getSharedUidsForUser('project', userId);

        // Get the project IDs for shared projects
        let sharedProjectIds = [];
        if (sharedProjectUids.length > 0) {
            const projects = await Project.findAll({
                where: { uid: { [Op.in]: sharedProjectUids } },
                attributes: ['id'],
                raw: true,
            });
            sharedProjectIds = projects.map((p) => p.id);
        }

        const conditions = [
            { user_id: userId }, // Items owned by user
        ];

        if (sharedUids.length > 0) {
            conditions.push({ uid: { [Op.in]: sharedUids } }); // Items directly shared with user
        }

        if (sharedProjectIds.length > 0) {
            conditions.push({ project_id: { [Op.in]: sharedProjectIds } }); // Items in shared projects
        }

        return { [Op.or]: conditions };
    }

    // For other resource types (projects, etc.), use the original logic
    return {
        [Op.or]: [
            { user_id: userId },
            sharedUids.length
                ? { uid: { [Op.in]: sharedUids } }
                : { uid: null },
        ],
    };
}

module.exports = {
    ACCESS,
    getAccess,
    ownershipOrPermissionWhere,
    getSharedUidsForUser,
};
