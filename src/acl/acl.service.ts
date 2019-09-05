
import { Injectable, Inject, Injector } from '@uon/core';
import { ResourceAccess, UserACL, Grant, ResourceUri, GroupACL } from './acl.model';

import { DbService, DbContext, Query } from '@uon/db';
import { ACL_MODULE_CONFIG, AclModuleConfig } from './config';


const DEFAULT_SOURCES = ['user', 'group'];

@Injectable()
export class AclService {

    private _db: DbContext;

    constructor(@Inject(ACL_MODULE_CONFIG) private config: AclModuleConfig,
        private dbService: DbService,
        private injector: Injector) {

    }

    /**
     * Check if a user has access to the given resource
     * @param userId 
     * @param uri 
     * @param access 
     */
    async check(userId: string, uri: string, access: ResourceAccess, sources: string[] = DEFAULT_SOURCES) {

        const db = await this.getDbContext();

        const parsed = ResourceUri.Parse(uri);
        const wild_card = `${parsed.realm}://${parsed.collection}/`;

        // in the case id === '*' user requests any prefix match
        const uri_match = parsed.id === '*' ? new RegExp(`^${wild_card}(.*)`) : { $in: [uri, wild_card] }

        // just need to find one match to authorize access
        const acl: UserACL = await db.findOne(
            UserACL,
            {
                userId,
                grants: {
                    $elemMatch: {
                        uri: uri_match,
                        access: { $bitsAllSet: access }
                    }
                }
            },
            {
                projection: { _id: 1 as 1 }
            }
        );



        return acl !== null;
    }

    /**
     * Retrieve a list of accessible resources, given a realm, 
     * collection and accessFlag
     * 
     * @return true if access is unrestricted, 
     * otherwise an array of resource ids
     * 
     * @param userId 
     * @param realm 
     * @param collection 
     * @param minimumAccess 
     */
    async list(userId: string, realm: string, collection: string, minimumAccess: ResourceAccess) {

        const db = await this.getDbContext();

        const acl: UserACL = await db.findOne(UserACL, { userId });

        const prefix = `${realm}://${collection}/`
        const resource_ids: string[] = [];

        for (let i = 0; i < acl.grants.length; ++i) {

            let grant = acl.grants[i];
            let access = (grant.access & minimumAccess);

            if (grant.uri === prefix && access == minimumAccess) {
                return true;
            }

            if (grant.uri.startsWith(prefix) && access == minimumAccess) {
                let res = ResourceUri.Parse(grant.uri);
                resource_ids.push(res.id);
            }

        }

        return resource_ids;

    }


    /**
     * Adds a grant for a user
     * @param userId 
     * @param uri 
     * @param access 
     */
    async grant(userId: string, uri: ResourceUri | ResourceUri[], access: ResourceAccess) {

        const db = await this.getDbContext();

        if (!Array.isArray(uri)) {
            uri = [uri];
        }

        const grants = uri.map(u => new Grant(u.toString(), access, 'user'));

        let acl: UserACL = await db.findOne(UserACL, { userId });

        if (!acl) {
            acl = new UserACL();
            acl.userId = userId;
            acl.groupIds = [];
        }

        acl.updatedOn = new Date();

        await db.updateOne(acl, {
            $addToSet: { grants: { $each: grants } },
            $setOnInsert: { createdOn: acl.updatedOn }
        }, { upsert: true });


    }

    /**
     * Revokes a grant for a user
     * @param userId 
     * @param uri 
     */
    async revoke(userId: string, uri: ResourceUri | ResourceUri[]) {

        const db = await this.getDbContext();

        if (!Array.isArray(uri)) {
            uri = [uri];
        }

        let uris = uri.map(u => u.toString());

        await db.updateMany(UserACL, { userId }, {
            $pull: {
                grants: {
                    uri: { $in: uris },
                    source: 'user'
                }
            },
            $currentDate: {
                updatedOn: true
            }
        });

    }

    /**
     * Revokes a grant on everyone
     * @param userId 
     * @param uri 
     */
    async revokeResource(uri: ResourceUri | ResourceUri[]) {

        const db = await this.getDbContext();

        if (!Array.isArray(uri)) {
            uri = [uri];
        }

        let uris = uri.map(u => u.toString());

        const query: Query<UserACL> = {
            grants: {
                $elemMatch: {
                    uri: { $in: uris },
                    source: 'user'
                }
            }
        };

        await db.updateMany(UserACL, query, {
            $pull: {
                grants: {
                    uri: { $in: uris },
                    source: 'user'
                }
            },
            $currentDate: {
                updatedOn: true
            }
        });

    }

    /**
     * Assign a group for the user
     * @param userId 
     * @param groupId 
     */
    async assignGroup(userId: string, groupId: string, db?: DbContext) {

        if (!db) {
            db = await this.getDbContext();
        }

        const group: GroupACL = await db.findOne(GroupACL, { id: groupId });

        if (!group) {
            throw new Error('Group does not exist.');
        }

        // format grants as they appear in user acl
        const new_grants = group.grants.map((g) => {
            let r = new Grant(g.uri, g.access, 'group');
            r.sourceId = groupId;
            return r;
        });

        // update user acl
        const result = await db.updateMany(UserACL, { userId }, {
            $addToSet: {
                groupIds: groupId,
                grants: { $each: new_grants }
            },
            $currentDate: {
                updatedOn: true
            }
        });

        return result.modifiedCount === 1;

    }

    /**
    * Revoke a group from the user
    * @param userId 
    * @param groupId 
    */
    async revokeGroup(userId: string, groupId: string, db?: DbContext) {

        if (!db) {
            db = await this.getDbContext();
        }

        const group: GroupACL = await db.findOne(GroupACL, { id: groupId });

        if (!group) {
            throw new Error('Group does not exist.');
        }

        // format grants as they appear in user acl
        const new_grants = group.grants.map((g) => {
            let r = new Grant(g.uri, g.access, 'group');
            r.sourceId = groupId;
            return r;
        });

        // update user acl
        const result = await db.updateMany(UserACL, { userId }, {
            $pullAll: {
                groupIds: [groupId],
                grants: new_grants
            },
            $currentDate: {
                updatedOn: true
            }
        });

        return result.modifiedCount === 1;

    }



    private async getDbContext() {

        if (!this._db) {
            this._db = await this.dbService.createContext(this.config.dbName, [], this.injector);
        }

        return this._db;
    }

}
