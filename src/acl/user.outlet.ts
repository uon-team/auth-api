
import { RouterOutlet, ActivatedRoute, RouteParams } from "@uon/router";
import { IncomingRequest, OutgoingResponse, HttpRoute, JsonBodyGuard, JsonBody, HttpError, QueryGuard, RequestQuery } from "@uon/http";
import { AuthService, AuthContext } from "../auth/auth.service";
import { AclService } from "./acl.service";
import { AclGuard } from "./acl.guard";
import { GroupACL, ResourceAccess, ResourceUri, Grant, UserACL } from "./acl.model";
import { Prohibited, Required } from "@uon/model";
import { DbContext, Query } from "@uon/db";

@RouterOutlet()
export class UserOutlet {

    constructor(private request: IncomingRequest,
        private response: OutgoingResponse,
        private auth: AuthService,
        private acl: AclService,
        private authContext: AuthContext) { }


    /**
     * Read a user acl by userId
     */
    @HttpRoute({
        method: 'GET',
        path: '/:userId',
        guards: [
            AclGuard('acl://users/:userId', ResourceAccess.Read)
        ]
    })
    async readUserAcl(params: RouteParams, db: DbContext) {

        const result = await db.findOne(UserACL, { userId: params.userId });

        if (!result) {
            throw new HttpError(404);
        }

        this.response.json(result);

        return this.response.finish();
    }

    /**
     * Assign a grant to a user
     */
    @HttpRoute({
        method: 'POST',
        path: '/:userId',
        guards: [
            AclGuard('acl://users/:userId', ResourceAccess.Update),
            JsonBodyGuard(Grant, {
                validate: {
                    source: [Prohibited()],
                    sourceId: [Prohibited()]
                }
            })
        ]
    })
    async addGrant(params: RouteParams, body: JsonBody<Grant>, db: DbContext) {

        const grant = body.value;

        // TODO ensure the requesting user can grant this claim
        const update_query: Query<UserACL> = {
            userId: params.userId,
            grants: { $elemMatch: { uri: grant.uri, source: 'user' } }
        }

        // try and update existing grant
        const result = await db.updateMany(UserACL, update_query, {
            $set: {
                'grants.$.access': grant.access,
                updatedOn: new Date()
            }
        });

        // if no document was matched, we have to insert the grant
        if (result.matchedCount === 0) {

            grant.source = 'user';

            const result = await db.updateMany(UserACL, { userId: params.userId }, {
                $addToSet: {
                    grants: grant
                },
                $set: {
                    updatedOn: new Date()
                }
            });
        }

        this.response.statusCode = 204;
        return this.response.finish();

    }

    /**
     * Revoke a grant
     */
    @HttpRoute({
        method: 'DELETE',
        path: '/:userId',
        guards: [
            AclGuard('acl://users/:userId', ResourceAccess.Update),
            QueryGuard({
                realm: { required: true },
                coll: { required: true },
                id: {}
            })
        ]
    })
    async removeGrants(params: RouteParams, rq: RequestQuery, db: DbContext) {

        const res_uri = new ResourceUri(rq.realm, rq.coll, rq.id);

        const uri = res_uri.toString();

        const result = await db.updateMany(UserACL, { userId: params.userId }, {
            $pull: {
                grants: {
                    $elemMatch: {
                        uri: uri,
                        source: 'user'
                    }
                }
            }
        });


        this.response.statusCode = 204;
        return this.response.finish();

    }

    /**
     * assign a group to a user
     */
    @HttpRoute({
        method: 'POST',
        path: '/:userId/g/:groupId',
        guards: [
            AclGuard('acl://users/:userId', ResourceAccess.Update),
            AclGuard('acl://groups/:groupId', ResourceAccess.Read)
        ]
    })
    async assignGroup(params: RouteParams, db: DbContext) {

        return this.acl.assignGroup(params.userId, params.groupId, db);

    }

    /**
     * revoke a group from a user
     */
    @HttpRoute({
        method: 'DELETE',
        path: '/:userId/g/:groupId',
        guards: [
            AclGuard('acl://users/:userId', ResourceAccess.Update),
            AclGuard('acl://groups/:groupId', ResourceAccess.Read)
        ]
    })
    async revokeGroup(params: RouteParams, db: DbContext) {

        return this.acl.revokeGroup(params.userId, params.groupId, db);

    }

}
