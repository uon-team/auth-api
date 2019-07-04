
import { RouterOutlet, ActivatedRoute, RouteParams } from "@uon/router";
import { IncomingRequest, OutgoingResponse, HttpRoute, JsonBodyGuard, JsonBody, HttpError } from "@uon/http";
import { AuthService, AuthContext } from "../auth/auth.service";
import { AclService } from "./acl.service";
import { AclGuard } from "./acl.guard";
import { GroupACL, ResourceAccess, ResourceUri, Grant, UserACL } from "./acl.model";
import { Prohibited, Required } from "@uon/model";
import { DbContext } from "@uon/db";


@RouterOutlet()
export class GroupOutlet {



    constructor(private request: IncomingRequest,
        private response: OutgoingResponse,
        private auth: AuthService,
        private acl: AclService,
        private authContext: AuthContext) { }


    /**
     * List all accessible groups
     */
    @HttpRoute({
        method: 'GET',
        path: '/',
        guards: [
            AclGuard('acl://groups/*', ResourceAccess.Read)
        ]
    })
    async listGroup() {

        const list = await this.acl.list(this.authContext.userId,
            'acl', 'groups',
            ResourceAccess.Read
        );


    }

    /**
     * Get a group
     */
    @HttpRoute({
        method: 'GET',
        path: '/:groupId',
        guards: [
            AclGuard('acl://groups/:groupId', ResourceAccess.Read)
        ]
    })
    async readGroup() {


    }

    /**
    * Create a new group
    * @param body 
    * @param db 
    */
    @HttpRoute({
        method: 'POST',
        path: '/',
        guards: [
            AclGuard('acl://groups/', ResourceAccess.Create),
            JsonBodyGuard(GroupACL, {
                validate: {
                    id: [Prohibited()],
                    name: [Required()],
                    description: [Required()]
                }
            })
        ]
    })
    async createGroup(body: JsonBody<GroupACL>, db: DbContext) {

        const group = body.value;

        // TODO ensure any grants is under the requester's control

        const result = await db.insertOne(group);

        if (result.insertedCount !== 1) {
            throw new HttpError(500);
        }

        // assign a permissions for the new group to the user who created it
        await this.acl.grant(this.authContext.userId,
            new ResourceUri('acl', 'groups', group.id),
            ResourceAccess.Owner
        );

        this.response.statusCode = 201;
        return this.response.finish();

    }

    /**
     * Modify a group
     */
    @HttpRoute({
        method: 'PATCH',
        path: '/:groupId',
        guards: [
            AclGuard('acl://groups/:groupId', ResourceAccess.Update),
            JsonBodyGuard(GroupACL, {
                validate: {
                    id: [Prohibited()]
                }
            })
        ]
    })
    async editGroup() {


    }

    /**
     * Delete a group
     * @param params 
     * @param db 
     */
    @HttpRoute({
        method: 'DELETE',
        path: '/:groupId',
        guards: [
            AclGuard('acl://groups/:groupId', ResourceAccess.Delete),
        ]
    })
    async deleteGroup(params: RouteParams, db: DbContext) {

        // find group
        const group = await db.findOne(GroupACL, { id: params.groupId });

        if (!group) {
            throw new HttpError(404);
        }

        // format grant as they should appear in UserACL
        const new_grants = group.grants.map((g) => {
            let r = new Grant(g.uri, g.access, 'group');
            r.sourceId = group.id;
            return r;
        });

        // detach any acls assigned to this group
        await db.updateMany(UserACL, { groupIds: group.id },
            {
                $pullAll: {
                    groupIds: [group.id],
                    grants: new_grants
                }
            });


        // also remove all acl://groups/id grants
        await db.updateMany(UserACL, { 'grants.uri': `acl://groups/${group.id}` },
            {
                $pull: {
                    grants: { uri: `acl://groups/${group.id}` }
                }
            });

        // finally delete the group itself
        await db.deleteOne(group);


        // all done with server work
        this.response.statusCode = 204;
        return this.response.finish();
    }



}
