
import { Injectable } from '@uon/core';
import { IRouteGuardService, ActivatedRoute } from "@uon/router";
import { IncomingRequest, HttpError } from "@uon/http";
import { ResourceAccess, ResourceUri } from './acl.model';
import { AuthContext } from '../auth/auth.service';
import { AclService } from './acl.service';



/**
 * 
 * @param uri 
 */
export function AclGuard(uri: string, accessFlag: ResourceAccess) {
    return class extends AclGuardService {

        async checkGuard(ar: ActivatedRoute<any>): Promise<boolean> {

            // we must have a valid jwt
            if (!this.authContext.valid) {
                throw new HttpError(401);
            }

            // resolve uri with route params
            const resolved_uri = uri.replace(/\:([a-zA-Z]+)(?=\/|$)/g, function (_, n) {
                return ar.params[n];
            });

            // run check against db
            const result = await this.acl.check(
                this.authContext.jwt.payload.sub as string,
                resolved_uri,
                accessFlag
            );

            // result has to be true to continue
            if (result !== true) {

                // makes more sense to send a 404 when user has 
                // no resources under a given collection
                const parsed = ResourceUri.Parse(resolved_uri);
                const code = parsed.id === '*' ? 404 : 403;
                throw new HttpError(code);
            }

            return true;
        }

    }

}



@Injectable()
export class AclGuardService {

    constructor(public request: IncomingRequest,
        public authContext: AuthContext,
        public acl: AclService) { }


}
