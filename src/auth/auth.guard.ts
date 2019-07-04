
import { Injectable } from '@uon/core';
import { IRouteGuardService, ActivatedRoute } from "@uon/router";
import { HttpError, OutgoingResponse } from '@uon/http';
import { AuthContext } from './auth.service';


@Injectable()
export class AuthGuard implements IRouteGuardService {

    constructor(private authContext: AuthContext, private response: OutgoingResponse) { }

    async checkGuard(route: ActivatedRoute) {

        // no token at all
        if (!this.authContext.jwt) {
            throw new HttpError(401);
        }

        // if a jwt is present and valid we can continue
        if (this.authContext.valid) {
            return true;
        }

        // if the token signature is valid but token expired
        // we want to refresh it
        if (this.authContext.verified.sig === true &&
            this.authContext.verified.exp === false) {

            // try and do a refresh
            const refresh_success = await this.authContext.refresh();

            // refresh might not have succeeded, make sure it did
            if (refresh_success) {
                return true;
            }
        }

        // in other cases, not authorised
        throw new HttpError(401);
    }
}
