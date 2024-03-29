
import { Injectable } from '@uon/core';
import { IRouteGuardService, ActivatedRoute } from "@uon/router";
import { HttpError, OutgoingResponse, IncomingRequest } from '@uon/http';
import { AuthContext } from './auth.service';
import { IAccessToken } from './auth.model';


/**
 * RouterGuard to check prevent unauthorized access.
 * Also provides the means to refresh a token on expiration.
 */
@Injectable()
export class AuthGuard implements IRouteGuardService {

    constructor(private authContext: AuthContext, 
        private request: IncomingRequest,
        private response: OutgoingResponse) { }

    async checkGuard(route: ActivatedRoute) {

        // no token at all
        if (!this.authContext.jwt) {
            throw new HttpError(401);
        }

        // if a jwt is present and valid we can continue
        if (this.authContext.valid === true) {
            return true;
        }

        // if the token signature is valid but token expired
        // we want to refresh it
        if (this.authContext.verified.sig === true &&
            this.authContext.verified.exp === false) {

            // try and do a refresh
            const refresh_success = await this.authContext.refresh();

            // refresh might not have succeeded, make sure it did
            if (refresh_success === true) {
                return true;
            }
        }

        // in other cases, not authorized
        throw new HttpError(401);
    }
}

/**
 * Interface for token refresh checks
 */
export interface ITokenRefreshGuard {
    checkGuard(accessToken: IAccessToken, request: IncomingRequest): Promise<boolean>;
}
