import { RouteGuard } from "@uon/router";
import { Type, InjectionToken } from "@uon/core";
import { IUserModel } from "./auth.model";
import { ITokenRefreshGuard } from "./auth.guard";

export const AUTH_MODULE_CONFIG = new InjectionToken<AuthModuleConfig>("AUTH_MODULE_CONFIG");

//export const AUTH_TOKEN_REFRESH_GUARDS = new InjectionToken<any[]>("AUTH_TOKEN_REFRESH_GUARDS");

export type RefreshCheckFunc = () => Promise<boolean>



/**
 * Configuration options for authentication module 
 */
export interface AuthModuleConfig {

    /**
     * Base path for the auth router
     */
    authPath: string;

    /**
     * Guards for the auth router
     */
    guards?: RouteGuard[];

    /**
     * A list of refresh guard types to invoke on token refresh
     */
    refreshGuards?: Type<ITokenRefreshGuard>[];

    /**
     * The db name (declared with @uon/db/DbModule) for storing user data
     */
    dbName: string;

    /**
     * The user model class to use
     */
    userModelClass: Type<IUserModel>;

    /**
     * The name of the field on the model which corresponds to
     * the user's unique username
     * Defaults to 'username'
     */
    usernameField?: string;

    /**
     * The name of the cookie storing the token
     * Defaults to '_uat'
     */
    tokenCookieName?: string;

    /**
     * Name of the header set when a token is assigned or refreshed
     * Defaults to 'X-Auth-Token-Expires'
     */
    tokenExpiresHeaderName?: string;

    /**
     * The duration of a jwt before it expires, in milliseconds
     * Defaults to 5 minutes
     */
    tokenDuration?: number;

    /**
     * The amount of time in milliseconds that a token can be 
     * refreshed after it had expired
     * Defaults to 1 day
     */
    tokenRefreshWindow?: number;

    /**
     * The secret to encode and verify jwt
     * If the algorithm is RS or ES, this must be an array 
     * with private [0] and public key [1]
     */
    tokenSecret: string | [string, string];

    /**
     * The algorithm to use for encoding jwt
     * Defaults to 'HS384'
     */
    tokenAlgorithm?: string;

    /**
     * The value to set as the iss field of a jwt
     */
    tokenIssuer?: string;


}

export const AUTH_CONFIG_DEFAULTS = {
    authPath: '/auth/v0',
    usernameField: 'username',
    tokenCookieName: '_uat',
    tokenAlgorithm: 'HS384',
    tokenDuration: 5 * 60 * 1000, // 5 minutes
    tokenRefreshWindow: 24 * 60 * 60 * 1000, // 1 day
    tokenExpiresHeaderName: 'X-Auth-Token-Expires'
};



