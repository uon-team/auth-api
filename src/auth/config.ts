import { RouteGuard } from "@uon/router";
import { Type, InjectionToken } from "@uon/core";
import { IUserModel } from "./auth.model";
import { ITokenRefreshGuard } from "./auth.guard";

export const AUTH_MODULE_CONFIG = new InjectionToken<AuthModuleConfig>("AUTH_MODULE_CONFIG");


export interface AuthTokenOptions {

    /**
     * The name of the cookie storing the token
     * Defaults to '_uat'
     */
    cookieName?: string;

    /**
     * Name of the header set when a token is assigned or refreshed
     * Defaults to 'X-Auth-Token-Expires'
     */
    expiresHeaderName?: string;

    /**
     * The duration of a jwt before it expires, in milliseconds
     * Defaults to 5 minutes
     */
    duration?: number;

    /**
     * The amount of time in milliseconds that a token can be 
     * refreshed after it had expired
     * Defaults to 1 day
     */
    refreshWindow?: number;

    /**
    * The secret to encode and verify jwt
    * If the algorithm is RS or ES, this must be an array 
    * with private [0] and public key [1]
    */
    secret: string | [string, string];

    /**
    * The algorithm to use for encoding jwt
    * Defaults to 'HS384'
    */
    algorithm?: string;


    /**
     * The value to set as the iss field of a jwt
     */
    issuer?: string;


}


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
     * Options for token generation and validation
     */
    token: AuthTokenOptions;

    /**
     * A provider for 2FA
     */
    twoFactorAuthProvider?: any;


}

export const AUTH_CONFIG_DEFAULTS: any  = {

    authPath: '/auth/v0',
    token: {
        cookieName: '_uat',
        expiresHeaderName: 'X-Auth-Token-Expires',
        algorithm: 'HS384',
        duration: 5 * 60 * 1000, // 5 minutes
        refreshWindow: 24 * 60 * 60 * 1000, // 1 day

    }
};



