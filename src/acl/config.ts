import { InjectionToken } from "@uon/core";
import { RouteGuard } from "@uon/router";


export const ACL_MODULE_CONFIG = new InjectionToken<AclModuleConfig>("ACL_MODULE_CONFIG");


export interface AclModuleConfig {


    /**
     * Base path for the acl router
     */
    aclPath?: string;

    /**
     * Guards for the acl router
     */
    guards?: RouteGuard[];

    /**
     * The db name (declared with @uon/db/DbModule) for storing user data
     */
    dbName: string;

}

export const ACL_CONFIG_DEFAULTS = {
    aclPath: '/acl/v0'
};
