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



}

export const ACL_CONFIG_DEFAULTS = {
    aclPath: '/acl/v0'
};
