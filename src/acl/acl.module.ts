
import { Module, ModuleWithProviders, Inject, Optional, Injector, NullInjector } from '@uon/core';
import { HTTP_ROUTER, HttpRoute } from '@uon/http';
import { Router, RouteGuard } from '@uon/router';
import { AclService } from './acl.service';
import { AclModuleConfig, ACL_MODULE_CONFIG, ACL_CONFIG_DEFAULTS } from './config';
import { GroupOutlet } from './group.outlet';
import { UserOutlet } from './user.outlet';
import { AuthGuard } from '../auth/auth.guard';




@Module({
    imports: [],
    providers: [
        AclService
    ]
})
export class AclModule {

    constructor(@Optional() @Inject('ACL_API_ROUTES') _routes: any,
        @Optional() @Inject(HTTP_ROUTER) _router: any) {

        if (!_routes) {
            throw new Error('AclModule needs to be imported using AclModule.WithConfig()');
        }
    }


    static WithConfig(config: AclModuleConfig): ModuleWithProviders<AclModule> {

        const merged_config = Object.assign({}, ACL_CONFIG_DEFAULTS, config);

        const guards: RouteGuard[] = [AuthGuard];


        return {
            module: AclModule,
            providers: [

                {
                    token: ACL_MODULE_CONFIG,
                    value: Object.freeze(merged_config)
                },

                /**
                 * Provides acl routes to http router 
                 */
                {
                    token: 'ACL_API_ROUTES',
                    factory: (injector: Injector) => {

                        const router: Router<HttpRoute> = injector.get(HTTP_ROUTER, null);
                       
                        if (router) {
                            router.add({
                                path: merged_config.aclPath,
                                guards: merged_config.guards || [],
                                children: [
                                    {
                                        path: '/group',
                                        outlet: GroupOutlet,
                                        guards
                                    },
                                    {
                                        path: '/user',
                                        outlet: UserOutlet,
                                        guards
                                    }

                                ]
                            });
                        }


                        return true;
                    },
                    deps: [Injector]
                }

            ]
        }

    }
}
