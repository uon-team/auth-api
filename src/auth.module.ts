
import { Module, ModuleWithProviders, Type, Inject, APP_INITIALIZER, Optional } from '@uon/core';
import { Router, RouteGuard } from '@uon/router';
import { HttpRoute, HTTP_ROUTER, HTTP_PROVIDERS } from '@uon/http';
import { AuthModuleConfig, AUTH_MODULE_CONFIG, AUTH_CONFIG_DEFAULTS } from './config';

import { AuthOutlet } from './auth.outlet';
import { AuthService, AuthContext } from './auth.service';

@Module({
    imports: [],
    providers: [
        AuthService
    ],
    declarations: [
        AuthOutlet
    ]
})
export class AuthModule {

    constructor(@Optional() @Inject('AUTH_API_ROUTES') _routes: any,
        @Inject(HTTP_ROUTER) _router: any) {

        if (!_routes) {
            throw new Error('AuthModule needs to be imported using AuthModule.WithConfig()');
        }
    }

    static WithConfig(config: AuthModuleConfig): ModuleWithProviders {


        const merged_config = Object.assign({}, AUTH_CONFIG_DEFAULTS, config);
        merged_config.token = Object.assign({}, AUTH_CONFIG_DEFAULTS.token, config.token);

        // format token secret to array
        if (!Array.isArray(merged_config.token.secret)) {

            if (!merged_config.token.algorithm.startsWith('HS')) {
                throw new Error(`AuthModule: You must provide a private and public key as array elements for algorithm ${merged_config.tokenAlgorithm}`);
            }

            merged_config.tokenSecret = [merged_config.token.secret as string, merged_config.token.secret as string];
        }

        // prevent further modifications to config
        Object.freeze(merged_config);

        return {
            module: AuthModule,
            providers: [

                /**
                 * Provides the auth module configuration
                 */
                {
                    token: AUTH_MODULE_CONFIG,
                    value: merged_config
                },


                /**
                 * Provide AuthContext to HttpContext
                 */
                {
                    token: HTTP_PROVIDERS,
                    value: [
                        AuthContext
                    ],
                    multi: true
                },

                /**
                 * Provides auth routes to http router 
                 */
                {
                    token: 'AUTH_API_ROUTES',
                    factory: (router: Router<HttpRoute>) => {
                        router.add({
                            path: merged_config.authPath,
                            outlet: AuthOutlet,
                            guards: merged_config.guards || [],
                        });
                        return true;
                    },
                    deps: [HTTP_ROUTER]
                }
            ]
        }

    }
}
