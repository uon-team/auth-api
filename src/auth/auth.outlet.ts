
import { RouterOutlet, ActivatedRoute } from "@uon/router";
import { HttpRoute, IncomingRequest, OutgoingResponse, HttpError, Cookies, JsonBodyGuard, JsonBody } from '@uon/http';
import { AuthService, AuthContext, ExchangeCredentialsResult } from "./auth.service";
import { Required } from "@uon/model";
import { Inject } from "@uon/core";
import { AUTH_MODULE_CONFIG, AuthModuleConfig } from "./config";


@RouterOutlet()
export class AuthOutlet {


    constructor(private request: IncomingRequest,
        private response: OutgoingResponse,
        private cookies: Cookies,
        private auth: AuthService,
        private authContext: AuthContext,
        @Inject(AUTH_MODULE_CONFIG) private config: AuthModuleConfig) { }



    @HttpRoute({
        method: 'POST',
        path: '/',
        guards: [
            JsonBodyGuard(null, {
                validate: {
                    username: [Required()],
                    password: [Required()]
                },
                maxLength: 8196
            })
        ]
    })
    async authenticate(body: JsonBody<{ username: string, password: string }>) {

        // remove any old token
        if (this.authContext.jwt) {
            // invalidate token in db
            await this.authContext.invalidate();
        }

        // try and get a token with the provided credentials
        const result = await this.auth.exchangeCredentials(
            body.value.username,
            body.value.password,
            this.request.headers['user-agent'],
            this.request.clientIp);

        if (!result) {
            throw new HttpError(401);
        }


        if(this.config.twoFactorAuthProvider) {
            throw new Error('Not implemented.')
        }
        else {
            this.setAuthSuccessResponse(result);
        }
        

        return this.response.finish();
    }

    @HttpRoute({
        method: 'POST',
        path: '/mfa',
        guards: [
            JsonBodyGuard(null, {
                validate: {
                    token: [Required()],
                    code: [Required()]
                },
                maxLength: 8196
            })
        ]
    })
    async completeMFA(body: JsonBody<{ token: string, code: string }>) {


        // try and get a token with the provided credentials
        /* const result = await this.auth.exchangeCredentials(
             body.value.username,
             body.value.password,
             this.request.headers['user-agent'],
             this.request.clientIp);
 
         if (!result) {
             throw new HttpError(401);
         }*/

        let result: any;

       
        this.setAuthSuccessResponse(result);

        return this.response.finish();
    }


    @HttpRoute({
        method: 'DELETE',
        path: '/'
    })
    async invalidate() {

        if (!this.authContext.jwt) {
            throw new HttpError(400);
        }

        // invalidate token
        await this.authContext.invalidate();

        return this.response.finish();
    }


    @HttpRoute({
        method: 'OPTIONS',
        path: '/'
    })
    async options() {

        return this.response.send(null);
    }



    private setAuthSuccessResponse(result: ExchangeCredentialsResult) {

        this.cookies.setCookie(this.auth.cookieName,
            result.token,
            {
                httpOnly: true,
                expires: new Date(result.expires),
                maxAge: this.config.token.refreshWindow / 1000
            }
        );
        this.response.use(this.cookies);

        // set token expires header
        this.response.setHeader(
            this.auth.expiresHeaderName,
            (new Date(result.expires)).toUTCString()
        );

        // send the user as json response
        this.response.json({
            user: result.user,
            expires: result.expires
        });

    }

}
