
import { RouterOutlet, ActivatedRoute } from "@uon/router";
import { HttpRoute, IncomingRequest, OutgoingResponse, HttpError, Cookies, JsonBodyGuard, JsonBody } from '@uon/http';
import { AuthService, AuthContext, ExchangeCredentialsResult } from "./auth.service";
import { Required } from "@uon/model";
import { Inject, Optional } from "@uon/core";
import { AUTH_MODULE_CONFIG, AuthModuleConfig } from "./config";
import { TwoFactorAuthAdapter } from "./two-factor-adapter";


@RouterOutlet()
export class AuthOutlet {


    constructor(private request: IncomingRequest,
        private response: OutgoingResponse,
        private cookies: Cookies,
        private auth: AuthService,
        private authContext: AuthContext,
        @Optional() private twoFactorAdapter: TwoFactorAuthAdapter) { }



    /**
     * Attempt to authenticate a user with username and password
     * This is the
     * @param body 
     */
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
            // invalidate current token
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

        // prepare response object
        const res: any = {
            user: result.user,
            expires: result.expires
        };

        // do 2FA if needed
        if (this.twoFactorAdapter) {

            const twofa_result = await this.twoFactorAdapter.generate(result);

            // if method is none, adapter didnt do anything
            if (twofa_result !== null) {
                res.mfa = twofa_result
            }

        }

        // no mfa, send jwt
        if (!res.mfa) {
            this.authContext.setupSuccessResponse(result);
        }

        // send json response
        this.response.json(res);

        // all done!
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

        if (!this.twoFactorAdapter) {
            throw new HttpError(404);
        }

        // try token and code on adapter
        const result = await this.twoFactorAdapter.validate(body.value.token, body.value.code);

        if (!result) {
            throw new HttpError(401);
        }

        this.authContext.setupSuccessResponse(result);

        // send the user as json response
        this.response.json({
            user: result.user,
            expires: result.expires
        });

        return this.response.finish();
    }


    @HttpRoute({
        method: 'DELETE',
        path: '/'
    })
    async invalidate() {

        if (this.authContext.jwt) {
            // invalidate token
            await this.authContext.invalidate();
        }

        return this.response.finish();
    }


    @HttpRoute({
        method: 'OPTIONS',
        path: '/'
    })
    async options() {

        return this.response.send(null);
    }



}
