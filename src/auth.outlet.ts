
import { RouterOutlet, ActivatedRoute } from "@uon/router";
import { HttpRoute, IncomingRequest, OutgoingResponse, HttpError, Cookies, JsonBodyGuard, RequestBody } from '@uon/http';
import { AuthService, AuthContext, ExchangeCredentialsResult } from "./auth.service";
import { Required } from "@uon/model";
import { Inject, Optional } from "@uon/core";
import { AUTH_MODULE_CONFIG, AuthModuleConfig } from "./config";
import { AuthTwoFactorAdapter } from "./two-factor-adapter";

@RouterOutlet()
export class AuthOutlet {

    constructor(private request: IncomingRequest,
        private response: OutgoingResponse,
        private cookies: Cookies,
        private auth: AuthService,
        private authContext: AuthContext,
        @Optional() private twoFactorAdapter: AuthTwoFactorAdapter) { }

    /**
     * Attempt to authenticate a user with username and password
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
    async authenticate(body: RequestBody<{ username: string, password: string }>) {

        const old_mfa_token = this.cookies.getCookie(this.auth.config.mfaTokenCookieName)

        // remove any old token
        if (this.authContext.jwt || old_mfa_token) {
            // invalidate current token
            await this.authContext.invalidate();
        }

        // try and get a token with the provided credentials
        const result = await this.auth.exchangeCredentials(
            body.value.username,
            body.value.password
        );

        if (!result) {
            throw new HttpError(401);
        }

        // if 2fa is defined, generate a code 
        const twofa_result = this.twoFactorAdapter && await this.twoFactorAdapter.generate(result);

        // do 2FA if needed
        if (twofa_result !== null) {

            // set the mfa token in cookies
            this.cookies.setCookie(this.auth.config.mfaTokenCookieName,
                result.tokenId + twofa_result.token,
                {
                    httpOnly: true,
                    expires: new Date(twofa_result.expires),
                    maxAge: this.auth.config.token.duration / 1000
                }
            );

            this.response.use(this.cookies);

            // send json response
            this.response.json({
                type: '2fa',
                result: twofa_result
            });


        }
        else {

            // set cookies and headers
            this.authContext.setupSuccessResponse(result);

            // send json response
            this.response.json({
                type: 'auth',
                result: {
                    user: result.user,
                    expires: result.expires
                }
            });

        }

        // all done!
        return this.response.finish();
    }

    @HttpRoute({
        method: 'POST',
        path: '/mfa',
        guards: [
            JsonBodyGuard(null, {
                validate: {
                    code: [Required()]
                },
                maxLength: 128
            })
        ]
    })
    async validateMFA(body: RequestBody<{ code: string }>) {

        if (!this.twoFactorAdapter) {
            throw new HttpError(404);
        }

        // grab MFA token from cookies
        const mfa_token = this.cookies.getCookie(this.auth.config.mfaTokenCookieName);

        if (!mfa_token) {
            throw new HttpError(401);
        }

        // try token and code on adapter
        const result = await this.twoFactorAdapter
            .validate(mfa_token.substring(24), body.value.code);

        if (!result) {
            throw new HttpError(401);
        }

        // remove the mfa token in cookies
        this.cookies.setCookie(this.auth.config.mfaTokenCookieName, null, {
            httpOnly: true,
            expires: new Date(0),
            maxAge: 0
        });

        // set cookies and headers
        this.authContext.setupSuccessResponse(result);

        // send the user as json response
        this.response.json({
            type: 'auth',
            result: {
                user: result.user,
                expires: result.expires
            }
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
        path: '/(.*)?'
    })
    async options() {

        return this.response.send(null);
    }



}
