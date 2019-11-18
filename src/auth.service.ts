
import { Injectable, Inject, Type, Injector, StringUtils, Optional, IsType } from '@uon/core';
import { AUTH_MODULE_CONFIG, AuthModuleConfig } from './config';
import { Encode, JwtToken, JwtPayload, Decode, VerifyResult, VerifyOptions, Verify, IsVerifyValid } from '@uon/jwt';
import { compare } from 'bcryptjs';
import { IUser, IAccessToken } from './auth.model';
import { Cookies, OutgoingResponse, IncomingRequest } from '@uon/http';
import { AuthStorageAdapter } from './storage-adapter';
import { access } from 'fs';
import { AuthPayloadAdapter } from './payload-adapter';


export interface ExchangeCredentialsResult {
    tokenId?: string;
    token: string;
    user?: IUser;
    expires: number;
}

@Injectable()
export class AuthService {


    constructor(
        @Inject(AUTH_MODULE_CONFIG) private _config: AuthModuleConfig,
        private storage: AuthStorageAdapter,
        private injector: Injector,
        @Optional() private payloadAdapter: AuthPayloadAdapter) {

    }


    /**
     * Simpler access to config object
     */
    get config() {
        return this._config;
    }

    /**
     * Exchange a credential pair for a token
     * @param username 
     * @param password 
     */
    async exchangeCredentials(username: string, password: string): Promise<ExchangeCredentialsResult> {

        // find the user by username
        const user: IUser = await this.storage.readUser(username);

        // cannot continue without a user
        if (!user) {
            return null;
        }

        // compare password with hash
        const pass_match = await compare(password, user.password);

        // password must match to continue
        if (!pass_match) {
            return null;
        }

        // remove password from user object
        user.password = undefined;
        delete user.password;


        const exp = Date.now() + this._config.token.duration;
        const iat = Date.now();

        // create an access token in the db
        const access_token: IAccessToken = {
            id: undefined,
            userId: user.id,
            expiresOn: new Date(exp + this._config.token.refreshWindow),
            createdOn: new Date(iat),
            refreshedOn: new Date(iat)
        };

        const new_access_token = await this.storage.insertAccessToken(access_token);

        // ensure that id was set by adapter
        if (!new_access_token.id) {
            throw new Error(`You must set 'id' on access token`);
        }


        // create a jwt payload
        const payload: JwtPayload = {
            ...this._config.token.issuer && { iss: this._config.token.issuer },
            sub: user.id,
            jti: new_access_token.id,
            exp,
            iat
        };

        if (this.payloadAdapter) {
            await this.payloadAdapter.modifyPayload(payload);
        }

        // encode jwt to string
        const token = Encode(payload,
            this._config.token.secret[0],
            this._config.token.algorithm
        );

        // the cookie expiry date
        const expires = exp + this._config.token.refreshWindow


        // return the jwt
        return { tokenId: new_access_token.id, token, user, expires };

    }


    /**
     * 
     * @param token 
     */
    async invalidateToken(tokenId: string) {

        await this.storage.deleteAccessToken(tokenId);

    }

    /**
     * 
     * @param token 
     */
    async refreshToken(oldToken: JwtToken, request: IncomingRequest) {

        // find an access token in the db
        const access_token: IAccessToken = await this.storage.readAccessToken(oldToken.payload.jti);

        // if no access token can be found, we cannot refresh
        if (!access_token) {
            return null;
        }

        let guards = this._config.refreshGuards || [];

        for (let i = 0; i < guards.length; ++i) {
            let s = await this.injector.instanciateAsync(guards[i]);
            let res = await s.checkGuard(access_token, request);

            if (!res) {
                return null;
            }
        }

        // all good for refresh, get new expiration date and issued-at date
        const exp = Date.now() + this._config.token.duration;
        const iat = Date.now();

        // copy orginal payload
        const payload = Object.assign({}, oldToken.payload);

        // update dates
        payload.iat = iat;
        payload.exp = exp;

        // encode new payload to jwt
        const token = Encode(payload, this._config.token.secret[0], this._config.token.algorithm);

        // new cookie expiration date
        const expires = exp + this._config.token.refreshWindow;

        access_token.refreshedOn = new Date();
        access_token.expiresOn = new Date(exp + this._config.token.refreshWindow);

        // save access_token
        await this.storage.updateAccessToken(access_token);

        // return the new jwt
        return { token, expires };

    }


}



/**
 * Contains the decoded jwt for the current request
 */
@Injectable()
export class AuthContext {

    private _token: JwtToken = null;
    private _valid: boolean = false;
    private _verified: VerifyResult;

    constructor(private cookies: Cookies,
        private service: AuthService,
        private response: OutgoingResponse,
        private request: IncomingRequest,
        @Inject(AUTH_MODULE_CONFIG) private config: AuthModuleConfig) {

        const token = cookies.getCookie(config.token.cookieName);

        if (token && token.length > 32) {

            const verify_opts: VerifyOptions = {
                exp: true,
                sig: true,
                alg: config.token.algorithm
            };

            const verify_result = Verify(token, config.token.secret[1], verify_opts)
            this._verified = verify_result;

            this._token = verify_result.decoded;
            this._valid = IsVerifyValid(verify_opts, verify_result);

        }

    }

    /**
     * Whether request JWT is valid 
     */
    get valid() {
        return this._valid;
    }

    /**
     * Access to the decoded token
     */
    get jwt() {
        return this._token;
    }

    /**
     * Get the verification results
     */
    get verified() {
        return this._verified;
    }

    /**
     * Shortcut to jwt payload.sub field
     */
    get userId() {
        return this._token ? this._token.payload.sub as string : null;
    }

    /**
     * Refreshes the token for the user
     */
    async refresh() {

        if (!this._token) {
            return false;
        }

        // try generating a new token on the service
        const refresh_result = await this.service.refreshToken(this._token, this.request);

        // couldn't refresh, expire cookie
        if (!refresh_result) {
            await this.invalidate();
            return false;
        }

        // reset auth context
        this._valid = true;
        this._token = Decode(refresh_result.token);

        // set cookie
        this.setupSuccessResponse(refresh_result);

        // reset request cookie in case we want to internally use mockRequest
        this.request.headers.cookie = this.request.headers.cookie.replace(
            new RegExp(`${this.config.token.cookieName}=([^;]+)`),
            `${this.config.token.cookieName}=${refresh_result.token}`
        );



        return true;
    }

    /**
     * Invalidate the current token
     */
    async invalidate() {


        const old_mfa_token = this.cookies.getCookie(this.config.mfaTokenCookieName)


        if (this._token || old_mfa_token) {

            let token_id = this._token
                ? this._token.payload.jti
                : old_mfa_token.substr(0, 24);

            await this.service.invalidateToken(token_id);
        }


        // remove cookies
        this.cookies.setCookie(this.config.token.cookieName, null, {
            httpOnly: true,
            expires: new Date(0),
            maxAge: 0
        });

        this.cookies.setCookie(this.config.mfaTokenCookieName, null, {
            httpOnly: true,
            expires: new Date(0),
            maxAge: 0
        });

        // make sure response uses cookies
        this.response.use(this.cookies);


    }

    setupSuccessResponse(result: ExchangeCredentialsResult) {

        // make sure we use cookies
        this.response.use(this.cookies);

        // set the token
        this.cookies.setCookie(this.config.token.cookieName,
            result.token,
            {
                httpOnly: true,
                expires: new Date(result.expires),
                maxAge: this.config.token.refreshWindow / 1000
            }
        );

        // set token expires header
        this.response.setHeader(
            this.config.token.expiresHeaderName,
            (new Date(result.expires)).toUTCString()
        );

        // set cors expose header
        this.response.setHeader('Access-Control-Expose-Headers',
            this.config.token.expiresHeaderName
        );

    }
}

