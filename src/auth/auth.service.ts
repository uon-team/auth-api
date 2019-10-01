
import { Injectable, Inject, Type, Injector, StringUtils } from '@uon/core';
import { DbService, DbContext } from '@uon/db';
import { AUTH_MODULE_CONFIG, AuthModuleConfig } from './config';
import { Encode, JwtToken, JwtPayload, Decode, VerifyResult, VerifyOptions, Verify, IsVerifyValid } from '@uon/jwt';
import { compare } from 'bcryptjs';
import { IUserModel, AccessToken } from './auth.model';
import { Cookies, OutgoingResponse, IncomingRequest } from '@uon/http';
import { AuthStorageAdapter } from 'src/storage-adapter';


export interface ExchangeCredentialsResult {
    token: string;
    user: IUserModel;
    expires: number;
}

@Injectable()
export class AuthService {


    constructor(@Inject(AUTH_MODULE_CONFIG) private config: AuthModuleConfig,
        private storage: AuthStorageAdapter,
        private injector: Injector) {

    }

    get cookieName() {
        return this.config.token.cookieName;
    }

    get expiresHeaderName() {
        return this.config.token.expiresHeaderName;
    }


    /**
     * Exchange a credential pair for a token
     * @param username 
     * @param password 
     */
    async exchangeCredentials(
        username: string,
        password: string,
        userAgent: string,
        clientIp: string): Promise<ExchangeCredentialsResult> {

        // find the user by username
        const user: IUserModel = await this.storage.readUser(username);
        
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

        const exp = Date.now() + this.config.token.duration;
        const iat = Date.now();


        // create an access token in the db
        const access_token: AccessToken = Object.assign(new AccessToken(), {
            userAgent,
            clientIp,
            userId: user.id,
            expiresOn: new Date(exp + this.config.token.refreshWindow),
            createdOn: new Date(iat)
        });
        await this.storage.insertAccessToken(access_token);


        // create a jwt payload
        const payload: JwtPayload = {
            ...this.config.token.issuer && { iss: this.config.token.issuer },
            sub: user.id,
            jti: access_token.id,
            exp,
            iat
        }

        // encode jwt to string
        const token = Encode(payload, this.config.token.secret[0], this.config.token.algorithm);

        // the cookie expiry date
        const expires = exp + this.config.token.refreshWindow

        // remove password from user object
        user.password = undefined;

        // return the jwt
        return { token, user, expires };

    }


    /**
     * 
     * @param token 
     */
    async invalidateToken(token: JwtToken) {

        await this.storage.deleteAccessToken(token.payload.jti);

    }

    /**
     * 
     * @param token 
     */
    async refreshToken(oldToken: JwtToken) {

        // find an access token in the db
        const access_token: AccessToken = await this.storage.readAccessToken(oldToken.payload.jti); 
        //await db.findOne(AccessToken, { id: oldToken.payload.jti });

        // if no access token can be found, we cannot refresh
        if (!access_token) {
            return null;
        }

        let guards = this.config.refreshGuards || [];

        for (let i = 0; i < guards.length; ++i) {
            let s = await this.injector.instanciateAsync(guards[i]);
            let res = await s.checkGuard(access_token);

            if (!res) {
                return null;
            }
        }


        // all good for refresh, get new expiration date and issued-at date
        const exp = Date.now() + this.config.token.duration;
        const iat = Date.now();

        // copy orginal payload
        const payload = Object.assign({}, oldToken.payload);

        // update dates
        payload.iat = iat;
        payload.exp = exp;

        // encode new payload to jwt
        const token = Encode(payload, this.config.token.secret[0], this.config.token.algorithm);

        // new cookie expiration date
        const expires = exp + this.config.token.refreshWindow;

        // increment refresh count
        access_token.refreshCount++;
        access_token.refreshedOn = new Date();
        access_token.expiresOn = new Date(exp + this.config.token.refreshWindow);

        // save access_token
        await this.storage.updateAccessToken(access_token);

        //await db.updateOne(access_token);

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

        if (token && token != 'null') {

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

        this.response.use(this.cookies);

        // try generating a new token on the service
        const refresh_result = await this.service.refreshToken(this._token);

        // couldn't refresh, expire cookie
        if (!refresh_result) {
            this.cookies.setCookie(this.config.token.cookieName,
                null,
                {
                    httpOnly: true,
                    expires: new Date(0),
                    maxAge: 0
                }
            );
            return false;
        }

        // reset auth context
        this._valid = true;
        this._token = Decode(refresh_result.token);

        // set cookie
        this.cookies.setCookie(this.config.token.cookieName,
            refresh_result.token,
            {
                httpOnly: true,
                expires: new Date(refresh_result.expires),
                maxAge: this.config.token.refreshWindow / 1000
            }
        );

        // reset request cookie in case we want to internally use mockRequest
        this.request.headers.cookie = this.request.headers.cookie.replace(
            new RegExp(`${this.config.token.cookieName}=([^;]+)`),
            `${this.config.token.cookieName}=${refresh_result.token}`
        );

        // set expires header
        this.response.setHeader(
            this.config.token.expiresHeaderName,
            (new Date(refresh_result.expires)).toUTCString()
        );

        // set cors expose header
        this.response.setHeader('Access-Control-Expose-Headers',
            this.config.token.expiresHeaderName
        );

        return true;
    }

    /**
     * Invalidate the current token
     */
    async invalidate() {

        this.cookies.setCookie(this.config.token.cookieName,
            null,
            {
                httpOnly: true,
                expires: new Date(0),
                maxAge: 0
            }
        );
        this.response.use(this.cookies);

        if (this._token) {
            return this.service.invalidateToken(this._token);
        }

    }
}

