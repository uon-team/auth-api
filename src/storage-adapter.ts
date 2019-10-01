import { IUserModel, AccessToken } from "./auth/auth.model";


export abstract class AuthStorageAdapter {

    abstract readUser(username: string): Promise<IUserModel>;

    abstract readAccessToken(jti: string): Promise<AccessToken>;

    abstract insertAccessToken(at: AccessToken): Promise<AccessToken>;

    abstract updateAccessToken(at: AccessToken): Promise<AccessToken>;

    abstract deleteAccessToken(jti: string): Promise<void>;

}