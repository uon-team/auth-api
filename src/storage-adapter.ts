import { IUser, IAccessToken } from "./auth.model";


export abstract class AuthStorageAdapter {

    abstract readUser(username: string): Promise<IUser>;

    abstract readAccessToken(jti: string): Promise<IAccessToken>;

    abstract deleteAccessToken(jti: string): Promise<void>;

    /**
     * Insert a new access token
     * Implementors must set id property on the object
     * @param at 
     */
    abstract insertAccessToken(at: IAccessToken): Promise<IAccessToken>;

    abstract updateAccessToken(at: IAccessToken): Promise<IAccessToken>;

   

}