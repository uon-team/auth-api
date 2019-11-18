import { IUser, IAccessToken } from "./auth.model";


export abstract class AuthStorageAdapter {


    /**
     * Fetch a user when exchanging credentials
     * @param username 
     */
    abstract readUser(username: string): Promise<IUser>;


    /**
     * Fetch an access token by id
     * @param jti 
     */
    abstract readAccessToken(jti: string): Promise<IAccessToken>;

    /**
     * Remove an access token
     * @param jti 
     */
    abstract deleteAccessToken(jti: string): Promise<void>;

    /**
     * Insert a new access token
     * Implementors must set id property on the object
     * @param at 
     */
    abstract insertAccessToken(at: IAccessToken): Promise<IAccessToken>;


    /**
     * Update access token
     * @param at 
     */
    abstract updateAccessToken(at: IAccessToken): Promise<IAccessToken>;

   

}