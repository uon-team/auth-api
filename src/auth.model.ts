

/**
 * The minimum interface for a user
 */
export interface IUser {

    /**
     * The unique user id
     */
    id: string;

    /**
     * The unique user username
     */
    username: string;

    /**
     * The hashed user password
     */
    password: string;

    /**
     * any other fields
     */
    [k: string]: any;
}


/**
 * The minimum access token interface
 */
export interface IAccessToken {

    /**
     * Unique id for this access token
     */
    id: string;

    /**
     * The unique user id associated with this token
     */
    userId: string;


    /**
     * The date this token was created
     */
    createdOn: Date;

    /**
     * Date when this token was last refreshed automatically
     */
    refreshedOn: Date;

    /**
     * The date the token is meant to expire
     */
    expiresOn: Date;
}


