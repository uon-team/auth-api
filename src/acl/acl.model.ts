
import { Model, ID, Member, NumberMember, ArrayMember } from '@uon/model';



/**
 * 
 */
export class ResourceUri {


    constructor(public realm: string,
        public collection: string,
        public id: string = '') {

    }

    toString() {
        return `${this.realm}://${this.collection}/${this.id}`;
    }

    static Parse(uri: string) {

        const regex = /^([a-zA-Z0-9_-]+):\/\/([a-zA-Z0-9_-]+)\/(.*)$/;
        const matches = uri.match(regex);
        const res = new ResourceUri(matches[1], matches[2], matches[3]);

        return res;
    }
}


/**
 * Resource access flags
 */
export enum ResourceAccess {

    /**
     * Right to create a resource
     */
    Create = 1 << 0,

    /**
     * Right to read the resource
     */
    Read = 1 << 1,

    /**
     * Right to update the resource
     */
    Update = 1 << 2,

    /**
     * Right to delete the resource
     */
    Delete = 1 << 3,

    /**
     * Right to share the resource with others
     */
    Share = 1 << 4,

    /**
     * Typical owner rights
     */
    Owner = Read | Update | Delete | Share,

    /**
     * Full rights
     */
    Full = Create | Read | Update | Delete | Share,
}


/**
 * An embedded model that represents a resource access permission
 * 
 */
@Model({
    name: 'Grant',
    version: 1
})
export class Grant {

    constructor(uri: string, access: ResourceAccess, source: 'user' | 'role' | 'group') {
        this.uri = uri;
        this.access = access;
        this.source = source;
    }

    /**
     * the resource identifier
     */
    @Member()
    uri: string;

    /**
     * a bit mask describing which type of access is permitted
     */
    @Member()
    access: number;

    /**
     * The claim source type: 'user' | 'role' | 'group'
     */
    @Member()
    source: 'user' | 'role' | 'group';

    /**
     * The id of source object
     */
    @Member()
    sourceId: string;

}



@Model({
    name: 'GroupACL',
    version: 1
})
export class GroupACL {

    /**
     * Unique id for this group
     */
    @ID()
    id: string;

    /**
     * The name of the group
     */
    @Member()
    name: string;

    /**
     * Group description
     */
    @Member()
    description: string;

    /**
     * Grants associated to this group
     */
    @ArrayMember(Grant)
    grants: Grant[];

    /**
     * The role scope, can be 'global' | 'user'
     */
    @Member()
    scope: string;


}



/**
 * Represents all grants for a user
 */
@Model({
    name: 'UserACL',
    version: 1
})
export class UserACL {

    /**
     * Unique ID for this ACL
     */
    @ID()
    id: string;

    /**
     * The unique user id who owns this ACL 
     */
    @Member()
    userId: string;

    /**
     * List of roles assigned to this user
     */
    @ArrayMember(String)
    groupIds: string[];

    /**
     * A list of claims for the user
     */
    @ArrayMember(Grant)
    grants: Grant[];

    /**
     * Last update date
     */
    @Member()
    updatedOn: Date;

}


