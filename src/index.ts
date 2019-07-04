import { DbCollectionDefinition } from '@uon/db';
import { UserACL, GroupACL } from './acl/acl.model';
import { AccessToken } from './auth/auth.model';



export * from './auth/auth.module';
export * from './auth/auth.service';
export * from './auth/auth.guard';
export * from './auth/auth.model';

export * from './acl/acl.module';
export * from './acl/acl.service';
export * from './acl/acl.guard';
export * from './acl/acl.model';


export const AUTH_API_COLLECTIONS: DbCollectionDefinition<any>[] = [

    {
        name: 'auth_user_acl',
        model: UserACL,
        indices: [
            {
                name: 'user_id_index',
                fields: {
                    userId: 1
                }
            },
            {
                name: 'groups_index',
                fields: {
                    groupIds: 1
                }
            },
            {
                name: 'resource_index',
                fields: {
                    'grants.uri': 1,
                    'grants.access': 1,
                    'grants.source': 1,
                    'grants.sourceId': 1
                },
                sparse: true
    
            }
        ]
    },

    {
        name: 'auth_group_acl',
        model: GroupACL,
        indices: [
            {
                name: 'group_name_index',
                fields: {
                    name: 1
                }
            },
            {
                name: 'resource_index',
                fields: {
                    'grants.uri': 1,
                    'grants.access': 1
                }
    
            }
        ]
    },

    {
        name: 'auth_access_tokens',
        model: AccessToken,
        indices: [
            {
                name: 'expires_index',
                fields: {
                    expiresOn: 1
                },
                expireAfterSeconds: 0
            }
        ]
    }



]; 