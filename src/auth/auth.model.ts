
import { Model, ID, Member, ArrayMember } from '@uon/model';


export interface IUserModel {
    id: string;
    username?: string;
    email?: string;
    password: string;
}


@Model()
export class AccessToken {

    @ID()
    id: string;

    @Member()
    userAgent: string;

    @Member()
    clientIp: string;

    @Member()
    userId: string;

    @Member()
    refreshCount: number = 0;

    @Member()
    refreshedOn: Date;

    @Member()
    createdOn: Date;

    @Member()
    expiresOn: Date;

}

