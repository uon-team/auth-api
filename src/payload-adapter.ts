import { JwtPayload } from "@uon/jwt";



export abstract class AuthPayloadAdapter {

    abstract modifyPayload(payload: JwtPayload): Promise<void>;

}