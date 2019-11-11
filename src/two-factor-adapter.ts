import { ExchangeCredentialsResult } from "./auth.service";
import { IUser } from "./auth.model";


export interface AuthTwoFactorGenResult {


    /**
     * The selected method for MFA, ie. sms, email
     */
    method: string;

    /**
     * Unique token that the user needs to pass back to validate
     */
    token: string;

    /**
     * When the code will expire
     */
    expires: number;


    /**
     * User defined props
     */
    [k: string]: any;


}

export abstract class AuthTwoFactorAdapter {


    /**
     * Generate an OTP and a token to reference it
     * Implementers must securely store the ExchangeCredentialsResult object 
     * and pass it back when validate is called
     * If null is return from this call, the 2fa mechanism is bypassed and 
     * user gets authenticated
     * @param result 
     */
    abstract generate(result: ExchangeCredentialsResult): Promise<AuthTwoFactorGenResult>;

    /**
     * Validate a code
     * @param token 
     * @param code 
     */
    abstract validate(token: string, code: string): Promise<ExchangeCredentialsResult>;
}