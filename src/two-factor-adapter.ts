import { ExchangeCredentialsResult } from "./auth.service";
import { IUser } from "./auth.model";


export interface TwoFactorAuthGenResult {


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


}

export abstract class TwoFactorAuthAdapter {

    /**
     * Generate an OTP and a token to reference it
     * Implementers must securely store the ExchangeCredentialsResult object 
     * and pass it back when validate is called
     * @param result 
     */
    abstract generate(result: ExchangeCredentialsResult): Promise<TwoFactorAuthGenResult>;

    /**
     * Validate a code
     * @param token 
     * @param code 
     */
    abstract validate(token: string, code: string): Promise<ExchangeCredentialsResult>;
}