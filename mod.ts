// deno-lint-ignore-file no-explicit-any
/**
 * API client for the Keratin-AuthN server.
 */
import { verify as verifyJWT, decode as decodeJWT } from "https://deno.land/x/djwt@v2.8/mod.ts";
import * as log from "https://deno.land/std@0.175.0/log/mod.ts";

type JWK = JsonWebKey & {kid: string};  // The runtime's type definition doesn't include the 'kid' key ID string.

interface Options {
    /** The URL to the authn server from your app's server; not necessarily the public URL. e.g. "http://authn:3000" */
    authnPrivateUrl?: string;
    /** The domain of your application (no protocol). Must be one of the APP_DOMAINS of the Keratin AuthN server. */
    appDomain: string;
    /** The AUTHN_URL of your Keratin AuthN server (its public URL).e.g. "https://authn.myapp.com" */
    authnUrl: string;
    /** Username for API requests to private Keratin AuthN endpoints. */
    username: string;
    /** Password for API requests to private Keratin AuthN endpoints. */
    password: string;
}

export interface KeratinAuthNSession {
    accountId: number;
}

export interface KeratinAuthNAccount {
    id: number;
    username: string;
    locked: boolean;
    deleted: boolean;
}

interface ErrorDetail {
    field: string;
    message: string;
}
class KeratinAuthNError extends Error {
    errors?: ErrorDetail[];

    constructor(statusCode: number, statusText: string, errors?: ErrorDetail[]) {
        super(`AuthN API Call Failed: ${statusCode} ${statusText}`);
        this.errors = errors;
        // This clips the constructor invocation to make the stack trace a little nicer.
        Error.captureStackTrace(this, this.constructor);
    }
}

/** Compare URLs, ignoring minor changes like misisng trailing slash or port number */
function urlsEqual(url1: string, url2: string): boolean {
    if (url1 === url2) {
        return true;
    }
    let u1, u2;
    try {
        u1 = new URL(url1);
        u2 = new URL(url2);
    } catch { return false; }
    return (
        (u1.protocol === u2.protocol) &&
        (u1.hostname === u2.hostname) && 
        ((u1.port || "80") === (u2.port || "80")) &&
        (u1.pathname === u2.pathname)
    );
}

export class KeratinAuthNClient {
    #authnUrl: string;
    #authnPrivateUrl: string;
    #appDomain: string;
    #username: string;
    #password: string;
    #activeKeys: CryptoKey[];

    constructor(options: Options) {
        this.#authnUrl = options.authnUrl;
        this.#authnUrl = this.#authnUrl.replace(/\/+$/g, ""); // Strip trailing slash
        this.#authnPrivateUrl = options.authnPrivateUrl || options.authnUrl;
        this.#authnPrivateUrl = this.#authnPrivateUrl.replace(/\/+$/g, ""); // Strip trailing slash
        this.#appDomain = options.appDomain;
        this.#username = options.username;
        this.#password = options.password;
        this.#activeKeys = [];
    }

    get authnUrl(): string { return this.#authnUrl; }
    get authnPrivateUrl(): string { return this.#authnPrivateUrl; }
    private log(msg: string, level: "info"|"debug"|"error" = "info") {
        log.getLogger("authn-deno")[level](msg);
    }

    /**
     * Validate a session token (would usually be passed as a JWT in the "Authorization" HTTP header).
     * Returns an object with the account ID if the token is valid, or undefined if the token is invalid.
     */
    public async validateSessionToken(token: string): Promise<KeratinAuthNSession|undefined> {
        // The token must be a (non-empty) string:
        if (!token || typeof token !== "string") {
            this.log(`Session token ${token} is empty or not a string.`, "error");
            return undefined;
        }
        // Parse the token
        let data: any;
        try {
            data = decodeJWT(token)[1];
        } catch (err) {
            this.log(`Invalid JWT: ${err}`, "error");
            return undefined;
        }
        // Check issuer
        if (!urlsEqual(data.iss, this.#authnUrl)) {
            this.log(`Invalid JWT issuer: ${data.iss} (expected ${this.#authnUrl})`, "error");
            return undefined;
        }
        // Check audience
        const audience = Array.isArray(data.aud) ? data.aud : [data.aud];
        if (!audience.includes(this.#appDomain)) {
            this.log(`Invalid JWT audience: ${data.aud} (expected ${this.#appDomain})`, "error");
            return undefined;
        }

        // Verify signature
        let isValid = false;
        const errors: string[] = [];
        const checkToken = async () => {
            for (const key of this.#activeKeys) {
                try {
                    await verifyJWT(token, key);
                    isValid = true;
                } catch (err) {
                    // This key was not valid. But perhaps another key is.
                    errors.push(err.message ?? String(err));
                }
            }
        };
        await checkToken();
        if (!isValid) {
            // Fetch new key and retry
            await this.refreshKeys();
            await checkToken();
        }
        if (!isValid) {
            this.log(`JWT Signature validation failed: ${errors}`, "error");
            return undefined;
        }
        // Return data
        const accountId = parseInt(data.sub, 10);
        return {accountId, };
    }

    /**
     * Register a new account. Normally the frontend should call this directly, but sometimes you need to create
     * accounts on the backend, e.g. for importing a user or dev/test accounts.
     *
     * Password may be either an existing BCrypt hash or a plaintext (raw) string. The password will not be validated
     * for complexity. If a password is not specified, a random one will be securely generated.
     */
    public async createUser(args: {username: string; password?: string; locked?: boolean}): Promise<{accountId: number}> {
        if (!args.password) {
            // Generate a secure password automatically
            args = {...args, password: await this._generateRandomPassword()};
        }
        const result = await this.callApi("post", "/accounts/import", args);
        this.log(`Created user ${args.username}`, "info");
        return {accountId: result.id};
    }

    /** Securely generate a random password, as a temporary password or for users who don't set a password at all */
    private async _generateRandomPassword(): Promise<string> {
        const array = new Uint8Array(24);
        await crypto.getRandomValues(array);
        return btoa(String.fromCharCode.apply(null, Array.from(array)));
    }

    /** Check if a user with the given username exists. */
    public async isUsernameRegistered(args: {username: string}): Promise<boolean> {
        const result = await this.callApiRaw("get", "/accounts/available", args);
        if (result.status === 200) {
            return false;
        } else if (result.status === 422) {
            return true;
        }
        throw new Error(`Unable to check username status: response was ${result.status} ${result.statusText}`);
    }

    /** Get a user via their account ID (get account ID from validateSessionToken()) */
    public getAccount(args: {accountId: number}): Promise<KeratinAuthNAccount> {
        return this.callApi("get", `/accounts/${args.accountId}`);
    }

    /**
     * Change a user's username (or email) or locked status
     * May throw a KeratinAuthNError with error.errors[0].message as either NOT_FOUND or FORMAT_INVALID
     */
    public async update(args: {accountId: number; username?: string; locked?: boolean}): Promise<void> {
        if (args.username !== undefined) {
            await this.callApi("patch", `/accounts/${args.accountId}`, {username: args.username});
        }
        if (args.locked === true) {
            await this.callApi("patch", `/accounts/${args.accountId}/lock`);
        } else if (args.locked === false) {
            await this.callApi("patch", `/accounts/${args.accountId}/unlock`);
        }
    }

    /** Wipe all personal information, including username and password. Intended for user deletion routine. */
    public archive(args: {accountId: number}): Promise<void> {
        return this.callApi("delete", `/accounts/${args.accountId}`, undefined, false);
    }

    /** Flags the account for a required password change on their next login */
    public expirePassword(args: {accountId: number}): Promise<void> {
        return this.callApi("patch", `/accounts/${args.accountId}/expire_password`);
    }

    /**
     * Request passwordless login for user with specified username.
     * This is useful in cases where your backend needs to look up the user (e.g. by email) to get their username,
     * if you are not using email as authn username.
     * 
     * Always claims to succeed - use isUsernameRegistered() if you need to know if this will succeed or not.
     */
    public requestPasswordlessLogin(args: {username: string}): Promise<void> {
        return this.callApi("get", `/session/token`, {username: args.username }, false);
    }

    private async callApi(method: "get"|"post"|"patch"|"delete", url: string, data?: any, jsonResult = true): Promise<any> {
        const result = await this.callApiRaw(method, url, data);
        if (result.status >= 200 && result.status <= 300) {
            if (jsonResult) {
                return (await result.json()).result;
            } else {
                return await result.text();
            }
        } else {
            const msg = await result.text();
            let errors: ErrorDetail[]|undefined = undefined;
            try {
                errors = (await result.json()).errors;
            } catch {/* error message could not be parsed as JSON */}
            this.log(`${method} to ${url} failed with ${result.status} ${result.statusText} (${msg})`, "error");
            throw new KeratinAuthNError(result.status, result.statusText, errors);
        }
    }

    private callApiRaw(method: "get"|"post"|"patch"|"delete", url: string, data?: any): Promise<Response> {
        const headers = new Headers();
        const authToken = btoa(`${this.#username}:${this.#password}`);
        headers.set("Authorization", `Basic ${authToken}`);  // Required for private endpoints
        headers.set("Origin", `http://${this.#appDomain}`);  // Required for public endpoints
        const opts: RequestInit = {method: method};
        if (method === "get") {
            if (data) {
                url = url + "?" + new URLSearchParams(data).toString();
            }
        } else {
            opts.body = JSON.stringify(data || {});
            headers.set("Content-Type", "application/json");
        }
        opts.headers = headers;
        return fetch(`${this.#authnPrivateUrl}${url}`, opts);
    }

    private async refreshKeys(): Promise<void> {
        this.log(`AuthN: Refreshing keys`, "info");
        const response = await this.callApiRaw("get", "/jwks");
        if (response.status !== 200) {
            throw new Error("Unable to fetch new key from AuthN microservice.");
        }
        const keydata = await response.json();
        const newActiveKeys: CryptoKey[] = [];
        for (const key of keydata.keys as JWK[]) {
            let algorithm: HmacImportParams;
            if (key.alg === "RS256") {
                // See https://www.rfc-editor.org/rfc/rfc7518.html#page-6
                algorithm = {name: "RSASSA-PKCS1-v1_5", hash: {name: "SHA-256"}};
            } else { throw new Error(`authn-deno deno doesn't know about key algorthithm "${key.alg}"`); }
            newActiveKeys.push(
                await crypto.subtle.importKey("jwk", key, algorithm, false, ["verify"])
            );
        }
        this.#activeKeys = newActiveKeys;
        this.log(`AuthN: Updated keys are: ${keydata.keys.map((k: JWK) => k.kid).join(", ")}`, "debug");
    }
}
