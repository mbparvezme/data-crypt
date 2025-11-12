const isNode = typeof process !== 'undefined' && process.versions?.node !== undefined;
let subtle;
let getRandomValues;
if (isNode) {
    try {
        const { webcrypto } = await import("crypto");
        subtle = webcrypto.subtle;
        getRandomValues = webcrypto.getRandomValues.bind(webcrypto);
    }
    catch (error) {
        throw new Error('Node.js crypto module not available');
    }
}
else {
    if (!crypto?.subtle || !crypto?.getRandomValues) {
        throw new Error('Web Crypto API not available in this environment');
    }
    subtle = crypto.subtle;
    getRandomValues = crypto.getRandomValues.bind(crypto);
}
const enc = new TextEncoder();
const dec = new TextDecoder();
export class DataCrypt {
    static keyCache = new Map();
    static DEFAULT_ITERATIONS = 600000;
    static DEFAULT_SALT_LENGTH = 16;
    static DEFAULT_IV_LENGTH = 12;
    static getCacheKey(password, salt, opts) {
        return `${password}-${Buffer.from(salt).toString('base64')}-${JSON.stringify(opts)}`;
    }
    static validatePassword(password) {
        if (!password || password.length === 0) {
            throw new Error('Password cannot be empty');
        }
    }
    static validateData(data) {
        if (!data || (typeof data === 'string' && data.length === 0) ||
            (data instanceof Uint8Array && data.length === 0)) {
            throw new Error('Data cannot be empty');
        }
    }
    /**
     * Derives a cryptographic key from a password using PBKDF2
     * @param password - Password for key derivation
     * @param salt - Salt for key derivation
     * @param opts - Key derivation options
     * @returns Derived CryptoKey
     */
    static async deriveKey(password, salt, { iterations = this.DEFAULT_ITERATIONS, hash = 'SHA-256', length = 256 } = {}) {
        this.validatePassword(password);
        const cacheKey = this.getCacheKey(password, salt, { iterations, hash, length });
        if (this.keyCache.has(cacheKey)) {
            return this.keyCache.get(cacheKey);
        }
        const keyMaterial = await subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
        const key = await subtle.deriveKey({ name: 'PBKDF2', salt: salt, iterations, hash }, keyMaterial, { name: 'AES-GCM', length }, false, ['encrypt', 'decrypt']);
        this.keyCache.set(cacheKey, key);
        return key;
    }
    /**
     * Encrypts data using AES-GCM with key derived from password via PBKDF2
     * @param text - Data to encrypt (string or Uint8Array)
     * @param password - Password for key derivation
     * @param opts - Key derivation options
     * @returns Base64-encoded encrypted data (salt + iv + ciphertext)
     * @throws {Error} When password or data is empty
     */
    static async encrypt(text, password, opts = {}) {
        this.validatePassword(password);
        this.validateData(text);
        const saltLength = opts.saltLength || this.DEFAULT_SALT_LENGTH;
        const salt = getRandomValues(new Uint8Array(saltLength));
        const iv = getRandomValues(new Uint8Array(this.DEFAULT_IV_LENGTH));
        const key = await this.deriveKey(password, salt, opts);
        const data = typeof text === 'string' ? enc.encode(text) : text;
        const encrypted = await subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, new Uint8Array(data));
        const buffer = new Uint8Array(encrypted);
        const combined = new Uint8Array(salt.length + iv.length + buffer.length);
        combined.set(salt);
        combined.set(iv, salt.length);
        combined.set(buffer, salt.length + iv.length);
        return Buffer.from(combined).toString('base64');
    }
    /**
     * Decrypts data encrypted with the encrypt method
     * @param base64 - Base64-encoded encrypted data
     * @param password - Password used for encryption
     * @param opts - Key derivation options (must match encryption options)
     * @returns Decrypted string or null if decryption fails
     */
    static async decrypt(base64, password, opts = {}) {
        try {
            this.validatePassword(password);
            if (!base64 || base64.length === 0) {
                return null;
            }
            const combined = new Uint8Array(Buffer.from(base64, 'base64'));
            if (combined.length < 28) { // Minimum: salt(16) + iv(12) = 28
                return null;
            }
            const saltLength = opts.saltLength || this.DEFAULT_SALT_LENGTH;
            const salt = combined.slice(0, saltLength);
            const iv = combined.slice(saltLength, saltLength + this.DEFAULT_IV_LENGTH);
            const data = combined.slice(saltLength + this.DEFAULT_IV_LENGTH);
            const key = await this.deriveKey(password, salt, opts);
            const decrypted = await subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
            return dec.decode(decrypted);
        }
        catch {
            return null;
        }
    }
    /**
     * Encrypts file data (Uint8Array) using AES-GCM
     * @param fileData - File data to encrypt
     * @param password - Password for key derivation
     * @param opts - Key derivation options
     * @returns Base64-encoded encrypted file data
     * @throws {Error} When password or file data is empty
     */
    static async encryptFile(fileData, password, opts = {}) {
        return await this.encrypt(fileData, password, opts);
    }
    /**
     * Decrypts file data encrypted with encryptFile method
     * @param base64 - Base64-encoded encrypted file data
     * @param password - Password used for encryption
     * @param opts - Key derivation options (must match encryption options)
     * @returns Decrypted file data as Uint8Array or null if decryption fails
     */
    static async decryptFile(base64, password, opts = {}) {
        try {
            this.validatePassword(password);
            if (!base64 || base64.length === 0) {
                return null;
            }
            const combined = new Uint8Array(Buffer.from(base64, 'base64'));
            if (combined.length < 28) {
                return null;
            }
            const saltLength = opts.saltLength || this.DEFAULT_SALT_LENGTH;
            const salt = combined.slice(0, saltLength);
            const iv = combined.slice(saltLength, saltLength + this.DEFAULT_IV_LENGTH);
            const data = combined.slice(saltLength + this.DEFAULT_IV_LENGTH);
            const key = await this.deriveKey(password, salt, opts);
            const decrypted = await subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
            return new Uint8Array(decrypted);
        }
        catch {
            return null;
        }
    }
    /**
     * Checks if a string appears to be valid encrypted data
     * @param data - Base64 string to check
     * @returns True if data has minimum structure of encrypted data
     */
    static isEncryptedData(data) {
        try {
            const combined = new Uint8Array(Buffer.from(data, 'base64'));
            return combined.length >= 28; // Minimum valid encrypted data length
        }
        catch {
            return false;
        }
    }
    /**
     * Generates cryptographically secure random bytes
     * @param length - Number of random bytes to generate
     * @returns Uint8Array with random bytes
     */
    static generateRandomBytes(length) {
        return getRandomValues(new Uint8Array(length));
    }
    /**
     * Clears the derived key cache
     */
    static clearCache() {
        this.keyCache.clear();
    }
    /**
     * Gets the number of cached keys
     * @returns Number of cached keys
     */
    static getCacheSize() {
        return this.keyCache.size;
    }
}
//# sourceMappingURL=index.js.map