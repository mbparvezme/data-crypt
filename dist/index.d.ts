/**
 * DataCrypt - A zero-dependency, cross-platform encryption library.
 * Uses AES-GCM for encryption and PBKDF2 for key derivation.
 */
export type HashAlgorithm = 'SHA-256' | 'SHA-384' | 'SHA-512';
export type KeyLength = 128 | 192 | 256;
export interface DeriveOptions {
    iterations?: number;
    hash?: HashAlgorithm;
    length?: KeyLength;
    saltLength?: number;
}
export declare class DataCrypt {
    private static readonly DEFAULT_ITERATIONS;
    private static readonly DEFAULT_HASH;
    private static readonly DEFAULT_KEY_LENGTH;
    private static readonly DEFAULT_SALT_LENGTH;
    private static readonly IV_LENGTH;
    private static keyCache;
    private static readonly CACHE_TTL_MS;
    /**
     * Encrypts a string or binary data.
     * Returns a Base64 encoded string containing Salt + IV + Ciphertext.
     */
    static encrypt(data: string | Uint8Array, password: string, opts?: DeriveOptions): Promise<string>;
    /**
     * Decrypts a Base64 encoded string.
     * Returns the original string or Uint8Array based on detection, or null on failure.
     */
    static decrypt(base64: string, password: string, opts?: DeriveOptions): Promise<string | Uint8Array | null>;
    /**
     * Encrypts binary file data. Returns Base64 string.
     * Wrapper for encrypt() to strictly handle Uint8Array input.
     */
    static encryptFile(fileData: Uint8Array, password: string, opts?: DeriveOptions): Promise<string>;
    /**
     * Decrypts to binary file data.
     * Forces return type to Uint8Array even if it looks like text.
     */
    static decryptFile(base64: string, password: string, opts?: DeriveOptions): Promise<Uint8Array | null>;
    /**
     * Checks if a string appears to be valid Base64 data.
     */
    static isEncrypted(data: string): boolean;
    /**
     * Generates cryptographically secure random bytes.
     */
    static generateRandomBytes(length: number): Uint8Array;
    /**
     * Clears the derived key cache.
     */
    static clearCache(): void;
    /**
     * Returns current cache size.
     */
    static getCacheSize(): number;
    private static deriveKey;
    private static cleanCache;
    private static toBase64;
    private static fromBase64;
}
