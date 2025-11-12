export type HashAlgorithm = 'SHA-256' | 'SHA-384' | 'SHA-512';
export type KeyLength = 128 | 192 | 256;
export interface DeriveOptions {
    iterations?: number;
    hash?: HashAlgorithm;
    length?: KeyLength;
    saltLength?: number;
}
export declare class DataCrypt {
    private static keyCache;
    private static readonly DEFAULT_ITERATIONS;
    private static readonly DEFAULT_SALT_LENGTH;
    private static readonly DEFAULT_IV_LENGTH;
    private static getCacheKey;
    private static validatePassword;
    private static validateData;
    /**
     * Derives a cryptographic key from a password using PBKDF2
     * @param password - Password for key derivation
     * @param salt - Salt for key derivation
     * @param opts - Key derivation options
     * @returns Derived CryptoKey
     */
    static deriveKey(password: string, salt: Uint8Array, { iterations, hash, length }?: DeriveOptions): Promise<CryptoKey>;
    /**
     * Encrypts data using AES-GCM with key derived from password via PBKDF2
     * @param text - Data to encrypt (string or Uint8Array)
     * @param password - Password for key derivation
     * @param opts - Key derivation options
     * @returns Base64-encoded encrypted data (salt + iv + ciphertext)
     * @throws {Error} When password or data is empty
     */
    static encrypt(text: string | Uint8Array, password: string, opts?: DeriveOptions): Promise<string>;
    /**
     * Decrypts data encrypted with the encrypt method
     * @param base64 - Base64-encoded encrypted data
     * @param password - Password used for encryption
     * @param opts - Key derivation options (must match encryption options)
     * @returns Decrypted string or null if decryption fails
     */
    static decrypt(base64: string, password: string, opts?: DeriveOptions): Promise<string | null>;
    /**
     * Encrypts file data (Uint8Array) using AES-GCM
     * @param fileData - File data to encrypt
     * @param password - Password for key derivation
     * @param opts - Key derivation options
     * @returns Base64-encoded encrypted file data
     * @throws {Error} When password or file data is empty
     */
    static encryptFile(fileData: Uint8Array, password: string, opts?: DeriveOptions): Promise<string>;
    /**
     * Decrypts file data encrypted with encryptFile method
     * @param base64 - Base64-encoded encrypted file data
     * @param password - Password used for encryption
     * @param opts - Key derivation options (must match encryption options)
     * @returns Decrypted file data as Uint8Array or null if decryption fails
     */
    static decryptFile(base64: string, password: string, opts?: DeriveOptions): Promise<Uint8Array | null>;
    /**
     * Checks if a string appears to be valid encrypted data
     * @param data - Base64 string to check
     * @returns True if data has minimum structure of encrypted data
     */
    static isEncryptedData(data: string): boolean;
    /**
     * Generates cryptographically secure random bytes
     * @param length - Number of random bytes to generate
     * @returns Uint8Array with random bytes
     */
    static generateRandomBytes(length: number): Uint8Array;
    /**
     * Clears the derived key cache
     */
    static clearCache(): void;
    /**
     * Gets the number of cached keys
     * @returns Number of cached keys
     */
    static getCacheSize(): number;
}
//# sourceMappingURL=index.d.ts.map