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
    compress?: boolean;
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
     */
    static decrypt(base64: string, password: string, opts?: DeriveOptions): Promise<string | Uint8Array | null>;
    static encryptFile(fileData: Uint8Array, password: string, opts?: DeriveOptions): Promise<string>;
    static decryptFile(base64: string, password: string, opts?: DeriveOptions): Promise<Uint8Array | null>;
    static generateSelfDecryptingHTML(encryptedBase64: string, filename?: string, opts?: DeriveOptions): string;
    static downloadFile(content: string | Uint8Array, filename: string, mimeType?: string): void;
    static isEncrypted(data: string): boolean;
    static generateRandomBytes(length: number): Uint8Array;
    static clearCache(): void;
    static getCacheSize(): number;
    private static compressData;
    private static decompressData;
    private static deriveKey;
    private static cleanCache;
    private static toBase64;
    private static fromBase64;
}
