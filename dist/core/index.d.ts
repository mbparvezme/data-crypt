import { DeriveOptions } from './types.js';
export { type DeriveOptions, type HashAlgorithm, type KeyLength } from './types.js';
/**
 * DataCrypt Facade
 * Orchestrates Config, Utils, Compression, and Crypto modules.
 */
export declare class DataCrypt {
    static encrypt(data: string | Uint8Array, password: string, opts?: DeriveOptions): Promise<string>;
    static decrypt(base64: string, password: string, opts?: DeriveOptions): Promise<string | Uint8Array | null>;
    static encryptFile(fileData: Uint8Array, password: string, opts?: DeriveOptions): Promise<string>;
    static decryptFile(base64: string, password: string, opts?: DeriveOptions): Promise<Uint8Array | null>;
    static generateSelfDecryptingHTML(encryptedBase64: string, filename?: string, opts?: DeriveOptions): string;
    static downloadFile(content: string | Uint8Array, filename: string, mimeType?: string): void;
    static isEncrypted(data: string): boolean;
    static generateRandomBytes(length: number): Uint8Array;
    static clearCache(): void;
    static getCacheSize(): number;
}
