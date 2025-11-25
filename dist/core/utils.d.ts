export declare class KeyCache {
    private static cache;
    static get(id: string): CryptoKey | undefined;
    static set(id: string, key: CryptoKey): void;
    static clear(): void;
    static size(): number;
    private static clean;
}
/**
 * Random Number Generation
 */
export declare const generateRandomBytes: (length: number) => Uint8Array;
/**
 * Checks for Base64 format validity
 */
export declare const isEncryptedData: (data: string) => boolean;
/**
 * Universal Base64 Encoder (Node/Browser)
 */
export declare const toBase64: (bytes: Uint8Array) => string;
/**
 * Universal Base64 Decoder (Node/Browser)
 */
export declare const fromBase64: (base64: string) => Uint8Array;
/**
 * Browser File Downloader
 */
export declare const triggerBrowserDownload: (content: string | Uint8Array, filename: string, mimeType: string) => void;
