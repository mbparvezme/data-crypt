export type HashAlgorithm = 'SHA-256' | 'SHA-384' | 'SHA-512';
export type KeyLength = 128 | 192 | 256;
export interface DeriveOptions {
    iterations?: number;
    hash?: HashAlgorithm;
    length?: KeyLength;
    saltLength?: number;
    compress?: boolean;
}
export interface CacheEntry {
    key: CryptoKey;
    timestamp: number;
}
