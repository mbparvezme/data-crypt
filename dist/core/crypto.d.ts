import { DeriveOptions } from './types.js';
export declare const deriveKey: (password: string, salt: Uint8Array, opts: DeriveOptions) => Promise<CryptoKey>;
export declare const encryptRaw: (key: CryptoKey, iv: Uint8Array, data: Uint8Array) => Promise<Uint8Array>;
export declare const decryptRaw: (key: CryptoKey, iv: Uint8Array, data: Uint8Array) => Promise<Uint8Array>;
