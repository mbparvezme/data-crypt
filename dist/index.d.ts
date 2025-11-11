export interface DeriveOptions {
    iterations?: number;
    hash?: string;
    length?: number;
}
export declare class DataCrypt {
    static deriveKey(password: string, salt: Uint8Array, { iterations, hash, length }?: DeriveOptions): Promise<CryptoKey>;
    static encrypt(text: string | Uint8Array, password: string, opts?: DeriveOptions): Promise<string>;
    static decrypt(base64: string, password: string, opts?: DeriveOptions): Promise<string | null>;
    static encryptFile(fileData: Uint8Array, password: string, opts?: DeriveOptions): Promise<string>;
    static decryptFile(base64: string, password: string, opts?: DeriveOptions): Promise<Uint8Array>;
}
