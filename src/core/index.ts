import { DeriveOptions } from './types.js';
import { CONSTANTS } from './constants.js';
import { generateRandomBytes, toBase64, fromBase64, isEncryptedData, KeyCache, triggerBrowserDownload } from './utils.js';
import { compressData, decompressData, isGzipped } from './compression.js';
import { generateHTMLTemplate } from './html.js';
import { deriveKey, encryptRaw, decryptRaw } from './crypto.js';

export { type DeriveOptions, type HashAlgorithm, type KeyLength } from './types.js';

/**
 * DataCrypt Facade
 * Orchestrates Config, Utils, Compression, and Crypto modules.
 */
export class DataCrypt {
  
  static async encrypt(
    data: string | Uint8Array,
    password: string,
    opts: DeriveOptions = {}
  ): Promise<string> {
    
    // 1. Prepare Data
    let encodedData = typeof data === 'string'  ? new TextEncoder().encode(data)  : data;

    // 2. Compress
    if (opts.compress) {
      encodedData = await compressData(encodedData);
    }

    // 3. Params
    const salt = generateRandomBytes(opts.saltLength ?? CONSTANTS.DEFAULT_SALT_LENGTH);
    const iv = generateRandomBytes(CONSTANTS.IV_LENGTH);

    // 4. Encrypt
    const key = await deriveKey(password, salt, opts);
    const ciphertext = await encryptRaw(key, iv, encodedData);

    // 5. Pack
    const packed = new Uint8Array(salt.length + iv.length + ciphertext.length);
    packed.set(salt, 0);
    packed.set(iv, salt.length);
    packed.set(ciphertext, salt.length + iv.length);

    return toBase64(packed);
  }

  static async decrypt(
    base64: string,
    password: string,
    opts: DeriveOptions = {}
  ): Promise<string | Uint8Array | null> {
    try {
      const packed = fromBase64(base64);
      const saltLen = opts.saltLength ?? CONSTANTS.DEFAULT_SALT_LENGTH;

      if (packed.length < saltLen + CONSTANTS.IV_LENGTH) return null;

      const salt = packed.slice(0, saltLen);
      const iv = packed.slice(saltLen, saltLen + CONSTANTS.IV_LENGTH);
      const ciphertext = packed.slice(saltLen + CONSTANTS.IV_LENGTH);

      const key = await deriveKey(password, salt, opts);
      let decryptedBytes = await decryptRaw(key, iv, ciphertext);

      // 4. Decompress: Auto-detect or Explicit
      if (opts.compress || (opts.compress !== false && isGzipped(decryptedBytes))) {
        try {
          decryptedBytes = await decompressData(decryptedBytes);
        } catch (e) {
          if (opts.compress) throw e; // Fail only if explicitly requested
        }
      }

      // 5. Return
      try {
        return new TextDecoder('utf-8', { fatal: true }).decode(decryptedBytes);
      } catch {
        return decryptedBytes;
      }
    } catch (e) {
      return null;
    }
  }

  static async encryptFile(fileData: Uint8Array, password: string, opts?: DeriveOptions): Promise<string> {
    return this.encrypt(fileData, password, opts);
  }

  static async decryptFile(base64: string, password: string, opts?: DeriveOptions): Promise<Uint8Array | null> {
    const result = await this.decrypt(base64, password, opts);
    if (result === null) return null;
    if (typeof result === 'string') {
      return new TextEncoder().encode(result);
    }
    return result;
  }

  static generateSelfDecryptingHTML(encryptedBase64: string, filename: string = 'secret', opts: DeriveOptions = {}): string {
    return generateHTMLTemplate(encryptedBase64, filename, opts);
  }

  static downloadFile(content: string | Uint8Array, filename: string, mimeType: string = 'application/octet-stream'): void {
    triggerBrowserDownload(content, filename, mimeType);
  }

  static isEncrypted(data: string): boolean {
    return isEncryptedData(data);
  }

  static generateRandomBytes(length: number): Uint8Array {
    return generateRandomBytes(length);
  }

  static clearCache(): void {
    KeyCache.clear();
  }

  static getCacheSize(): number {
    return KeyCache.size();
  }
}