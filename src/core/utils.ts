import { CONSTANTS } from './constants.js';
import { CacheEntry } from './types.js';

export class KeyCache {
  private static cache: Map<string, CacheEntry> = new Map();

  static get(id: string): CryptoKey | undefined {
    this.clean();
    return this.cache.get(id)?.key;
  }

  static set(id: string, key: CryptoKey): void {
    this.cache.set(id, { key, timestamp: Date.now() });
  }

  static clear(): void {
    this.cache.clear();
  }

  static size(): number {
    this.clean();
    return this.cache.size;
  }

  private static clean(): void {
    const now = Date.now();
    for (const [id, entry] of this.cache) {
      if (now - entry.timestamp > CONSTANTS.CACHE_TTL_MS) {
        this.cache.delete(id);
      }
    }
  }
}

/**
 * Random Number Generation
 */
export const generateRandomBytes = (length: number): Uint8Array => {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return array;
}

/**
 * Checks for Base64 format validity
 */
export const isEncryptedData = (data: string): boolean => {
  if (!data || data.length % 4 !== 0) return false;
  const regex = /^[A-Za-z0-9+/]*={0,2}$/;
  return regex.test(data);
}

/**
 * Universal Base64 Encoder (Node/Browser)
 */
export const toBase64 = (bytes: Uint8Array): string => {
  if (typeof (globalThis as any).Buffer !== 'undefined') {
    return (globalThis as any).Buffer.from(bytes).toString('base64');
  }

  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }

  return globalThis.btoa(binary);
}

/**
 * Universal Base64 Decoder (Node/Browser)
 */
export const fromBase64 = (base64: string): Uint8Array => {
  if (typeof (globalThis as any).Buffer !== 'undefined') {
    return new Uint8Array((globalThis as any).Buffer.from(base64, 'base64'));
  }

  const binary = globalThis.atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

/**
 * Browser File Downloader
 */
export const triggerBrowserDownload = (content: string | Uint8Array, filename: string, mimeType: string): void => {
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    console.warn('DataCrypt.downloadFile() called in a non-browser environment.');
    return;
  }

  const blob = new Blob([content as any], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}