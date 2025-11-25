import { CONSTANTS } from './constants.js';
export class KeyCache {
    static cache = new Map();
    static get(id) {
        this.clean();
        return this.cache.get(id)?.key;
    }
    static set(id, key) {
        this.cache.set(id, { key, timestamp: Date.now() });
    }
    static clear() {
        this.cache.clear();
    }
    static size() {
        this.clean();
        return this.cache.size;
    }
    static clean() {
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
export const generateRandomBytes = (length) => {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return array;
};
/**
 * Checks for Base64 format validity
 */
export const isEncrypted = (data) => {
    if (!data || data.length % 4 !== 0)
        return false;
    const regex = /^[A-Za-z0-9+/]*={0,2}$/;
    return regex.test(data);
};
/**
 * Universal Base64 Encoder (Node/Browser)
 */
export const toBase64 = (bytes) => {
    if (typeof globalThis.Buffer !== 'undefined') {
        return globalThis.Buffer.from(bytes).toString('base64');
    }
    let binary = '';
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return globalThis.btoa(binary);
};
/**
 * Universal Base64 Decoder (Node/Browser)
 */
export const fromBase64 = (base64) => {
    if (typeof globalThis.Buffer !== 'undefined') {
        return new Uint8Array(globalThis.Buffer.from(base64, 'base64'));
    }
    const binary = globalThis.atob(base64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
};
/**
 * Browser File Downloader
 */
export const triggerBrowserDownload = (content, filename, mimeType) => {
    if (typeof window === 'undefined' || typeof document === 'undefined') {
        console.warn('DataCrypt.downloadFile() called in a non-browser environment.');
        return;
    }
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
};
