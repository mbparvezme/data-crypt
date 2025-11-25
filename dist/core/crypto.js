import { CONSTANTS } from './constants.js';
import { KeyCache } from './utils.js';
export const deriveKey = async (password, salt, opts) => {
    const iterations = opts.iterations ?? CONSTANTS.DEFAULT_ITERATIONS;
    const hash = opts.hash ?? CONSTANTS.DEFAULT_HASH;
    const keyLen = opts.length ?? CONSTANTS.DEFAULT_KEY_LENGTH;
    const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
    const cacheId = `${hash}:${iterations}:${keyLen}:${saltHex}:${password}`;
    const cached = KeyCache.get(cacheId);
    if (cached)
        return cached;
    const passwordBuffer = new TextEncoder().encode(password);
    const importedKey = await crypto.subtle.importKey('raw', passwordBuffer, { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']);
    const derivedKey = await crypto.subtle.deriveKey({
        name: 'PBKDF2',
        salt: salt,
        iterations: iterations,
        hash: hash,
    }, importedKey, { name: 'AES-GCM', length: keyLen }, false, ['encrypt', 'decrypt']);
    KeyCache.set(cacheId, derivedKey);
    return derivedKey;
};
export const encryptRaw = async (key, iv, data) => {
    const buffer = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
    return new Uint8Array(buffer);
};
export const decryptRaw = async (key, iv, data) => {
    const buffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    return new Uint8Array(buffer);
};
