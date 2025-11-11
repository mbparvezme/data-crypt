const isNode = typeof window === 'undefined';
const { subtle, getRandomValues } = isNode ? require('crypto').webcrypto : crypto;

const enc = new TextEncoder();
const dec = new TextDecoder();

export class DataCrypt {
  static async deriveKey(password, salt, {
    iterations = 100000,
    hash = 'SHA-256',
    length = 256
  } = {}) {
    const keyMaterial = await subtle.importKey(
      'raw',
      enc.encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    return subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash },
      keyMaterial,
      { name: 'AES-GCM', length },
      false,
      ['encrypt', 'decrypt']
    );
  }

  static async encrypt(text, password, opts = {}) {
    const salt = getRandomValues(new Uint8Array(16));
    const iv = getRandomValues(new Uint8Array(12));
    const key = await this.deriveKey(password, salt, opts);

    const data = typeof text === 'string' ? enc.encode(text) : text;
    const encrypted = await subtle.encrypt({ name: 'AES-GCM', iv }, key, data);

    const buffer = new Uint8Array(encrypted);
    const combined = new Uint8Array(salt.length + iv.length + buffer.length);
    combined.set(salt);
    combined.set(iv, salt.length);
    combined.set(buffer, salt.length + iv.length);

    return Buffer.from(combined).toString('base64');
  }

  static async decrypt(base64, password, opts = {}) {
    try {
      const combined = new Uint8Array(Buffer.from(base64, 'base64'));
      const salt = combined.slice(0, 16);
      const iv = combined.slice(16, 28);
      const data = combined.slice(28);

      const key = await this.deriveKey(password, salt, opts);
      const decrypted = await subtle.decrypt({ name: 'AES-GCM', iv }, key, data);

      return dec.decode(decrypted);
    } catch {
      return null;
    }
  }

  // Encrypt file (Buffer or Uint8Array)
  static async encryptFile(fileData, password, opts = {}) {
    return await this.encrypt(fileData, password, opts);
  }

  // Decrypt file → returns Uint8Array
  static async decryptFile(base64, password, opts = {}) {
    const combined = new Uint8Array(Buffer.from(base64, 'base64'));
    const salt = combined.slice(0, 16);
    const iv = combined.slice(16, 28);
    const data = combined.slice(28);

    const key = await this.deriveKey(password, salt, opts);
    const decrypted = await subtle.decrypt({ name: 'AES-GCM', iv }, key, data);

    return new Uint8Array(decrypted);
  }
}
