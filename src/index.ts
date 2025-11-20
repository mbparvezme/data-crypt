/**
 * DataCrypt - A zero-dependency, cross-platform encryption library.
 * Uses AES-GCM for encryption and PBKDF2 for key derivation.
 */

export type HashAlgorithm = 'SHA-256' | 'SHA-384' | 'SHA-512';
export type KeyLength = 128 | 192 | 256;

export interface DeriveOptions {
  iterations?: number;
  hash?: HashAlgorithm;
  length?: KeyLength;
  saltLength?: number;
}

// Key cache interface
interface CacheEntry {
  key: CryptoKey;
  timestamp: number;
}

export class DataCrypt {
  private static readonly DEFAULT_ITERATIONS = 600000;
  private static readonly DEFAULT_HASH = 'SHA-256';
  private static readonly DEFAULT_KEY_LENGTH = 256;
  private static readonly DEFAULT_SALT_LENGTH = 16;
  private static readonly IV_LENGTH = 12; // 96 bits standard for GCM

  // Cache derived keys to improve performance on repeated operations
  private static keyCache: Map<string, CacheEntry> = new Map();
  private static readonly CACHE_TTL_MS = 1000 * 60 * 5; // 5 minutes

  /**
   * Encrypts a string or binary data.
   * Returns a Base64 encoded string containing Salt + IV + Ciphertext.
   */
  static async encrypt(
    data: string | Uint8Array,
    password: string,
    opts: DeriveOptions = {}
  ): Promise<string> {
    const alg = 'AES-GCM';

    // 1. Prepare Data
    let encodedData: Uint8Array;
    if (typeof data === 'string') {
      encodedData = new TextEncoder().encode(data);
    } else {
      encodedData = data;
    }

    // 2. Generate Random Salt and IV
    const saltLength = opts.saltLength ?? this.DEFAULT_SALT_LENGTH;
    const salt = this.generateRandomBytes(saltLength);
    const iv = this.generateRandomBytes(this.IV_LENGTH);

    // 3. Derive Key
    const key = await this.deriveKey(password, salt, opts);

    // 4. Encrypt
    const ciphertextBuffer = await crypto.subtle.encrypt(
      { name: alg, iv } as any,
      key,
      encodedData as any
    );
    const ciphertext = new Uint8Array(ciphertextBuffer);

    // 5. Pack: Salt + IV + Ciphertext
    const packed = new Uint8Array(salt.length + iv.length + ciphertext.length);
    packed.set(salt, 0);
    packed.set(iv, salt.length);
    packed.set(ciphertext, salt.length + iv.length);

    // 6. Return as Base64
    return this.toBase64(packed);
  }

  /**
   * Decrypts a Base64 encoded string.
   * Returns the original string or Uint8Array based on detection, or null on failure.
   */
  static async decrypt(
    base64: string,
    password: string,
    opts: DeriveOptions = {}
  ): Promise<string | Uint8Array | null> {
    try {
      const alg = 'AES-GCM';
      const packed = this.fromBase64(base64);

      // 1. Extract Salt, IV, and Ciphertext
      const saltLength = opts.saltLength ?? this.DEFAULT_SALT_LENGTH;

      if (packed.length < saltLength + this.IV_LENGTH) return null;

      const salt = packed.slice(0, saltLength);
      const iv = packed.slice(saltLength, saltLength + this.IV_LENGTH);
      const ciphertext = packed.slice(saltLength + this.IV_LENGTH);

      // 2. Derive Key
      const key = await this.deriveKey(password, salt, opts);

      // 3. Decrypt
      const decryptedBuffer = await crypto.subtle.decrypt(
        { name: alg, iv },
        key,
        ciphertext
      );

      const decryptedBytes = new Uint8Array(decryptedBuffer);

      // 4. Attempt to decode as UTF-8 string, fallback to binary if invalid characters
      // Simple heuristic: check if bytes look like valid UTF-8
      try {
        const decoded = new TextDecoder('utf-8', { fatal: true }).decode(decryptedBytes);
        return decoded;
      } catch {
        return decryptedBytes;
      }
    } catch (e) {
      // Decryption failed (wrong password or corrupted data)
      return null;
    }
  }

  /**
   * Encrypts binary file data. Returns Base64 string.
   * Wrapper for encrypt() to strictly handle Uint8Array input.
   */
  static async encryptFile(
    fileData: Uint8Array,
    password: string,
    opts?: DeriveOptions
  ): Promise<string> {
    return this.encrypt(fileData, password, opts);
  }

  /**
   * Decrypts to binary file data.
   * Forces return type to Uint8Array even if it looks like text.
   */
  static async decryptFile(
    base64: string,
    password: string,
    opts?: DeriveOptions
  ): Promise<Uint8Array | null> {
    const result = await this.decrypt(base64, password, opts);
    if (result === null) return null;
    if (typeof result === 'string') {
      return new TextEncoder().encode(result);
    }
    return result;
  }

  /**
   * Checks if a string appears to be valid Base64 data.
   */
  static isEncrypted(data: string): boolean {
    if (!data || data.length % 4 !== 0) return false;
    const regex = /^[A-Za-z0-9+/]*={0,2}$/;
    return regex.test(data);
  }

  /**
   * Generates cryptographically secure random bytes.
   */
  static generateRandomBytes(length: number): Uint8Array {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return array;
  }

  /**
   * Clears the derived key cache.
   */
  static clearCache(): void {
    this.keyCache.clear();
  }

  /**
   * Returns current cache size.
   */
  static getCacheSize(): number {
    this.cleanCache(); // Remove expired cache
    return this.keyCache.size;
  }

  // --- Private Helpers ---

  private static async deriveKey(
    password: string,
    salt: Uint8Array,
    opts: DeriveOptions
  ): Promise<CryptoKey> {
    const iterations = opts.iterations ?? this.DEFAULT_ITERATIONS;
    const hash = opts.hash ?? this.DEFAULT_HASH;
    const keyLen = opts.length ?? this.DEFAULT_KEY_LENGTH;

    // Generate Cache Key
    const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
    const cacheId = `${hash}:${iterations}:${keyLen}:${saltHex}:${password}`;

    // Check Cache
    this.cleanCache();
    const cached = this.keyCache.get(cacheId);
    if (cached) return cached.key;

    // Import Password
    const passwordBuffer = new TextEncoder().encode(password);
    const importedKey = await crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      { name: 'PBKDF2' },
      false,
      ['deriveBits', 'deriveKey']
    );

    // Derive Key
    const derivedKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: iterations,
        hash: hash,
      } as any, // Cast to any to resolve TS overload mismatch for salt/hash types
      importedKey,
      { name: 'AES-GCM', length: keyLen },
      false, // non-exportable
      ['encrypt', 'decrypt']
    );

    // Save to Cache
    this.keyCache.set(cacheId, {
      key: derivedKey,
      timestamp: Date.now()
    });

    return derivedKey;
  }

  private static cleanCache() {
    const now = Date.now();
    for (const [id, entry] of this.keyCache) {
      if (now - entry.timestamp > this.CACHE_TTL_MS) {
        this.keyCache.delete(id);
      }
    }
  }

  // Universal Base64 Helper (Node + Browser)
  private static toBase64(bytes: Uint8Array): string {
    if (typeof globalThis.Buffer !== 'undefined') {
      return globalThis.Buffer.from(bytes).toString('base64');
    }
    // Browser fallback
    let binary = '';
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return globalThis.btoa(binary);
  }

  private static fromBase64(base64: string): Uint8Array {
    if (typeof globalThis.Buffer !== 'undefined') {
      return new Uint8Array(globalThis.Buffer.from(base64, 'base64'));
    }
    // Browser fallback
    const binary = globalThis.atob(base64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
}