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
  compress?: boolean; // New option for compression
}

interface CacheEntry {
  key: CryptoKey;
  timestamp: number;
}

export class DataCrypt {
  private static readonly DEFAULT_ITERATIONS = 600000;
  private static readonly DEFAULT_HASH = 'SHA-256';
  private static readonly DEFAULT_KEY_LENGTH = 256;
  private static readonly DEFAULT_SALT_LENGTH = 16;
  private static readonly IV_LENGTH = 12;

  private static keyCache: Map<string, CacheEntry> = new Map();
  private static readonly CACHE_TTL_MS = 1000 * 60 * 5;

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

    // 2. Compress if requested (New Feature)
    if (opts.compress) {
      encodedData = await this.compressData(encodedData);
    }

    // 3. Generate Random Salt and IV
    const saltLength = opts.saltLength ?? this.DEFAULT_SALT_LENGTH;
    const salt = this.generateRandomBytes(saltLength);
    const iv = this.generateRandomBytes(this.IV_LENGTH);

    // 4. Derive Key
    const key = await this.deriveKey(password, salt, opts);

    // 5. Encrypt
    const ciphertextBuffer = await crypto.subtle.encrypt(
      { name: alg, iv } as any,
      key,
      encodedData as any
    );
    const ciphertext = new Uint8Array(ciphertextBuffer);

    // 6. Pack: Salt + IV + Ciphertext
    const packed = new Uint8Array(salt.length + iv.length + ciphertext.length);
    packed.set(salt, 0);
    packed.set(iv, salt.length);
    packed.set(ciphertext, salt.length + iv.length);

    return this.toBase64(packed);
  }

  /**
   * Decrypts a Base64 encoded string.
   */
  static async decrypt(
    base64: string,
    password: string,
    opts: DeriveOptions = {}
  ): Promise<string | Uint8Array | null> {
    try {
      const alg = 'AES-GCM';
      const packed = this.fromBase64(base64);

      const saltLength = opts.saltLength ?? this.DEFAULT_SALT_LENGTH;
      if (packed.length < saltLength + this.IV_LENGTH) return null;

      const salt = packed.slice(0, saltLength);
      const iv = packed.slice(saltLength, saltLength + this.IV_LENGTH);
      const ciphertext = packed.slice(saltLength + this.IV_LENGTH);

      const key = await this.deriveKey(password, salt, opts);

      const decryptedBuffer = await crypto.subtle.decrypt(
        { name: alg, iv } as any,
        key,
        ciphertext as any
      );

      // Use : Uint8Array type annotation to prevent strict ArrayBuffer inference issues
      let decryptedBytes: Uint8Array = new Uint8Array(decryptedBuffer);

      // 4. Decompress if requested or auto-detected (New Feature)
      // Check for GZIP magic number (1F 8B) if compress option is true or undefined
      if (opts.compress || (opts.compress !== false && decryptedBytes[0] === 0x1f && decryptedBytes[1] === 0x8b)) {
        try {
          // Fix 1: Cast argument to any to handle SharedArrayBuffer mismatch
          decryptedBytes = await this.decompressData(decryptedBytes as any);
        } catch (e) {
          // If explicit compress=true was passed, we should fail. 
          // If auto-detecting, we ignore error and assume it wasn't compressed.
          if (opts.compress) throw e;
        }
      }

      // 5. Return String or Binary
      try {
        const decoded = new TextDecoder('utf-8', { fatal: true }).decode(decryptedBytes);
        return decoded;
      } catch {
        return decryptedBytes;
      }
    } catch (e) {
      return null;
    }
  }

  static async encryptFile(
    fileData: Uint8Array,
    password: string,
    opts?: DeriveOptions
  ): Promise<string> {
    return this.encrypt(fileData, password, opts);
  }

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

  static generateSelfDecryptingHTML(encryptedBase64: string, filename: string = 'secret', opts: DeriveOptions = {}): string {
    return "";
  }

  static downloadFile(content: string | Uint8Array, filename: string, mimeType: string = 'application/octet-stream'): void {
    if (typeof window === 'undefined' || typeof document === 'undefined') {
      console.warn('DataCrypt.downloadFile() called in a non-browser environment. Operation ignored.');
      return;
    }

    // Fix: Cast content to any to resolve SharedArrayBuffer mismatch with BlobPart
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

  static isEncrypted(data: string): boolean {
    if (!data || data.length % 4 !== 0) return false;
    const regex = /^[A-Za-z0-9+/]*={0,2}$/;
    return regex.test(data);
  }

  static generateRandomBytes(length: number): Uint8Array {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return array;
  }

  static clearCache(): void {
    this.keyCache.clear();
  }

  static getCacheSize(): number {
    this.cleanCache();
    return this.keyCache.size;
  }

  // --- Compression Helpers (Node 18+ / Browser) ---
  
  private static async compressData(data: Uint8Array): Promise<Uint8Array> {
    if (typeof CompressionStream === 'undefined') {
       throw new Error('CompressionStream not supported in this environment (requires Node 18+ or modern browser)');
    }
    const stream = new CompressionStream('gzip');
    const writer = stream.writable.getWriter();
    // Fix 2: Cast to any to handle BufferSource mismatch
    writer.write(data as any);
    writer.close();
    return new Uint8Array(await new Response(stream.readable).arrayBuffer());
  }

  private static async decompressData(data: Uint8Array): Promise<Uint8Array> {
    if (typeof DecompressionStream === 'undefined') {
        throw new Error('DecompressionStream not supported in this environment');
    }
    const stream = new DecompressionStream('gzip');
    const writer = stream.writable.getWriter();
    // Fix 2: Cast to any to handle BufferSource mismatch
    writer.write(data as any);
    writer.close();
    return new Uint8Array(await new Response(stream.readable).arrayBuffer());
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
    
    const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
    const cacheId = `${hash}:${iterations}:${keyLen}:${saltHex}:${password}`;

    this.cleanCache();
    const cached = this.keyCache.get(cacheId);
    if (cached) return cached.key;

    const passwordBuffer = new TextEncoder().encode(password);
    const importedKey = await crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      { name: 'PBKDF2' },
      false,
      ['deriveBits', 'deriveKey']
    );

    const derivedKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: iterations,
        hash: hash,
      } as any,
      importedKey,
      { name: 'AES-GCM', length: keyLen },
      false,
      ['encrypt', 'decrypt']
    );

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

  private static toBase64(bytes: Uint8Array): string {
    // Fix 3: Cast globalThis to any to access .Buffer without index signature error
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

  private static fromBase64(base64: string): Uint8Array {
    // Fix 3: Cast globalThis to any
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
}