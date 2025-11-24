/**
 * DataCrypt - A zero-dependency, cross-platform encryption library.
 * Uses AES-GCM for encryption and PBKDF2 for key derivation.
 */
export class DataCrypt {
    static DEFAULT_ITERATIONS = 600000;
    static DEFAULT_HASH = 'SHA-256';
    static DEFAULT_KEY_LENGTH = 256;
    static DEFAULT_SALT_LENGTH = 16;
    static IV_LENGTH = 12;
    static keyCache = new Map();
    static CACHE_TTL_MS = 1000 * 60 * 5;
    /**
     * Encrypts a string or binary data.
     * Returns a Base64 encoded string containing Salt + IV + Ciphertext.
     */
    static async encrypt(data, password, opts = {}) {
        const alg = 'AES-GCM';
        // 1. Prepare Data
        let encodedData;
        if (typeof data === 'string') {
            encodedData = new TextEncoder().encode(data);
        }
        else {
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
        const ciphertextBuffer = await crypto.subtle.encrypt({ name: alg, iv }, key, encodedData);
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
    static async decrypt(base64, password, opts = {}) {
        try {
            const alg = 'AES-GCM';
            const packed = this.fromBase64(base64);
            const saltLength = opts.saltLength ?? this.DEFAULT_SALT_LENGTH;
            if (packed.length < saltLength + this.IV_LENGTH)
                return null;
            const salt = packed.slice(0, saltLength);
            const iv = packed.slice(saltLength, saltLength + this.IV_LENGTH);
            const ciphertext = packed.slice(saltLength + this.IV_LENGTH);
            const key = await this.deriveKey(password, salt, opts);
            const decryptedBuffer = await crypto.subtle.decrypt({ name: alg, iv }, key, ciphertext);
            // Use : Uint8Array type annotation to prevent strict ArrayBuffer inference issues
            let decryptedBytes = new Uint8Array(decryptedBuffer);
            // 4. Decompress if requested or auto-detected (New Feature)
            // Check for GZIP magic number (1F 8B) if compress option is true or undefined
            if (opts.compress || (opts.compress !== false && decryptedBytes[0] === 0x1f && decryptedBytes[1] === 0x8b)) {
                try {
                    // Fix 1: Cast argument to any to handle SharedArrayBuffer mismatch
                    decryptedBytes = await this.decompressData(decryptedBytes);
                }
                catch (e) {
                    // If explicit compress=true was passed, we should fail. 
                    // If auto-detecting, we ignore error and assume it wasn't compressed.
                    if (opts.compress)
                        throw e;
                }
            }
            // 5. Return String or Binary
            try {
                const decoded = new TextDecoder('utf-8', { fatal: true }).decode(decryptedBytes);
                return decoded;
            }
            catch {
                return decryptedBytes;
            }
        }
        catch (e) {
            return null;
        }
    }
    static async encryptFile(fileData, password, opts) {
        return this.encrypt(fileData, password, opts);
    }
    static async decryptFile(base64, password, opts) {
        const result = await this.decrypt(base64, password, opts);
        if (result === null)
            return null;
        if (typeof result === 'string') {
            return new TextEncoder().encode(result);
        }
        return result;
    }
    static generateSelfDecryptingHTML(encryptedBase64, filename = 'secret', opts = {}) {
        const saltLen = opts.saltLength ?? this.DEFAULT_SALT_LENGTH;
        const iterations = opts.iterations ?? this.DEFAULT_ITERATIONS;
        const hash = opts.hash ?? this.DEFAULT_HASH;
        const length = opts.length ?? this.DEFAULT_KEY_LENGTH;
        return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Locked Document: ${filename}</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; background: #f0f2f5; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .card { background: white; padding: 2rem; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); width: 100%; max-width: 400px; text-align: center; }
    h2 { margin-top: 0; color: #1a1a1a; }
    .icon { font-size: 3rem; margin-bottom: 1rem; }
    input { width: 100%; padding: 10px; margin: 15px 0; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; font-size: 16px; }
    button { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 6px; font-size: 16px; cursor: pointer; width: 100%; }
    button:hover { background: #0056b3; }
    .error { color: #dc3545; margin-top: 10px; font-size: 14px; display: none; background: #fff5f5; padding: 10px; border-radius: 4px; border: 1px solid #ffebeb; }
    .info { font-size: 13px; color: #666; margin-top: 15px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">🔐</div>
    <h2>Protected File</h2>
    <p>Enter password to unlock <strong>${filename}</strong></p>
    <input type="password" id="pwd" placeholder="Password" autofocus onkeypress="if(event.key==='Enter') unlock()">
    <button onclick="unlock()" id="btn">Unlock & Download</button>
    <div id="err" class="error"></div>
    <div class="info">Powered by DataCrypt</div>
  </div>
  <script>
    const DATA = "${encryptedBase64}";
    const CONFIG = { s: ${saltLen}, i: ${iterations}, h: '${hash}', l: ${length} };

    async function unlock() {
      const pwd = document.getElementById('pwd').value;
      const btn = document.getElementById('btn');
      const err = document.getElementById('err');
      
      // Check for Environment Support (Chrome file:// restriction)
      if (!window.crypto || !window.crypto.subtle) {
        err.style.display = 'block';
        err.innerHTML = "<strong>Browser Error:</strong> Encryption APIs are blocked in this context.<br>Try opening this file in <strong>Firefox</strong> or use a local server (http://localhost).";
        return;
      }

      if (!pwd) return;
      btn.disabled = true; btn.innerText = 'Decrypting...'; err.style.display = 'none';

      try {
        const encryptedBytes = Uint8Array.from(atob(DATA), c => c.charCodeAt(0));
        const salt = encryptedBytes.slice(0, CONFIG.s);
        const iv = encryptedBytes.slice(CONFIG.s, CONFIG.s + 12);
        const ciphertext = encryptedBytes.slice(CONFIG.s + 12);

        const keyMaterial = await window.crypto.subtle.importKey("raw", new TextEncoder().encode(pwd), { name: "PBKDF2" }, false, ["deriveKey"]);
        const key = await window.crypto.subtle.deriveKey(
          { name: "PBKDF2", salt, iterations: CONFIG.i, hash: CONFIG.h },
          keyMaterial, { name: "AES-GCM", length: CONFIG.l }, false, ["decrypt"]
        );

        const decryptedBuf = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
        let decrypted = new Uint8Array(decryptedBuf);

        if (decrypted[0] === 0x1f && decrypted[1] === 0x8b) {
            const stream = new DecompressionStream('gzip');
            const writer = stream.writable.getWriter();
            writer.write(decrypted);
            writer.close();
            decrypted = new Uint8Array(await new Response(stream.readable).arrayBuffer());
        }

        const blob = new Blob([decrypted], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = "${filename}"; 
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        btn.innerText = 'Success!';
        setTimeout(() => { btn.disabled = false; btn.innerText = 'Unlock & Download'; }, 2000);
      } catch (e) {
        console.error(e);
        err.style.display = 'block';
        if (e.name === 'OperationError') {
             err.innerText = 'Incorrect password.';
        } else {
             err.innerText = 'Error: ' + e.message;
        }
        btn.disabled = false; btn.innerText = 'Unlock & Download';
      }
    }
  </script>
</body>
</html>`;
    }
    static downloadFile(content, filename, mimeType = 'application/octet-stream') {
        if (typeof window === 'undefined' || typeof document === 'undefined') {
            console.warn('DataCrypt.downloadFile() called in a non-browser environment. Operation ignored.');
            return;
        }
        // Fix: Cast content to any to resolve SharedArrayBuffer mismatch with BlobPart
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
    static isEncrypted(data) {
        if (!data || data.length % 4 !== 0)
            return false;
        const regex = /^[A-Za-z0-9+/]*={0,2}$/;
        return regex.test(data);
    }
    static generateRandomBytes(length) {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return array;
    }
    static clearCache() {
        this.keyCache.clear();
    }
    static getCacheSize() {
        this.cleanCache();
        return this.keyCache.size;
    }
    // --- Compression Helpers (Node 18+ / Browser) ---
    static async compressData(data) {
        if (typeof CompressionStream === 'undefined') {
            throw new Error('CompressionStream not supported in this environment (requires Node 18+ or modern browser)');
        }
        const stream = new CompressionStream('gzip');
        const writer = stream.writable.getWriter();
        // Fix 2: Cast to any to handle BufferSource mismatch
        writer.write(data);
        writer.close();
        return new Uint8Array(await new Response(stream.readable).arrayBuffer());
    }
    static async decompressData(data) {
        if (typeof DecompressionStream === 'undefined') {
            throw new Error('DecompressionStream not supported in this environment');
        }
        const stream = new DecompressionStream('gzip');
        const writer = stream.writable.getWriter();
        // Fix 2: Cast to any to handle BufferSource mismatch
        writer.write(data);
        writer.close();
        return new Uint8Array(await new Response(stream.readable).arrayBuffer());
    }
    // --- Private Helpers ---
    static async deriveKey(password, salt, opts) {
        const iterations = opts.iterations ?? this.DEFAULT_ITERATIONS;
        const hash = opts.hash ?? this.DEFAULT_HASH;
        const keyLen = opts.length ?? this.DEFAULT_KEY_LENGTH;
        const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
        const cacheId = `${hash}:${iterations}:${keyLen}:${saltHex}:${password}`;
        this.cleanCache();
        const cached = this.keyCache.get(cacheId);
        if (cached)
            return cached.key;
        const passwordBuffer = new TextEncoder().encode(password);
        const importedKey = await crypto.subtle.importKey('raw', passwordBuffer, { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']);
        const derivedKey = await crypto.subtle.deriveKey({
            name: 'PBKDF2',
            salt: salt,
            iterations: iterations,
            hash: hash,
        }, importedKey, { name: 'AES-GCM', length: keyLen }, false, ['encrypt', 'decrypt']);
        this.keyCache.set(cacheId, {
            key: derivedKey,
            timestamp: Date.now()
        });
        return derivedKey;
    }
    static cleanCache() {
        const now = Date.now();
        for (const [id, entry] of this.keyCache) {
            if (now - entry.timestamp > this.CACHE_TTL_MS) {
                this.keyCache.delete(id);
            }
        }
    }
    static toBase64(bytes) {
        // Fix 3: Cast globalThis to any to access .Buffer without index signature error
        if (typeof globalThis.Buffer !== 'undefined') {
            return globalThis.Buffer.from(bytes).toString('base64');
        }
        let binary = '';
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return globalThis.btoa(binary);
    }
    static fromBase64(base64) {
        // Fix 3: Cast globalThis to any
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
    }
}
