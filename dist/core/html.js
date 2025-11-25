import { CONSTANTS } from './constants.js';
export const generateHTMLTemplate = (encryptedBase64, filename, opts) => {
    const saltLen = opts.saltLength ?? CONSTANTS.DEFAULT_SALT_LENGTH;
    const iterations = opts.iterations ?? CONSTANTS.DEFAULT_ITERATIONS;
    const hash = opts.hash ?? CONSTANTS.DEFAULT_HASH;
    const length = opts.length ?? CONSTANTS.DEFAULT_KEY_LENGTH;
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
      const pwd = document.getElementById('pwd').value.trim();
      const btn = document.getElementById('btn');
      const err = document.getElementById('err');
      
      if (!window.crypto || !window.crypto.subtle) {
        err.style.display = 'block';
        err.innerHTML = "<strong>Browser Error:</strong> Encryption APIs are blocked.<br>Use HTTPS or localhost.";
        return;
      }

      if (!pwd) return;
      btn.disabled = true; btn.innerText = 'Decrypting...'; err.style.display = 'none';

      try {
        const encryptedBytes = Uint8Array.from(atob(DATA), c => c.charCodeAt(0));
        const salt = encryptedBytes.slice(0, CONFIG.s);
        const iv = encryptedBytes.slice(CONFIG.s, CONFIG.s + 12);
        const ciphertext = encryptedBytes.slice(CONFIG.s + 12);

        const keyMaterial = await window.crypto.subtle.importKey(
            "raw", 
            new TextEncoder().encode(pwd), 
            { name: "PBKDF2" }, 
            false, 
            ["deriveKey"]
        );
        
        const key = await window.crypto.subtle.deriveKey(
          { name: "PBKDF2", salt, iterations: CONFIG.i, hash: CONFIG.h },
          keyMaterial, 
          { name: "AES-GCM", length: CONFIG.l }, 
          false, 
          ["decrypt"]
        );

        const decryptedBuf = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
        let decrypted = new Uint8Array(decryptedBuf);

        // Auto-detect GZIP (1F 8B)
        if (decrypted[0] === 0x1f && decrypted[1] === 0x8b) {
            try {
                const stream = new DecompressionStream('gzip');
                const writer = stream.writable.getWriter();
                writer.write(decrypted);
                writer.close();
                decrypted = new Uint8Array(await new Response(stream.readable).arrayBuffer());
            } catch (e) { console.warn('Decompression skipped', e); }
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
};
