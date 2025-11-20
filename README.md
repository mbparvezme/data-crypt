# 🔐 DataCrypt

A robust, cross-platform TypeScript/JavaScript library for encrypting and decrypting data and files using AES-GCM with PBKDF2 key derivation. Works seamlessly in both Node.js and browser environments with built-in CLI support.

<br>

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Usage](#cli-usage)
  - [CLI Installation](#cli-installation)
  - [Help](#help)
  - [Available Commands](#available-commands)
  - [Basic CLI Text Operations](#basic-cli-text-operations)
  - [CLI File Operations](#cli-file-operations)
  - [Advanced CLI Options](#advanced-cli-options)
  - [Examples with Advanced Options](#examples-with-advanced-options)
  - [Piping Support](#piping-support)
- [API Reference](#api-reference)
  - [Piping Support](#piping-support)
- [Compressing Data](#compressing-data)
- [Custom Options](#custom-options)
- [Usage](#usage)
  - [Browser Usage](#browser-usage)
    - [With Bundlers (Webpack, Vite, etc.)](#with-bundlers-webpack-vite-etc)
    - [Direct Script Tag](#direct-script-tag)
  - [Node.js Usage](#nodejs-usage)
    - [CommonJS](#commonjs)
    - [ES Modules](#es-modules)
- [Security Considerations](#security-considerations)
  - [Best Practices](#best-practices)
  - [Default Security Parameters](#default-security-parameters)
  - [Performance](#performance)
  - [Limitations](#limitations)
- [Contributing](#contributing)
- [License](#license)

<br>

## Features

* **Secure Encryption**: AES-GCM with PBKDF2 key derivation
* **Built-in CLI**: Command-line interface for encrypting/decrypting files
* **Cross-Platform**: Works in Node.js and modern browsers
* **Zero Dependencies**: Uses native Web Crypto API
* **Type Safe**: Written in TypeScript with full type definitions
* **Compression Support**: Built-in GZIP compression to reduce file size
* **Self-Decrypting HTML**: Generate standalone HTML files unlockable in any browser
* **Configurable**: Customizable encryption parameters
* **File Support**: Encrypt/decrypt binary file data
* **Simple API**: Easy-to-use static methods

<br>

## Installation

```bash
npm install data-crypt
```

or

```bash
yarn add data-crypt
```

<br>

## Quick Start

```js
// Import DataCrypt
import { DataCrypt } from 'data-crypt';

// Encrypt a string
const encrypted = await DataCrypt.encrypt('Secret message', 'my-password');
console.log('Encrypted:', encrypted);

// Decrypt the data
const decrypted = await DataCrypt.decrypt(encrypted, 'my-password');
console.log('Decrypted:', decrypted); // 'Secret message'
```
<br>

## CLI Usage

DataCrypt provides a convenient command-line interface for quick encryption/decryption operations.

### CLI Installation

```bash
npm install -g data-crypt
```


### Help

```bash
dc --help
dc -h
```

### Available Commands
You can use any of these command names:

- `dc` (recommended, short and fast)
- `datacrypt` (full name)
- `data-crypt` (hyphenated)


### Basic CLI Text Operations

**Encrypt Text**
```bash
dc encrypt "your secret message" "password"
```

**Decrypt Text**
```bash
dc decrypt "ENCRYPTED_BASE64_DATA" "password"
```

### CLI File Operations

**Encrypt Text**
```bash
dc encrypt -f input.txt -o encrypted.txt "password"
```

**Decrypt Text**
```bash
dc decrypt -f encrypted.txt -o decrypted.txt "password"
```


### Advanced CLI Options

| Option	|   Description   |   Example |
| :------------ | :-------------- | :---------- |
| `-i, --iterations <number>` | PBKDF2 iterations | `-i 1000000` |
| `--hash <algorithm>` | Hash algorithm (SHA-256, SHA-384, SHA-512) | `--hash SHA-512` |
| `-l, --length <bits>` | Key length in bits (`128`, `192`, `256`) | `--hash SHA-512` |
| `-s, --salt-length <bytes>` | Salt length in bytes | `-s 32` |
| `-z, --compress` | Compress data (GZIP) before encryption | `-z` |
| `--html` | Generate a self-decrypting HTML file | `--html` |


### Examples with Advanced Options

```bash
# Encrypt with custom parameters
dc encrypt "text" -i 1000000 --hash SHA-512 "password"

# Encrypt file with advanced options
dc encrypt -f document.pdf -o secure.pdf -i 500000 --hash SHA-384 "password"
```

### Self-Decrypting HTML Files

Create a standalone `.html` file that anyone can decrypt in their browser without installing any software.

```bash
# Encrypt file into a self-unlocking HTML page
dc encrypt -f secret.pdf -o unlock.html --html "password"
```

> **⚠️ Important Note for Chrome/Edge Users:**
>
> Modern browsers like Chrome and Edge restrict the Web Crypto API on `file://` URLs for security reasons. If you double-click the generated HTML file to open it, decryption might fail.
>
> **Solutions:**
> 1. Open the file in **Firefox** (it works locally).
> 2. Use a local server (e.g., `npx serve .`).
> 3. Upload the file to any website (HTTPS) or localhost.

### Compression

Reduce file size by compressing data before encryption (uses GZIP).

```bash
# Compress and encrypt a large log file
dc encrypt -f server.log -o server.enc -z "password"
```

### Decompression

When decrypting files that were compressed using the `-z` flag, **decompression is automatic**. You do not need to pass a compression flag during decryption. DataCrypt detects the compression headers inside the encrypted data and handles it for you.

```bash
# Just run the standard decrypt command
dc decrypt -f server.enc -o server.log "password"
```

### Piping Support

You can also pipe data through the CLI:

```bash
# Encrypt piped data
echo "secret data" | dc encrypt "password"

# Encrypt file content
cat file.txt | dc encrypt -f "password" > encrypted.txt
```

<br>

## API Reference

### ⭐ `encrypt()`: Encrypts text or binary data.

**Syntax**
```ts
encrypt(
  text: string | Uint8Array,
  password: string,
  opts?: DeriveOptions
): Promise<string>
```

**Parameters**
- `text`: String or Uint8Array to encrypt
- `password`: Password for encryption
- `opts`: [Optional derivation options](#custom-options)

**Returns**: Base64-encoded encrypted data (salt + iv + ciphertext)

**Example**
```ts
const encrypted = await DataCrypt.encrypt('Hello World', 'password');
```
<br>

### ⭐ `decrypt()`: Decrypts previously encrypted data.

**Syntax**
```ts
decrypt(
  base64: string,
  password: string,
  opts?: DeriveOptions
): Promise<string | null>
```

**Parameters**
- `base64`: Base64-encoded encrypted data
- `password`: Password used for encryption
- `opts`: [Optional derivation options](#custom-options) (must match encryption options, if used)

**Returns**: Decrypted string or `null` if decryption fails.

**Example**
```ts
const decrypted = await DataCrypt.decrypt(encryptedData, 'password');
```
<br>

### ⭐ `encryptFile()`: Encrypts binary file data.

**Syntax**
```ts
encryptFile(
  fileData: Uint8Array,
  password: string,
  opts?: DeriveOptions
): Promise<string>
```

**Parameters**
- `fileData`: Uint8Array containing file data
- `password`: Password used for encryption
- `opts`: [Optional derivation options](#custom-options)

**Returns**: Base64-encoded encrypted file data.

**Example**
```ts
const fileData = new TextEncoder().encode('File content');
const encryptedFile = await DataCrypt.encryptFile(fileData, 'password');
```
<br>

### ⭐ `decryptFile()`: Decrypts previously encrypted file data.

**Syntax**
```ts
decryptFile(
  base64: string,
  password: string,
  opts?: DeriveOptions
): Promise<Uint8Array | null>
```

**Parameters**
- `base64`: Uint8Array containing file data
- `password`: Password used for encryption
- `opts`: [Optional derivation options](#custom-options) (must match encryption options)

**Returns**: Decrypted Uint8Array or `null` if decryption fails.

**Example**
```ts
const decryptedFile = await DataCrypt.decryptFile(encryptedFile, 'password');
```
<br>

### ⭐ `isEncrypted()`: Checks if a string appears to be valid encrypted data.

**Syntax**
```ts
isEncrypted(data: string): boolean
```

**Example**
```ts
const isValid = DataCrypt.isEncrypted(encryptedData);
console.log('Is encrypted?', isValid); // true or false
```
<br>

### ⭐ `generateSelfDecryptingHTML()`: Generates a standalone HTML string containing the encrypted data and a decryption script.

**Syntax**
```ts
generateSelfDecryptingHTML(
  encryptedBase64: string, 
  filename: string, 
  opts?: DeriveOptions
): string
```

**Example**
```ts
const html = DataCrypt.generateSelfDecryptingHTML(encryptedData, 'doc.pdf');
```

**Parameters**
- `encryptedBase64`: The Base64 string returned by `encrypt()` or `encryptFile()`.
- `filename`: The default filename used when the user downloads the decrypted file (e.g., '`secret.pdf`').
- `opts`: [Optional derivation options](#custom-options) (must match encryption options)

> [!NOTE]
> If you used custom options (like specific iterations) to encrypt, you must pass them here so the HTML file uses the correct parameters to derive the key.

**Returns**: A string containing the full HTML document.

<br>

### ⭐ `downloadFile()`: **[Browser Only]** Triggers an immediate file download in the browser. Useful for saving generated HTML files or decrypted binary data.

**Syntax**
```ts
downloadFile(
  content: string | Uint8Array,
  filename: string,
  mimeType: string = 'application/octet-stream'
): void
```

**Example**
```js
const html = DataCrypt.generateSelfDecryptingHTML(encryptedData, 'doc.pdf');
DataCrypt.downloadFile(html, 'secret.html', 'text/html');
```

**Parameters**
- `content`: The data to download (string or binary).
- `filename`: The name of the file to save (e.g., '`secret.html`').
- `mimeType`: (Optional) The MIME type (default: `'application/octet-stream'`).

<br>

### ⭐ `generateRandomBytes()`: Generates cryptographically secure random bytes.

**Syntax**
```ts
generateRandomBytes(length: number): Uint8Array
```

**Example**
```ts
const randomBytes = DataCrypt.generateRandomBytes(32);
```
<br>

### ⭐ `clearCache(): void`: Clears the derived key cache.

**Syntax**
```ts
clearCache(): void
```

**Example**
```ts
DataCrypt.clearCache();
```
<br>

### ⭐ `getCacheSize()`: Returns the number of cached keys.

**Syntax**
```ts
getCacheSize(): number
```

**Example**
```ts
console.log('Cached keys: ', DataCrypt.getCacheSize());
```
<br>

## Compression & Decompression

DataCrypt includes built-in GZIP compression to reduce the size of your encrypted data. This is especially useful for large text files, logs, or JSON data.

### 1. Compressing Data
When you enable compression, the data is first compressed using GZIP and then encrypted. This results in significantly smaller output files for compressible data.

**CLI Usage**

Use the `-z` or `--compress` flag during encryption:

```bash
# Encrypt and compress a large log file
dc encrypt -f app.log -o app.log.enc -z "password"
```

**API Usage**

Pass `{ compress: true }` in the options object:

```js
const bigData = JSON.stringify(largeObject);
const encrypted = await DataCrypt.encrypt(bigData, 'password', { compress: true });
```

### 1. Decompressing Data
Decompression is automatic. You do not need to specify any special flags or options when decrypting. DataCrypt automatically detects the GZIP compression headers inside the encrypted payload and decompresses the data transparently.

**CLI Usage**

```bash
# Just run the standard command; DataCrypt handles the rest
dc decrypt -f app.log.enc -o restored.log "password"
```

**API Usage**

```js
// No options needed; automatic detection
const decrypted = await DataCrypt.decrypt(encrypted, 'password');
```

<br>

## Custom Options

Customize the key derivation process:

| Option        | Type            | Default     | Description                                               |
| :------------ | :-------------- | :---------- | :-------------------------------------------------------- |
| `iterations`  | `number`        | `600000`    | Number of PBKDF2 iterations (more = stronger but slower)  |
| `hash`        | `HashAlgorithm` | `'SHA-256'` | Hash algorithm for PBKDF2                                 |
| `length`      | `KeyLength`     | `256`       | Key length in bits (128 / 192 / 256)                      |
| `saltLength`  | `number`        | `16`        | Salt length in bytes (default: 16)                        |
| `compress`    | `boolean`       | `false`     | Enable GZIP compression before encryption                 |

**Interface**
```ts
interface DeriveOptions {
  iterations?: number;
  hash?: HashAlgorithm;
  length?: KeyLength;
  saltLength?: number;
  compress?: boolean;
}
```

<br>

## Usage

### Browser Usage

#### With Bundlers (Webpack, Vite, etc.)

```ts
import { DataCrypt } from 'data-crypt';
// NOw use as normal Javascript
```

#### Direct Script Tag
You can use the same API in a browser environment.

```html
<script type="module">
  import { DataCrypt } from 'https://cdn.skypack.dev/data-crypt';

  const text = 'Hello from Browser!';
  const password = 'browser-key';

  const encrypted = await DataCrypt.encrypt(text, password);
  const decrypted = await DataCrypt.decrypt(encrypted, password);

  console.log({ encrypted, decrypted });
</script>
```

### Node.js Usage

#### CommonJS

```js
const { DataCrypt } = require('data-crypt');

async function main() {
  const encrypted = await DataCrypt.encrypt('Node.js data', 'password');
  const decrypted = await DataCrypt.decrypt(encrypted, 'password');
  console.log(decrypted);
}

main().catch(console.error);
```

#### ES Modules

```js
import { DataCrypt } from 'data-crypt';
// Use as shown in browser examples
```

<br>

## Security Considerations

### Best Practices
1. **Use Strong Passwords**: The security depends on password strength.
2. **Increase Iterations**: Use higher PBKDF2 iterations for sensitive data.
3. **Unique Salts**: Each encryption uses a random salt (automatically handled).
4. **Secure Storage**: Store encrypted data securely, separate from keys.

### Default Security Parameters
- **PBKDF2 Iterations**: 600,000 (OWASP recommended minimum)
- **Hash Algorithm**: SHA-256
- **Key Length**: 256-bit
- **Encryption**: AES-GCM with 12-byte IV
- **Salt Length**: 16 bytes

### Performance
The library is optimized for performance with:

- **Key Caching**: Derived keys are cached for same parameters
- **Native Crypto**: Uses platform's native Web Crypto API
- **Efficient Encoding**: Minimal data copying and encoding

For large files, consider streaming encryption in chunks (not currently supported).

### Limitations
- **Password Strength**: Security depends entirely on password strength
- **No Key Management**: This library doesn't handle key storage/management
- **Memory**: Large files are loaded entirely into memory

<br>

## Contributing
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request



## License

MIT © 2025 [[M B Parvez](https://www.mbparvez.me)]
