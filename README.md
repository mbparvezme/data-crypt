# 🔐 Data-Cryp

A robust, cross-platform TypeScript/JavaScript library for encrypting and decrypting data and files using AES-GCM with PBKDF2 key derivation. Works seamlessly in both Node.js and browser environments with built-in CLI support.

<br>

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [Encrypt and Decrypt Text](#encrypt-and-decrypt-text)
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

## 🚀 Features

* Secure Encryption: AES-GCM with PBKDF2 key derivation
* Built-in CLI support
* Cross-Platform: Works in Node.js and browsers
* Zero Dependencies: Uses native Web Crypto API
* Type Safe: Written in TypeScript with full type definitions
* Configurable: Customizable encryption parameters
* File Support: Encrypt/decrypt binary file data
* Simple API: Easy-to-use static methods

<br>

## 📦 Installation

```bash
npm install data-crypt
```

or

```bash
yarn add data-crypt
```

<br>

## 🕓 Quick Start

###  Encrypt and Decrypt Text

```js
import { DataCrypt } from 'data-crypt';

// Encrypt a string
const encrypted = await DataCrypt.encrypt('Secret message', 'my-password');
console.log('Encrypted:', encrypted);

// Decrypt the data
const decrypted = await DataCrypt.decrypt(encrypted, 'my-password');
console.log('Decrypted:', decrypted); // 'Secret message'
```
<br>

## 🔳 CLI Usage

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
| -i, --iterations &lt;number&gt; | PBKDF2 iterations | -i 1000000 |
| --hash &lt;algorithm&gt; | Hash algorithm (SHA-256, SHA-384, SHA-512) | --hash SHA-512 |
| -l, --length &lt;bits&gt; | Hash algorithm (SHA-256, SHA-384, SHA-512) | --hash SHA-512 |
| -s, --salt-length &lt;bytes&gt; | Salt length in bytes | -s 32 |


### Examples with Advanced Options

```bash
# Encrypt with custom parameters
dc encrypt "text" -i 1000000 --hash SHA-512 "password"

# Encrypt file with advanced options
dc encrypt -f document.pdf -o secure.pdf -i 500000 --hash SHA-384 "password"
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

##  📄 API Reference

###  ⭐ `encrypt()`: Encrypts text or binary data.

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
- `fileData`: Uint8Array containing file data
- `password`: Password used for encryption
- `opts`: [Optional derivation options](#custom-options) (must match encryption options)

**Returns**: Decrypted Uint8Array or `null` if decryption fails.

**Example**
```ts
const decryptedFile = await DataCrypt.decryptFile(encryptedFile, 'password');
```
<br>

### ⭐ `isEncryptedData()`: Checks if a string appears to be valid encrypted data.

**Syntax**
```ts
isEncryptedData(data: string): boolean
```

**Example**
```ts
const isValid = DataCrypt.isEncryptedData(encryptedData);
console.log('Is encrypted?', isValid); // true or false
```
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

## ⚙️ Custom Options

Customize the key derivation process:

| Option        | Type            | Default     | Description                                               |
| :------------ | :-------------- | :---------- | :-------------------------------------------------------- |
| `iterations`  | `number`        | `600000`    | Number of PBKDF2 iterations (more = stronger but slower)  |
| `hash`        | `HashAlgorithm` | `'SHA-256'` | Hash algorithm for PBKDF2                                 |
| `length`      | `KeyLength`     | `256`       | Key length in bits (128 / 192 / 256)                      |
| `saltLength`  | `number`        | `16`        | Salt length in bytes (default: 16)                        |

**Interface**
```ts
interface DeriveOptions {
  iterations?: number;
  hash?: HashAlgorithm;
  length?: KeyLength;
  saltLength?: number;
}
```

<br>

## 🎯 Usage

### 🌐 Browser Usage

#### With Bundlers (Webpack, Vite, etc.)

```ts
import { DataCrypt } from 'datacrypt';
// NOw use as normal Javascript
```

#### Direct Script Tag
You can use the same API in a browser environment.

```html
<script type="module">
  import { DataCryp } from 'https://cdn.skypack.dev/data-cryp';

  const text = 'Hello from Browser!';
  const password = 'browser-key';

  const encrypted = await DataCryp.encrypt(text, password);
  const decrypted = await DataCryp.decrypt(encrypted, password);

  console.log({ encrypted, decrypted });
</script>
```

### 📦 Node.js Usage

#### CommonJS

```js
const { DataCrypt } = require('datacrypt');

async function main() {
  const encrypted = await DataCrypt.encrypt('Node.js data', 'password');
  const decrypted = await DataCrypt.decrypt(encrypted, 'password');
  console.log(decrypted);
}

main().catch(console.error);
```

#### ES Modules

```js
import { DataCrypt } from 'datacrypt';
// Use as shown in browser examples
```

<br>

## 🔒 Security Considerations

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

## 💁‍♂️ Contributing
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request



## 🛡️ License

MIT © 2025 [[M B Parvez](https://www.mbparvez.me)]
