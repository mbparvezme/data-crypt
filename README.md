# 🔐 DataCryp

**DataCryp** is a lightweight and powerful encryption library for **Node.js** and **browser**.
It allows you to **encrypt and decrypt text or files** using a password — safely and easily.

It uses **AES-GCM** with a derived key from **PBKDF2**, supporting custom iterations, hash, and key length.

---

## 🚀 Features

* Works in **both Browser and Node.js**
* Encrypt and decrypt **text or files**
* Uses **AES-GCM (256-bit)** encryption
* Password-based key derivation with **PBKDF2**
* Customizable:

  * Iteration count
  * Hash function (e.g., `SHA-256`, `SHA-512`)
  * Key length (128, 192, 256 bits)
* Written in **TypeScript-friendly** modern JavaScript

---

## 📦 Installation

```bash
npm install data-cryp
```

or

```bash
yarn add data-cryp
```

---

## 🧠 Basic Usage

### Encrypt and Decrypt Text

```js
import { DataCryp } from 'data-cryp';

(async () => {
  const password = 'my-secret-password';
  const text = 'Hello, DataCryp!';

  // Encrypt text
  const encrypted = await DataCryp.encrypt(text, password);
  console.log('Encrypted:', encrypted);

  // Decrypt text
  const decrypted = await DataCryp.decrypt(encrypted, password);
  console.log('Decrypted:', decrypted);
})();
```

---

## ⚙️ Custom Options

You can customize how the encryption key is derived.

| Option       | Default     | Description                                              |
| :----------- | :---------- | :------------------------------------------------------- |
| `iterations` | `100000`    | Number of PBKDF2 iterations (more = stronger but slower) |
| `hash`       | `'SHA-256'` | Hash algorithm for PBKDF2                                |
| `length`     | `256`       | Key length in bits (128 / 192 / 256)                     |

```js
const encrypted = await DataCryp.encrypt('My Data', 'password123', {
  iterations: 200000,
  hash: 'SHA-512',
  length: 256
});
```

---

## 📁 Encrypt and Decrypt Files

### Encrypt File (Node.js)

```js
import fs from 'fs';
import { DataCryp } from 'data-cryp';

(async () => {
  const fileBuffer = await fs.promises.readFile('example.txt');

  const encryptedFile = await DataCryp.encryptFile(fileBuffer, 'mypassword');
  await fs.promises.writeFile('example.enc', encryptedFile);

  console.log('File encrypted and saved as example.enc');
})();
```

### Decrypt File (Node.js)

```js
import fs from 'fs';
import { DataCryp } from 'data-cryp';

(async () => {
  const encryptedData = await fs.promises.readFile('example.enc', 'utf8');

  const decryptedFile = await DataCryp.decryptFile(encryptedData, 'mypassword');
  await fs.promises.writeFile('example-decrypted.txt', decryptedFile);

  console.log('File decrypted and saved as example-decrypted.txt');
})();
```

---

## 🌐 Browser Usage

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

---

## 🧩 API Reference

### `DataCryp.encrypt(text, password, options?)`

Encrypts a string or Uint8Array. Returns a Base64 string.

### `DataCryp.decrypt(base64, password, options?)`

Decrypts Base64 data. Returns a UTF-8 string or `null` if decryption fails.

### `DataCryp.encryptFile(fileData, password, options?)`

Encrypts binary file data (Buffer or Uint8Array). Returns Base64 string.

### `DataCryp.decryptFile(base64, password, options?)`

Decrypts Base64 file data. Returns a `Uint8Array`.

---

## ⚠️ Notes

* Always **use a strong password**.
* The encrypted output includes the **salt**, **IV**, and **ciphertext**, so everything needed for decryption is inside.
* Each encryption call generates a new random salt and IV.
* You can safely store or transmit the Base64 result.

---

## 🧑‍💻 License

MIT © 2025 [Your Name or Org]
