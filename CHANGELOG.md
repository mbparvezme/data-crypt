## Changelog

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

### [1.0.0-rc3] - 2025-11-25

**Added**

* **Compression Support**: Added GZIP compression using native `CompressionStream`. Use the `-z / --compress` flag in CLI or `{ compress: true }` in API.
* **Self-Decrypting HTML**: Added ability to generate standalone .html files that decrypt in the browser. Use the `--html` flag in CLI.
* **Browser Download Utility**: Added `DataCrypt.downloadFile()` for triggering downloads in browser environments.
* **CLI Improvements**: Added support for flexible argument positioning (flags can now be placed anywhere).

**Changed**

* **Core Architecture**: Refactored the monolithic `index.ts` into a modular `src/core/` structure (separating crypto, compression, HTML, and utils).
* **Type Safety**: Improved CLI argument parsing with stricter type checks.


### [1.0.0-rc2] - 2025-11-24

**Changed**

* Improved CLI help text with colored output and better examples.
* Enhanced type definitions for `DeriveOptions` to support stricter TypeScript environments.
* Fixed CLI execution permissions (`setup-bin` script).

**Fixed**

* Fixed module resolution issues in test files.
* Fixed type mismatches between Node.js Buffers and Web Crypto `BufferSource`.

### [1.0.0-rc1] - 2025-11-12

**Added**

* **Core Cryptography**: Implemented AES-GCM encryption with PBKDF2 key derivation.
* **Zero Dependencies**: Built entirely on native Web Crypto API.
* **Cross-Platform**: Full support for Node.js and modern browsers.
* **CLI**: Basic Command Line Interface for `encrypt` and `decrypt` operations on text and files.
* **Type Safety**: Complete TypeScript definitions.