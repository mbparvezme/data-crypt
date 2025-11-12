#!/usr/bin/env node
import { DataCrypt } from './index.js';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { argv, stdin, exit } from 'process';

interface CLIOptions {
  operation: 'encrypt' | 'decrypt';
  input?: string;
  output?: string;
  password?: string;
  file?: boolean;
  iterations?: number;
  hash?: string;
  length?: number;
  saltLength?: number;
  help?: boolean;
}

function showHelp() {
  console.log(`
DataCrypt CLI (dc) - Encrypt/Decrypt files and data

Usage:
  dc <command> [options]

Commands:
  encrypt <text> <password>    Encrypt text
  decrypt <encrypted> <password>  Decrypt text

Options for file operations:
  -f, --file <path>          Input file path
  -o, --output <path>        Output file path

Advanced options:
  -i, --iterations <number>  PBKDF2 iterations (default: 600000)
  --hash <algorithm>         Hash algorithm: SHA-256, SHA-384, SHA-512
  -l, --length <bits>        Key length: 128, 192, 256
  -s, --salt-length <bytes>  Salt length in bytes (default: 16)

General:
  -h, --help                 Show this help

Examples:
  # Text encryption/decryption
  dc encrypt "secret text" "password"
  dc decrypt "ENCRYPTED_BASE64" "password"

  # File encryption/decryption
  dc encrypt -f input.txt -o encrypted.txt "password"
  dc decrypt -f encrypted.txt -o decrypted.txt "password"

  # With advanced options
  dc encrypt -f document.pdf -o secure.pdf -i 1000000 --hash SHA-512 "password"
  dc encrypt "text" -i 500000 -l 256 "password"
`);
}

function parseArgs(): CLIOptions {
  const args = argv.slice(2);
  const options: CLIOptions = {
    operation: 'encrypt',
    file: false
  };

  // First, check for help
  if (args.includes('-h') || args.includes('--help')) {
    options.help = true;
    return options;
  }

  // Parse command and arguments
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    switch (arg) {
      case 'encrypt':
      case 'decrypt':
        options.operation = arg;
        // Next arguments should be text and password (for simple usage)
        if (!options.file && args[i + 2] && !args[i + 2].startsWith('-')) {
          options.input = args[++i];
          options.password = args[++i];
        }
        break;
        
      case '-f':
      case '--file':
        options.file = true;
        options.input = args[++i];
        break;
        
      case '-o':
      case '--output':
        options.output = args[++i];
        break;
        
      case '-i':
      case '--iterations':
        options.iterations = parseInt(args[++i]);
        break;
        
      case '--hash':
        options.hash = args[++i];
        break;
        
      case '-l':
      case '--length':
        options.length = parseInt(args[++i]) as any;
        break;
        
      case '-s':
      case '--salt-length':
        options.saltLength = parseInt(args[++i]);
        break;
        
      case '-p':
      case '--password':
        options.password = args[++i];
        break;
    }
  }

  return options;
}

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = '';
    stdin.setEncoding('utf8');
    stdin.on('data', chunk => data += chunk);
    stdin.on('end', () => resolve(data.trim()));
  });
}

async function encryptData(text: string, password: string, opts?: any): Promise<string> {
  return await DataCrypt.encrypt(text, password, opts);
}

async function decryptData(encrypted: string, password: string, opts?: any): Promise<string | null> {
  return await DataCrypt.decrypt(encrypted, password, opts);
}

async function encryptFile(filePath: string, password: string, opts?: any): Promise<string> {
  if (!existsSync(filePath)) {
    throw new Error(`File not found: ${filePath}`);
  }
  const fileData = readFileSync(filePath);
  return await DataCrypt.encryptFile(new Uint8Array(fileData), password, opts);
}

async function decryptFile(filePath: string, password: string, opts?: any): Promise<Uint8Array | null> {
  if (!existsSync(filePath)) {
    throw new Error(`File not found: ${filePath}`);
  }
  const encryptedData = readFileSync(filePath, 'utf8');
  return await DataCrypt.decryptFile(encryptedData, password, opts);
}

async function main() {
  const options = parseArgs();

  if (options.help || argv.length <= 2) {
    showHelp();
    return;
  }

  try {
    let password = options.password;
    if (!password) {
      const lastArg = argv[argv.length - 1];
      if (lastArg && !lastArg.startsWith('-') && lastArg !== 'encrypt' && lastArg !== 'decrypt') {
        password = lastArg;
      }
    }

    if (!password) {
      console.error('Error: Password is required');
      console.error('Example: dc encrypt "text" "password"');
      console.error('Example: dc encrypt -f file.txt "password"');
      exit(1);
    }

    // Get input
    let input = options.input;
    if (!input && !stdin.isTTY && !options.file) {
      input = await readStdin();
    }

    // Build options object
    const cryptoOpts: any = {};
    if (options.iterations) cryptoOpts.iterations = options.iterations;
    if (options.hash) cryptoOpts.hash = options.hash;
    if (options.length) cryptoOpts.length = options.length;
    if (options.saltLength) cryptoOpts.saltLength = options.saltLength;

    if (options.file) {
      // File operations
      if (!input) {
        console.error('Error: Input file path required with -f/--file');
        exit(1);
      }

      if (options.operation === 'encrypt') {
        const encrypted = await encryptFile(input, password, cryptoOpts);
        if (options.output) {
          writeFileSync(options.output, encrypted);
          console.log(`✅ File encrypted and saved to: ${options.output}`);
        } else {
          console.log(encrypted);
        }
      } else {
        const decrypted = await decryptFile(input, password, cryptoOpts);
        if (decrypted) {
          if (options.output) {
            writeFileSync(options.output, decrypted);
            console.log(`✅ File decrypted and saved to: ${options.output}`);
          } else {
            // Try to decode as text, otherwise show as base64
            try {
              const text = new TextDecoder().decode(decrypted);
              console.log(text);
            } catch {
              console.log(Buffer.from(decrypted).toString('base64'));
            }
          }
        } else {
          console.error('❌ Decryption failed - wrong password or corrupted data');
          exit(1);
        }
      }
    } else {
      // Text operations
      if (!input) {
        console.error('Error: No input text provided');
        console.error('Example: dc encrypt "your text" "password"');
        exit(1);
      }

      if (options.operation === 'encrypt') {
        const encrypted = await encryptData(input, password, cryptoOpts);
        if (options.output) {
          writeFileSync(options.output, encrypted);
          console.log(`✅ Text encrypted and saved to: ${options.output}`);
        } else {
          console.log(encrypted);
        }
      } else {
        const decrypted = await decryptData(input, password, cryptoOpts);
        if (decrypted) {
          if (options.output) {
            writeFileSync(options.output, decrypted);
            console.log(`✅ Text decrypted and saved to: ${options.output}`);
          } else {
            console.log(decrypted);
          }
        } else {
          console.error('❌ Decryption failed - wrong password or corrupted data');
          exit(1);
        }
      }
    }

  } catch (error: any) {
    console.error('❌ Error:', error.message);
    exit(1);
  }
}

// Run the CLI
main().catch(console.error);