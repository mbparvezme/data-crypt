#!/usr/bin/env node
import { DataCrypt } from './index.js';
import { readFileSync, writeFileSync } from 'fs';
import { argv, stdin, exit } from 'process';
import * as path from 'path';
function showHelp() {
    console.log(`
${color('blue', '='.repeat(60))}
${bold(color('blue', '🔐  DataCrypt CLI (dc) - Encrypt/Decrypt files and data'))}
${color('blue', '='.repeat(60))}

${color('yellow', 'USAGE:')}
  ${color('green', 'dc')} ${color('white', '<command>')} ${color('gray', '[options]')}

${color('yellow', 'COMMANDS:')}
  ${color('green', 'encrypt')} ${color('white', '<text> <password>')}      ${color('gray', '# Encrypt text')}
  ${color('green', 'decrypt')} ${color('white', '<encrypted> <password>')} ${color('gray', '# Decrypt text')}

${color('yellow', 'FILE OPERATIONS:')}
  ${color('magenta', '-f, --file')} ${color('white', '<path>')}              ${color('gray', '# Input file path')}
  ${color('magenta', '-o, --output')} ${color('white', '<path>')}            ${color('gray', '# Output file path')}

${color('yellow', 'NEW FEATURES:')}
  ${color('magenta', '-z, --compress')}               ${color('gray', '# Compress data before encrypting (GZIP)')}
  ${color('magenta', '--html')}                       ${color('gray', '# Generate self-decrypting HTML file')}

${color('yellow', 'ADVANCED OPTIONS:')}
  ${color('magenta', '-i, --iterations')} ${color('white', '<number>')}      ${color('gray', '# PBKDF2 iterations')}
  ${color('magenta', '--hash')} ${color('white', '<algorithm>')}             ${color('gray', '# SHA-256, SHA-384, SHA-512')}
  ${color('magenta', '-l, --length')} ${color('white', '<bits>')}            ${color('gray', '# 128, 192, 256')}

${color('yellow', 'EXAMPLES:')}
  ${color('gray', '# Compress and encrypt a large file')}
  ${color('green', 'dc encrypt')} ${color('magenta', '-f large.log -o large.enc -z')} ${color('white', '"password"')}

  ${color('gray', '# Create a self-decrypting HTML file for a friend')}
  ${color('green', 'dc encrypt')} ${color('magenta', '-f secret.pdf -o secret.html --html')} ${color('white', '"password"')}

`);
}
function color(colorName, text) {
    const colors = {
        reset: '\x1b[0m',
        blue: '\x1b[34m',
        green: '\x1b[32m',
        yellow: '\x1b[33m',
        magenta: '\x1b[35m',
        cyan: '\x1b[36m',
        white: '\x1b[37m',
        gray: '\x1b[90m',
    };
    return `${colors[colorName] || colors.reset}${text}${colors.reset}`;
}
const bold = (text) => `\x1b[1m${text}\x1b[0m`;
function parseArgs() {
    const args = argv.slice(2);
    const options = {
        operation: 'encrypt',
        file: false
    };
    if (args.includes('-h') || args.includes('--help')) {
        options.help = true;
        return options;
    }
    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        switch (arg) {
            case 'encrypt':
            case 'decrypt':
                options.operation = arg;
                if (!options.file && args[i + 1] && !args[i + 1].startsWith('-')) {
                    options.input = args[++i];
                    if (args[i + 1] && !args[i + 1].startsWith('-')) {
                        options.password = args[++i];
                    }
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
                options.length = parseInt(args[++i]);
                break;
            case '-s':
            case '--salt-length':
                options.saltLength = parseInt(args[++i]);
                break;
            case '-p':
            case '--password':
                options.password = args[++i];
                break;
            // New Flags
            case '-z':
            case '--compress':
                options.compress = true;
                break;
            case '--html':
                options.html = true;
                break;
        }
    }
    return options;
}
function readStdin() {
    return new Promise((resolve) => {
        let data = '';
        stdin.setEncoding('utf8');
        stdin.on('data', chunk => data += chunk);
        stdin.on('end', () => resolve(data.trim()));
    });
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
                // Fallback: If input is set, but password isn't, and the last arg wasn't consumed as input
                if (options.input !== lastArg) {
                    password = lastArg;
                }
            }
        }
        if (!password) {
            console.error('Error: Password is required');
            exit(1);
        }
        let input = options.input;
        if (!input && !stdin.isTTY && !options.file) {
            input = await readStdin();
        }
        // Build crypto options with strict typing
        const cryptoOpts = {
            iterations: options.iterations,
            hash: options.hash,
            length: options.length,
            saltLength: options.saltLength,
            compress: options.compress
        };
        if (options.file) {
            if (!input) {
                console.error('Error: Input file path required with -f');
                exit(1);
            }
            const fileBuffer = readFileSync(input);
            const fileBytes = new Uint8Array(fileBuffer);
            if (options.operation === 'encrypt') {
                // --- Encryption Flow ---
                const encrypted = await DataCrypt.encryptFile(fileBytes, password, cryptoOpts);
                if (options.html) {
                    // GENERATE HTML
                    const filename = path.basename(input);
                    const htmlContent = DataCrypt.generateSelfDecryptingHTML(encrypted, filename, cryptoOpts);
                    if (options.output) {
                        writeFileSync(options.output, htmlContent);
                        console.log(`✅ Self-decrypting HTML saved to: ${options.output}`);
                    }
                    else {
                        console.log(htmlContent);
                    }
                }
                else {
                    // STANDARD OUTPUT
                    if (options.output) {
                        writeFileSync(options.output, encrypted);
                        const action = options.compress ? 'Compressed & Encrypted' : 'Encrypted';
                        console.log(`✅ File ${action} and saved to: ${options.output}`);
                    }
                    else {
                        console.log(encrypted);
                    }
                }
            }
            else {
                // --- Decryption Flow ---
                // For decryption, read the file as string (Base64)
                const encryptedData = new TextDecoder().decode(fileBytes);
                const decrypted = await DataCrypt.decryptFile(encryptedData, password, cryptoOpts);
                if (decrypted) {
                    if (options.output) {
                        writeFileSync(options.output, decrypted);
                        console.log(`✅ File decrypted and saved to: ${options.output}`);
                    }
                    else {
                        // Try UTF-8
                        try {
                            console.log(new TextDecoder().decode(decrypted));
                        }
                        catch {
                            console.log(Buffer.from(decrypted).toString('base64'));
                        }
                    }
                }
                else {
                    console.error('❌ Decryption failed');
                    exit(1);
                }
            }
        }
        else {
            // Text Operations
            if (!input) {
                console.error('Error: No input text');
                exit(1);
            }
            if (options.operation === 'encrypt') {
                const encrypted = await DataCrypt.encrypt(input, password, cryptoOpts);
                if (options.html) {
                    const htmlContent = DataCrypt.generateSelfDecryptingHTML(encrypted, 'secret-message.txt', cryptoOpts);
                    if (options.output)
                        writeFileSync(options.output, htmlContent);
                    else
                        console.log(htmlContent);
                }
                else {
                    if (options.output)
                        writeFileSync(options.output, encrypted);
                    else
                        console.log(encrypted);
                }
            }
            else {
                const decrypted = await DataCrypt.decrypt(input, password, cryptoOpts);
                if (decrypted) {
                    if (options.output) {
                        // Determine if binary or string
                        const outData = typeof decrypted === 'string' ? decrypted : Buffer.from(decrypted);
                        writeFileSync(options.output, outData);
                    }
                    else {
                        console.log(typeof decrypted === 'string' ? decrypted : Buffer.from(decrypted).toString('utf-8'));
                    }
                }
                else {
                    console.error('❌ Decryption failed');
                    exit(1);
                }
            }
        }
    }
    catch (error) {
        console.error('❌ Error:', error.message);
        exit(1);
    }
}
main().catch(console.error);
