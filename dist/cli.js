#!/usr/bin/env node
import { DataCrypt } from './index.js';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { argv, stdin, exit } from 'process';
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

${color('yellow', 'ADVANCED OPTIONS:')}
  ${color('magenta', '-i, --iterations')} ${color('white', '<number>')}      ${color('gray', '# PBKDF2 iterations')} ${color('gray', '(default: 600,000)')}
  ${color('magenta', '--hash')} ${color('white', '<algorithm>')}             ${color('gray', '# Hash algorithm:')} ${color('cyan', 'SHA-256, SHA-384, SHA-512')}
  ${color('magenta', '-l, --length')} ${color('white', '<bits>')}            ${color('gray', '# Key length:')} ${color('cyan', '128, 192, 256')}
  ${color('magenta', '-s, --salt-length')} ${color('white', '<bytes>')}      ${color('gray', '# Salt length')} ${color('gray', '(default: 16)')}

${color('yellow', 'GENERAL:')}
  ${color('magenta', '-h, --help')}                     ${color('gray', '# Show this help message')}

${color('yellow', 'EXAMPLES:')}
  ${color('gray', '# Text encryption/decryption')}
  ${color('cyan', '→')} ${color('green', 'dc encrypt')} ${color('white', '"secret text"')} ${color('magenta', '"password"')}
  ${color('cyan', '→')} ${color('green', 'dc decrypt')} ${color('white', '"ENCRYPTED_BASE64"')} ${color('magenta', '"password"')}

  ${color('gray', '# File encryption/decryption')}
  ${color('cyan', '→')} ${color('green', 'dc encrypt')} ${color('magenta', '-f input.txt -o encrypted.txt')} ${color('white', '"password"')}
  ${color('cyan', '→')} ${color('green', 'dc decrypt')} ${color('magenta', '-f encrypted.txt -o decrypted.txt')} ${color('white', '"password"')}

  ${color('gray', '# With advanced options')}
  ${color('cyan', '→')} ${color('green', 'dc encrypt')} ${color('magenta', '-f document.pdf -o secure.pdf -i 1000000 --hash SHA-512')} ${color('white', '"password"')}
  ${color('cyan', '→')} ${color('green', 'dc encrypt')} ${color('white', '"text"')} ${color('magenta', '-i 500000 -l 256')} ${color('white', '"password"')}

${color('gray', '┌' + '─'.repeat(60) + '┐')}
${color('gray', '│')} ${bold(color('gray', '💎 Tip'))} ${color('gray', '                                                      │')}
${color('gray', '│')} ${color('gray', 'Use quotes around text/passwords with spaces!')} ${color('gray', '             │')}
${color('gray', '│')} ${color('gray', 'For more, visit: ')} ${color('white', 'https://github.com/mbparvezme/data-crypt')} ${color('gray', '│')}
${color('gray', '└' + '─'.repeat(60) + '┘')}

`);
}
// Color utility function
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
        brightWhite: '\x1b[97m'
    };
    const colorCode = colors[colorName] || colors.reset;
    return `${colorCode}${text}${colors.reset}`;
}
const bold = (text) => `\x1b[1m${text}\x1b[0m`;
function parseArgs() {
    const args = argv.slice(2);
    const options = {
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
async function encryptData(text, password, opts) {
    return await DataCrypt.encrypt(text, password, opts);
}
async function decryptData(encrypted, password, opts) {
    return await DataCrypt.decrypt(encrypted, password, opts);
}
async function encryptFile(filePath, password, opts) {
    if (!existsSync(filePath)) {
        throw new Error(`File not found: ${filePath}`);
    }
    const fileData = readFileSync(filePath);
    return await DataCrypt.encryptFile(new Uint8Array(fileData), password, opts);
}
async function decryptFile(filePath, password, opts) {
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
        const cryptoOpts = {};
        if (options.iterations)
            cryptoOpts.iterations = options.iterations;
        if (options.hash)
            cryptoOpts.hash = options.hash;
        if (options.length)
            cryptoOpts.length = options.length;
        if (options.saltLength)
            cryptoOpts.saltLength = options.saltLength;
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
                }
                else {
                    console.log(encrypted);
                }
            }
            else {
                const decrypted = await decryptFile(input, password, cryptoOpts);
                if (decrypted) {
                    if (options.output) {
                        writeFileSync(options.output, decrypted);
                        console.log(`✅ File decrypted and saved to: ${options.output}`);
                    }
                    else {
                        try {
                            const text = new TextDecoder().decode(decrypted);
                            console.log(text);
                        }
                        catch {
                            console.log(Buffer.from(decrypted).toString('base64'));
                        }
                    }
                }
                else {
                    console.error('❌ Decryption failed - wrong password or corrupted data');
                    exit(1);
                }
            }
        }
        else {
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
                }
                else {
                    console.log(encrypted);
                }
            }
            else {
                const decrypted = await decryptData(input, password, cryptoOpts);
                if (decrypted) {
                    if (options.output) {
                        writeFileSync(options.output, decrypted);
                        console.log(`✅ Text decrypted and saved to: ${options.output}`);
                    }
                    else {
                        console.log(decrypted);
                    }
                }
                else {
                    console.error('❌ Decryption failed - wrong password or corrupted data');
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
// Run the CLI
main().catch(console.error);
