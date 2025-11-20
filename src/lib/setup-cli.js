import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

// Helper to handle __dirname in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const cliPath = path.join(__dirname, '..', 'cli.ts');

try {
  if (fs.existsSync(cliPath)) {
    fs.chmodSync(cliPath, '755');
    console.log('✔ CLI executable permissions set.');
  } else {
    console.warn('⚠ CLI file not found at:', cliPath);
  }
} catch (err) {
  console.error('Failed to set permissions:', err);
}