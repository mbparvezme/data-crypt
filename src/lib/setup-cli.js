import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

// Helper to handle __DIRNAME in ESM
const __FILENAME = fileURLToPath(import.meta.url);
const __DIRNAME = path.dirname(__FILENAME);

const cliPath = path.join(__DIRNAME, '..', 'cli.ts');

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