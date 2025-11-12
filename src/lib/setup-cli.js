import { chmod } from 'fs/promises';
import { existsSync } from 'fs';

async function setupCLI() {
  const cliPath = './dist/cli.js';
  
  if (existsSync(cliPath)) {
    try {
      await chmod(cliPath, 0o755);
      console.log('✅ CLI executable permissions set');
    } catch (error) {
      console.log('⚠️  Could not set executable permissions (Windows may ignore this)');
    }
  }
}

setupCLI();