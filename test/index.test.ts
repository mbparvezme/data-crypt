import { DataCrypt, type DeriveOptions } from "../src/index";

async function runTests() {
  const password = "test-password";
  const text = "Hello DataCrypt! 🔐";

  console.log("\nMain text: ", text, "\n");

  // --- 1. Basic Text Test ---
  console.log("🧩 Testing text encryption/decryption...");
  const encrypted = await DataCrypt.encrypt(text, password);
  const decrypted = await DataCrypt.decrypt(encrypted, password);

  console.log("Encrypted (Sample):", encrypted.slice(0, 30) + "...");

  if (decrypted === text) {
    console.log("✅ Text test Passed.");
  } else {
    console.error("❌ Text test failed!", { expected: text, got: decrypted });
  }

  // --- 2. Custom Options Test ---
  const opts: DeriveOptions = { iterations: 200000, hash: "SHA-512", length: 256 };

  console.log("\n🧩 Testing text encryption/decryption with custom options...");
  const encryptedCustom = await DataCrypt.encrypt(text, password, opts);
  const decryptedCustom = await DataCrypt.decrypt(encryptedCustom, password, opts);

  // FIX: Originally checked 'decrypted === text', changed to 'decryptedCustom === text'
  if (decryptedCustom === text) {
    console.log("✅ Text test (custom) Passed.");
  } else {
    console.error("❌ Text test (custom) failed!", { got: decryptedCustom });
  }

  // --- 3. File/Binary Test ---
  console.log("\n🧩 Testing file encryption/decryption...");
  const fileData = new TextEncoder().encode("File encryption example");
  const encryptedFile = await DataCrypt.encryptFile(fileData, password);
  const decryptedFile = await DataCrypt.decryptFile(encryptedFile, password);

  // FIX: Added null check for TypeScript strict safety
  if (decryptedFile) {
    const decodedFile = new TextDecoder().decode(decryptedFile);
    console.log("Encrypted File Length:", encryptedFile.length);

    if (decodedFile === "File encryption example") {
      console.log("✅ File test passed.");
    } else {
      console.error("❌ File test content mismatch!");
    }
  } else {
    console.error("❌ File test failed: Decryption returned null");
  }

  // --- 4. Utilities Test ---
  console.log("\n🧩 Testing utilities...");
  const isMsgEncrypted = DataCrypt.isEncrypted(encrypted);
  console.log(isMsgEncrypted ? "✅ isEncrypted passed." : "❌ isEncrypted failed.");

  const cacheSize = DataCrypt.getCacheSize();
  console.log(`Cache size: ${cacheSize}`);
  DataCrypt.clearCache();
  console.log(`Cache cleared. New size: ${DataCrypt.getCacheSize()}`);
}

runTests().catch(console.error);