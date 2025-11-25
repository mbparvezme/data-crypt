import { DataCrypt, type DeriveOptions } from "../src/index.js";

async function runTests() {
  const password = "test-password";
  const text = "Hello DataCrypt! 🔐";

  console.log("\nMain text: ", text, "\n");

  // --- 1. Basic Text Test ---
  console.log("🧩 1. Testing text encryption/decryption...");
  const encrypted = await DataCrypt.encrypt(text, password);
  const decrypted = await DataCrypt.decrypt(encrypted, password);

  if (decrypted === text) {
    console.log("✅ Text test Passed.");
  } else {
    console.error("❌ Text test failed!", { expected: text, got: decrypted });
  }

  // --- 2. Custom Options Test ---
  const opts: DeriveOptions = { iterations: 200000, hash: "SHA-512", length: 256 };

  console.log("\n🧩 2. Testing text encryption/decryption with custom options...");
  const encryptedCustom = await DataCrypt.encrypt(text, password, opts);
  const decryptedCustom = await DataCrypt.decrypt(encryptedCustom, password, opts);

  if (decryptedCustom === text) {
    console.log("✅ Text test (custom) Passed.");
  } else {
    console.error("❌ Text test (custom) failed!", { got: decryptedCustom });
  }

  // --- 3. File/Binary Test ---
  console.log("\n🧩 3. Testing file encryption/decryption...");
  const fileData = new TextEncoder().encode("File encryption example");
  const encryptedFile = await DataCrypt.encryptFile(fileData, password);
  const decryptedFile = await DataCrypt.decryptFile(encryptedFile, password);

  if (decryptedFile) {
    const decodedFile = new TextDecoder().decode(decryptedFile);
    
    if (decodedFile === "File encryption example") {
      console.log("✅ File test passed.");
    } else {
      console.error("❌ File test content mismatch!");
    }
  } else {
    console.error("❌ File test failed: Decryption returned null");
  }

  // --- 4. Utilities Test ---
  console.log("\n🧩 4. Testing utilities...");
  
  const isMsgEncrypted = DataCrypt.isEncrypted(encrypted); 
  console.log(isMsgEncrypted ? "✅ isEncrypted passed." : "❌ isEncrypted failed.");

  const cacheSize = DataCrypt.getCacheSize();
  console.log(`Cache size: ${cacheSize}`);
  DataCrypt.clearCache();
  console.log(`Cache cleared. New size: ${DataCrypt.getCacheSize()}`);

  // --- 5. Compression Test (New Feature) ---
  console.log("\n🧩 5. Testing Compression...");
  try {
    // Create a larger string to make compression noticeable
    const largeText = "A".repeat(1000) + "B".repeat(1000); 
    const compressedEncrypted = await DataCrypt.encrypt(largeText, password, { compress: true });
    
    // Decrypt without specifying compress: true (should auto-detect)
    const decompressed = await DataCrypt.decrypt(compressedEncrypted, password);

    if (decompressed === largeText) {
       console.log("✅ Compression round-trip passed.");
    } else {
       console.error("❌ Compression round-trip failed.");
    }
  } catch (e: any) {
    console.error("❌ Compression test skipped (Environment might lack CompressionStream):", e.message);
  }

  // --- 6. HTML Generation Test (New Feature) ---
  console.log("\n🧩 6. Testing HTML Generation...");
  const html = DataCrypt.generateSelfDecryptingHTML(encrypted, "secret.txt");
  if (html.startsWith("<!DOCTYPE html>") && html.includes(encrypted)) {
    console.log("✅ HTML generation passed.");
  } else {
    console.error("❌ HTML generation failed.");
  }
}

runTests().catch(console.error);