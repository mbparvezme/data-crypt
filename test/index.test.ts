import { DataCrypt, type DeriveOptions } from "../src/index.ts";

async function runTests() {
  const password = "test-password";
  const text = "Hello DataCrypt! 🔐";

  console.log("\nMain text: ", text, "\n\n");

  console.log("🧩 Testing text encryption/decryption...");
  const encrypted = await DataCrypt.encrypt(text, password);
  const decrypted = await DataCrypt.decrypt(encrypted, password);
  console.log("Encrypted:", encrypted);
  console.log("Decrypted:", decrypted);
  console.log(decrypted === text ? "✅ Text test Passed." : "❌ Text test failed!");

  // Custom options
  const opts: DeriveOptions = {iterations: 200000, hash: "SHA-512", length: 256};

  console.log("\n🧩 Testing text encryption/decryption with custom options...");
  const encryptedCustom = await DataCrypt.encrypt(text, password, opts);
  const decryptedCustom = await DataCrypt.decrypt(encryptedCustom, password, opts);
  console.log("Encrypted:", encryptedCustom);
  console.log("Decrypted:", decryptedCustom);
    console.log(decrypted === text ? "✅ Text test (custom) Passed." : "❌ Text test (custom) failed!");
  console.log("✅ Text test (custom):", decryptedCustom === text);

  console.log("\n\n🧩 Testing file encryption/decryption...");
  const fileData = new TextEncoder().encode("File encryption example");
  const encryptedFile = await DataCrypt.encryptFile(fileData, password);
  const decryptedFile = await DataCrypt.decryptFile(encryptedFile, password);
  const decodedFile = new TextDecoder().decode(decryptedFile);
  console.log("Encrypted File:", encryptedFile);
  console.log("Decrypted File:", decodedFile);
  console.log(decodedFile === "File encryption example" ? "✅ File test passed." : "❌ File test failed!");
}

runTests().catch(console.error);
