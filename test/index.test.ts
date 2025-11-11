import { DataCrypt } from "../src/index";

async function runTests() {
  const password = "test-password";
  const text = "Hello DataCrypt! 🔐";

  console.log("🧩 Testing text encryption/decryption...");
  const encrypted = await DataCrypt.encrypt(text, password);
  const decrypted = await DataCrypt.decrypt(encrypted, password);
  console.log("Encrypted:", encrypted);
  console.log("Decrypted:", decrypted);
  console.log("✅ Text test:", decrypted === text);

  console.log("\n🧩 Testing file encryption/decryption...");
  const fileData = new TextEncoder().encode("File encryption example");
  const encryptedFile = await DataCrypt.encryptFile(fileData, password);
  const decryptedFile = await DataCrypt.decryptFile(encryptedFile, password);
  const decodedFile = new TextDecoder().decode(decryptedFile);

  console.log("Encrypted File:", encryptedFile);
  console.log("Decrypted File:", decodedFile);
  console.log("✅ File test:", decodedFile === "File encryption example");
}

runTests().catch(console.error);
