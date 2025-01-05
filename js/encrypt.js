const iv = new TextEncoder().encode("0000000000000000"); // 16-byte fixed IV for AESconst keyCharset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const keyCharset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

async function importAESKey(rawKey) {
  // Convert raw key (Base64, hex, etc.) to ArrayBuffer
  const keyBuffer = str2ab(rawKey); // Assuming it's in Base64 format

  console.log("key: " + keyBuffer.byteLength);

  // Import the key as a CryptoKey object
  return await crypto.subtle.importKey(
    "raw", // Key format
    keyBuffer, // Raw key as ArrayBuffer
    { name: "AES-GCM" }, // Algorithm
    true, // Extractable
    ["encrypt", "decrypt"] // Usages
  );
}

// AES-GCM Encryption
async function encryptAES(key, data) {
  const encoded = new TextEncoder().encode(data);

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv, // Initialization Vector (must be the same for encryption and decryption)
    },
    await importAESKey(key), // AES Key
    encoded // Data to be encrypted
  );

  return arrayBufferToBase64(ciphertext);
}

// AES-GCM Decryption
async function decryptAES(key, ciphertext) {
  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv, // Same IV that was used for encryption
    },
    await importAESKey(key), // AES Key
    base64ToArrayBuffer(ciphertext) // Data to be decrypted
  );

  return new TextDecoder().decode(decrypted);
}

function arrayBufferToBase64(buffer) {
  const binary = String.fromCharCode(...new Uint8Array(buffer));
  return btoa(binary);
}

// Helper function to convert Base64 to ArrayBuffer
function base64ToArrayBuffer(base64) {
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

function generateRandomString(length, charset) {
  let result = '';
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * charset.length);
    result += charset.charAt(randomIndex);
  }
  return result;
}

function generateKey() {
    return generateRandomString(32, keyCharset);
}

// PEM encoded X.509 key
async function encryptRSA2(key, plaintext) {
    try {
        const publicKey = key;
        const pub = await importPublicKey(publicKey);
        const encrypted = await encryptRSA(pub, new TextEncoder().encode(plaintext));
        const encryptedBase64 = window.btoa(ab2str(encrypted));
        return encryptedBase64.replace(/(.{64})/g, "$1\n");
    } catch (error) {
        return error;
    }
}

async function decryptRSA2(key, ciphertextB64) {
    try {
        const privateKey = key;
        const priv = await importPrivateKey(privateKey);
        const decrypted = await decryptRSA(priv, str2ab(window.atob(ciphertextB64)));
        return decrypted;
    } catch (error) {
        return error;
    }
}

async function encryptRSA(key, plaintext) {
    let encrypted = await window.crypto.subtle.encrypt({
            name: "RSA-OAEP"
        },
        key,
        plaintext
    );
    return encrypted;
}

async function decryptRSA(key, ciphertext) {
    let decrypted = await window.crypto.subtle.decrypt({
            name: "RSA-OAEP"
        },
        key,
        ciphertext
    );
    return new TextDecoder().decode(decrypted);
}

function getSpkiDer(spkiPem) {
    const pemHeader = "-----BEGIN PUBLIC KEY-----";
    const pemFooter = "-----END PUBLIC KEY-----";
    var pemContents = spkiPem.substring(pemHeader.length, spkiPem.length - pemFooter.length);
    var binaryDerString = window.atob(pemContents);
    return str2ab(binaryDerString);
}


async function importPublicKey(spkiPem) {
    return await window.crypto.subtle.importKey(
        "spki",
        getSpkiDer(spkiPem), {
            name: "RSA-OAEP",
            hash: "SHA-256",
        },
        true,
        ["encrypt"]
    );
}

async function importPrivateKey(pkcs8Pem) {
    return await window.crypto.subtle.importKey(
        "pkcs8",
        getPkcs8Der(pkcs8Pem), {
            name: "RSA-OAEP",
            hash: "SHA-256",
        },
        true,
        ["decrypt"]
    );
}



function getPkcs8Der(pkcs8Pem) {
    const pemHeader = "-----BEGIN PRIVATE KEY-----";
    const pemFooter = "-----END PRIVATE KEY-----";
    var pemContents = pkcs8Pem.substring(pemHeader.length, pkcs8Pem.length - pemFooter.length);
    var binaryDerString = window.atob(pemContents);
    return str2ab(binaryDerString);
}


//
// Helper
//

// https://stackoverflow.com/a/11058858
function str2ab(str) {
    console.log(str);
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}

function ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint8Array(buf));
}