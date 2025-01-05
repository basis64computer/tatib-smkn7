const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
  "Content-Type": "application/json", // Ensure the response is JSON
}

function handleOptions(request) {
  let headers = request.headers;
  if (
    headers.get("Origin") !== null &&
    headers.get("Access-Control-Request-Method") !== null &&
    headers.get("Access-Control-Request-Headers") !== null
  ) {
    let respHeaders = {
      ...corsHeaders,
      "Access-Control-Allow-Headers": request.headers.get("Access-Control-Request-Headers"),
    };
    return new Response(null, {
      headers: respHeaders,
    });
  } else {
    return new Response(null, {
      headers: {
        Allow: "GET, HEAD, POST, OPTIONS",
      },
    });
  }
}

// Export the fetch function
export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env);
  },
};

// Generate RSA key pair using the Web Crypto API
async function generateRSAKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true, // extractable (key can be exported)
    ["encrypt", "decrypt"]
  );

  return keyPair;
}

// Export CryptoKey to PEM format
async function exportKeyToPEM(key) {
  let exportFormat;
  if (key.type === "public") {
    exportFormat = "spki";  // Public keys are exported as 'spki'
  } else if (key.type === "private") {
    exportFormat = "pkcs8"; // Private keys are exported as 'pkcs8'
  }

  const exported = await crypto.subtle.exportKey(exportFormat, key);
  const exportedAsString = arrayBufferToBase64(exported);
  
  const pemHeader = key.type === "public" ? "PUBLIC KEY" : "PRIVATE KEY";
  const pemString = `-----BEGIN ${pemHeader}-----\n${exportedAsString.match(/.{1,64}/g).join('\n')}\n-----END ${pemHeader}-----`;

  return pemString;
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

function str2ab(str) {
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

async function decryptRSA2(key, ciphertextB64) {
  try {
    const privateKey = key;
      const priv = await importPrivateKey(privateKey);
      const decrypted = await decryptRSA(priv, str2ab(atob(ciphertextB64)));
      return decrypted;
  } catch (error) {
      return error;
  }
}

async function encryptRSA(key, plaintext) {
  let encrypted = await crypto.subtle.encrypt({
          name: "RSA-OAEP"
      },
      key,
      plaintext
  );
  return encrypted;
}

async function decryptRSA(key, ciphertext) {
  let decrypted = await crypto.subtle.decrypt({
          name: "RSA-OAEP"
      },
      key,
      ciphertext
  );
  return new TextDecoder().decode(decrypted);
}

async function importPrivateKey(pkcs8Pem) {
  return await crypto.subtle.importKey(
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
  var binaryDerString = atob(pemContents);
  return str2ab(binaryDerString);
}

const iv = new TextEncoder().encode("0000000000000000"); // 16-byte fixed IV for AESconst keyCharset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const keyCharset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

async function importAESKey(rawKey) {
  // Convert raw key (Base64, hex, etc.) to ArrayBuffer
  const keyBuffer = base64ToArrayBuffer(rawKey); // Assuming it's in Base64 format

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
async function encrypt(key, data) {
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
async function decrypt(key, ciphertext) {
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

let queue = {};
let clients = {};

function generateRandomString(length, charset) {
  let result = '';
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * charset.length);
    result += charset.charAt(randomIndex);
  }
  return result;
}

async function loadSession(env) {
  return JSON.parse(await env.session.get("session"));
}

async function saveSession(env) {
  await env.session.put("session", JSON.stringify(clients));
}

async function handleRequest(request, env) {
  if (request.method === "OPTIONS") {
    return handleOptions(request);
  } else if (request.method === "GET") {
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    
    // Generate RSA Key Pair
    const { publicKey, privateKey } = await generateRSAKeyPair();

    // Convert public and private keys to PEM format
    const publicKeyPEM = await exportKeyToPEM(publicKey);
    const privateKeyPEM = await exportKeyToPEM(privateKey);

    let session = generateRandomString(32, charset);

    // Store session keys
    queue[session] = {
      private_key: privateKeyPEM,
      public_key: publicKeyPEM,
    };

    // Return JSON response with session ID and public key
    return new Response(JSON.stringify({
      session_id: session,
      public_key: publicKeyPEM,
    }), {
      headers: corsHeaders,
    });
  } else {
    // Handle other request methods
    let jsonResponse;
    clients = JSON.parse(await env.session.get("session"));;
    if (request.headers.get("type") == "SCOREBOARD") {
      let body = await request.json();
      if (clients[body.session_id]) {
        jsonResponse = {ok: true, ciphertext: await encrypt(clients[body.session_id].key, JSON.stringify(getScoreBoard(body.session_id)))};
      } else {
        jsonResponse = {ok: false, error: "invalid session id"}
      }
    } else if (request.headers.get("type") == "GETDATA") {
      let body = await request.json();
      if (clients[body.session_id]) {
        jsonResponse = {ok: true, ciphertext: await encrypt(clients[body.session_id].key, JSON.stringify(getData(body.session_id)))};
      } else {
        jsonResponse = {ok: false, error: "invalid session id"}
      }
    } else if (request.headers.get("type") == "LOGOUT") {
      let body = await request.json();
      delete clients[body.session_id];
      await env.session.put("session", JSON.stringify(clients));
      saveSession();
      jsonResponse = JSON.stringify({ok: true, message: "Logged out"});
    }else if(request.headers.get("type") == "PEMANGGILAN") {
      let ciphertext = await request.json();
      const client = database.find(item => item.username === clients[ciphertext.session_id].username);
      if (client.type != "teacher") {
        return new Response(JSON.stringify({error: "invalid request"}), {
          headers: corsHeaders,
        });
      }
      let json = JSON.parse(await decrypt(clients[ciphertext.session_id].key, ciphertext.ciphertext));
      const result = database.find(item => item.username === json.nisn);
      sendBroadcast("*Info Penting*\nMurid bernama " + result.name + " mendapatkan pemanggilan orang tua dan diharapkan untuk segera datang ke sekolah." + "\nSisa poin: " + result.score + "\nDeskripsi: " + json.description)
      return new Response(JSON.stringify({ok: true, message: "pemanggilan"}), {headers: corsHeaders,});
    } else if (request.headers.get("type") == "POTONGPOIN") {
      let ciphertext = await request.json();
      const client = database.find(item => item.username === clients[ciphertext.session_id].username);
      if (client.type != "teacher") {
        return new Response(JSON.stringify({error: "invalid request"}), {
          headers: corsHeaders,
        });
      }
      let json = JSON.parse(await decrypt(clients[ciphertext.session_id].key, ciphertext.ciphertext));
      const result = database.find(item => item.username === json.nisn);
      //return new Response(JSON.stringify({database: database, data: json}), {headers: corsHeaders,});
      if (!result.history) {
        result.history = [];
      }

      let telegramResponse = await sendBroadcast("*Info Penting*\nMurid bernama " + result.name + " mendapatkan pemotongan poin karena melakukan pelanggaran.\nPoin sebelum dipotong : " + result.score + "\nSisa poin: " + (result.score - json.potongpoin) + "\nPemotongan poin: -" + json.potongpoin + "\nDeskripsi: " + json.description)

      if (result.score - json.potongpoin <= 0) {
        result.score = 0;
      } else {
        result.score -= json.potongpoin;
      }
      
      result.history.push({sisa: result.score, kurang: json.potongpoin, description: json.description, timestamp: new Date().getTime()});
      return new Response(JSON.stringify({ok: true, message: "potong poin"}), {headers: corsHeaders,});

    } else if (request.headers.get("type") == "TAMBAHPOIN") {
      let ciphertext = await request.json();
      const client = database.find(item => item.username === clients[ciphertext.session_id].username);
      if (client.type != "teacher") {
        return new Response(JSON.stringify({error: "invalid request"}), {
          headers: corsHeaders,
        });
      }
      let json = JSON.parse(await decrypt(clients[ciphertext.session_id].key, ciphertext.ciphertext));
      const result = database.find(item => item.username === json.nisn);
      //return new Response(JSON.stringify({database: database, data: json}), {headers: corsHeaders,});
      if (!result.history) {
        result.history = [];
      }

      // @ts-ignore
      let sisa_poin;
      // @ts-ignore
      if ((parseInt(result.score) + parseInt(json.potongpoin)) >= 100) {
        sisa_poin = 100;
      } else {
        // @ts-ignore
        sisa_poin = (parseInt(result.score) + parseInt(json.potongpoin));
      }
      let telegramResponse = await sendBroadcast("*Info Penting*\nMurid bernama " + result.name + " mendapatkan penambahan poin.\nPoin sebelum ditambahkan : " + result.score + "\nSisa poin: " + sisa_poin + "\nPenambahan poin: +" + json.potongpoin + "\nDeskripsi: " + json.description);
      
      // @ts-ignore
      if ((parseInt(result.score) + parseInt(json.potongpoin)) >= 100) {
        result.score = 100;
      } else {
        // @ts-ignore
        result.score = (parseInt(result.score) + parseInt(json.potongpoin));
      }
      
      result.history.push({sisa: result.score, tambah: json.potongpoin, description: json.description, timestamp: new Date().getTime()});
      return new Response(JSON.stringify({ok: true, message: "tambah poin", response: telegramResponse}), {headers: corsHeaders,});

    } else if (request.headers.get("type") == "AES") {
      let body = await request.json();
      if (!queue[body.session_id]) {
        return new Response(JSON.stringify({error: "invalid session id"}), {
          headers: corsHeaders,
        });
      }
      let AES_key = await decryptRSA2(queue[body.session_id].private_key, body.cipher);
      delete queue[body.session_id];
      clients[body.session_id] = {key: AES_key};
      jsonResponse = JSON.stringify({"response": "key received"});
    } else if (request.headers.get("type") == "CHECK_SESSION") {
      let body = await request.json();
      if (!clients[body.session_id]) {
        return new Response(JSON.stringify({ok: false, error: "invalid session id"}), {
          headers: corsHeaders,
        });
      } else {
        return new Response(JSON.stringify({ok: true}), {
          headers: corsHeaders,
        });
      }
    } else if (request.headers.get("type") == "LOGIN") {
      let body = await request.json();
      if (!clients[body.session_id]) {
        return new Response(JSON.stringify({error: "invalid session id"}), {
          headers: corsHeaders,
        });
      }

      if (!body.username || !body.password) {
        return new Response(JSON.stringify({error: "LOGIN_FAILED"}), {
          headers: corsHeaders,
        });
      }

      let decryptedUsername = await decrypt(clients[body.session_id].key, body.username);
      let decryptedPassword = await decrypt(clients[body.session_id].key, body.password);
      let data = await env.siswaDatabase
      const result = ;
      if (!result) {
        return new Response(JSON.stringify({ok: false, error: "LOGIN_FAILED"}), {
          headers: corsHeaders,
        });
      }
      if (result.username == decryptedUsername && result.password == decryptedPassword && result.type == body.type) {
        clients[body.session_id].username = decryptedUsername;
        clients[body.session_id].type = "student";
        await env.session.put("session", JSON.stringify(clients));
        jsonResponse = {ok: true, message: "Login"};
      } else {
        jsonResponse = {ok: false, message: "Username atau password salah."};
      }
      
    } else {
      jsonResponse = {ok: false, error: "invalid request"};
    }

    return new Response(JSON.stringify(jsonResponse), {
      headers: corsHeaders,
    });
  }
}

async function sendBroadcast(message) {
  let encoded = message.replaceAll("\n", "%0A");
  let response = await fetch("https://api.telegram.org/bot7946600072:AAGqa5KBTmK1nL-xdfefh9j-nTg_KuN6J2k/sendMessage?chat_id=@tatibsmkn7samarinda&text=" + encoded + "&parse_mode=markdown");
  let json = await response.json();
  return json;
}

// Sample database for the scoreboard
const database = [
  {
    "username": "100888064",
    "password": "100888064",
    "name": "Naufal",
    "type": "student",
    "class": "XI TJKT 1",
    "phonenumber": "081112345678",
    "telegram_id": 1234567890,
    "score": 100,
    "history": []
  },
  {
    "username": "100888065",
    "password": "100888065",
    "name": "Dafa",
    "type": "student",
    "class": "XI PPLG 1",
    "phonenumber": "081112345679",
    "telegram_id": 1123456789,
    "score": 64,
    "history": []
  },
  {
    "username": "bibitlele",
    "password": "bibitlele",
    "name": "Bibit Lele",
    "type": "teacher",
    "class": null,
    "phonenumber": "081112345679",
    "telegram_id": 1123456789,
    "score": 64
  },
  {
    "username": "guru",
    "password": "guru",
    "name": "Guru",
    "type": "teacher",
    "class": null,
    "phonenumber": "081112345679",
    "telegram_id": 1123456789,
    "score": 64
  }
];



// Function to get the sorted scoreboard
function getScoreBoard(session_id) {
  let scoreboard = {};
  const result = database.find(item => item.username === clients[session_id].username);
  scoreboard.ok = true;
  scoreboard.name = result.name;
  scoreboard.type = result.type;
  scoreboard.scoreboard = [];
  let copy = JSON.parse(JSON.stringify(database));
  copy.sort((a, b) => (a.score < b.score ? 1 : -1));
  let j = 0;
  for (var i = 0; i < copy.length; i++) {
    if(copy[i].type != "teacher") {
      if(result.type == "teacher") {
        scoreboard.scoreboard.push({name: copy[i].name, class: copy[i].class, score: copy[i].score, nisn: copy[i].username});
      } else {
        scoreboard.scoreboard.push({name: copy[i].name, class: copy[i].class, score: copy[i].score});
      }
      j++;
    }
  }
  return scoreboard;
}

function getData(session_id) {
  let history = {};
  const result = database.find(item => item.username === clients[session_id].username);
  history.ok = true;
  history.name = result.name;
  history.nisn = result.username;
  history.type = result.type;
  history.poin = result.score;
  history.telegram_id = result.telegram_id;
  if(result.history) {
    history.history = result.history;
  } else {
    history.history = [];
  }
  return history;
}
