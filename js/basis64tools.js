
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
  const keyBuffer = str2ab(rawKey); // Assuming it's in Base64 format

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

function jsonParse(jsonString) {
  // Remove whitespace for a slightly faster parse
  jsonString = jsonString.replace(/\s+/g, '');

  // Handle null
  if (jsonString === 'null') return null;

  // Handle booleans
  if (jsonString === 'true') return true;
  if (jsonString === 'false') return false;

  // Handle numbers
  if (/^-?\d+(\.\d+)?([eE][+-]?\d+)?$/.test(jsonString)) {
      return Number(jsonString);
  }

  // Handle strings
  if (/^".*"$/.test(jsonString)) {
      return jsonString.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  }

  // Handle arrays
  if (jsonString[0] === '[' && jsonString[jsonString.length - 1] === ']') {
      const arr = [];
      jsonString.slice(1, -1).split(',').forEach(item => {
          arr.push(jsonParse(item));
      });
      return arr;
  }

  // Handle objects
  if (jsonString[0] === '{' && jsonString[jsonString.length - 1] === '}') {
      const obj = {};
      const properties = jsonString.slice(1, -1).split(',');

      properties.forEach(prop => {
          const [key, value] = prop.split(':');
          // Remove quotes from key
          const cleanKey = key.replace(/^"|"$/g, '');
          obj[cleanKey] = jsonParse(value);
      });

      return obj;
  }

  throw new SyntaxError('Invalid JSON');
}

let serverKey = "stmtawuran64";
let email = {};
async function handleRequest(request, env) {
  if (request.method === "OPTIONS") {
    return handleOptions(request);
  } else if (request.method === "GET") {
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    // @ts-ignore
    
    // Generate RSA Key Pair
    // @ts-ignore
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
      last_id: clients
    }), {
      headers: corsHeaders,
    });
  } else {
    // Handle other request methods
    let jsonResponse;
    let clients_KV = await env.session.get("clients");
    let emails_KV = await env.session.get("emails");

    clients = JSON.parse(clients_KV);
    email = JSON.parse(emails_KV);

    //let requestBody = await request.json();

    /*
    if(email[requestBody.account.email].expired < new Date().getTime()) {
      delete email[requestBody.account.email];
      delete clients[requestBody.session_id];
      await env.session.put("clients", clients);
      await env.session.put("emails", email);
      return new Response(JSON.stringify({ok: false, error: "SESSION_EXPIRED"}), {
        headers: corsHeaders,
      });
    }
    */

    /*
    return new Response(JSON.stringify({error: "INVALID_SESSION_ID"}), {
      headers: corsHeaders,
    });
    */
    
    
    if (request.headers.get("type") == "GETDATA") {
      let body = await request.json();
      if (!queue[body.session_id]) {
        return new Response(JSON.stringify({ok: false, error: "INVALID_SESSION_ID"}), {
          headers: corsHeaders,
        });
      }
      if (clients[body.session_id].expired > new Date().getTime() || email[body.account.email].expired < new Date().getTime()) {
        delete email[body.account.email];
        delete clients[body.session_id];
        await env.session.put("clients", clients);
        await env.session.put("emails", email);
        return new Response(JSON.stringify({ok:false, error: "SESSION_EXPIRED"}), {
          headers: corsHeaders,
        });
      }

      return new Response(JSON.stringify({ok: true, account: clients[body.session_id].account}), {
        headers: corsHeaders,
      });
    } else if (request.headers.get("type") == "INFO") {
      let body = await request.json();
      if (!queue[body.session_id]) {
        return new Response(JSON.stringify({error: "invalid session id"}), {
          headers: corsHeaders,
        });
      }

      return new Response(JSON.stringify({error: "invalid session id"}), {
        headers: corsHeaders,
      });
    } else if (request.headers.get("type") == "ADMINLOGIN") {
      let body = await request.json();
      if (!clients[body.session_id]) {
        return new Response(JSON.stringify({ok: false, error: "INVALID_SESSION_ID"}), {
          headers: corsHeaders,
        });
      }

      

      let username = await decrypt(clients[body.session_id].key, body.username);
      let password = await decrypt(clients[body.session_id].key, body.password);

      if (username == "admin" && password == "stmtawuran64") {
        clients[body.session_id].admin = true;
        await env.session.put("clients", JSON.stringify(clients));
        return new Response(JSON.stringify({ok: true}), {
          headers: corsHeaders,
        });
      } else {
        clients[body.session_id].admin = false;
        return new Response(JSON.stringify({ok: false, error: "WRONG_PASSWORD"}), {
          headers: corsHeaders,
        });
      }

      
    } else if (request.headers.get("type") == "AES") {
      let body = await request.json();
      if (!queue[body.session_id]) {
        return new Response(JSON.stringify({error: "invalid session id"}), {
          headers: corsHeaders,
        });
      }
      let AES_key = await decryptRSA2(queue[body.session_id].private_key, body.cipher);
      delete queue[body.session_id];
      clients[body.session_id] = {key: AES_key, expired: new Date().getTime() + 24*3600*1000};
      await env.session.put("clients", JSON.stringify(clients));
      jsonResponse = JSON.stringify({response: "AES key received", list: clients});
    } else if (request.headers.get("type") == "CHECK_SESSION") {
      let body = await request.json();
      if (!clients[body.session_id]) {
        return new Response(JSON.stringify({ok: false, error: "invalid session id"}), {
          headers: corsHeaders,
        });
      }
      if (clients[body.session_id].expired < new Date().getTime()) {
        if(clients[body.session_id].account) {
          delete email[body.account.email];
        }
        if(clients[body.session_id]) {
          delete clients[body.session_id];
        }
        await env.session.put("clients", JSON.stringify(clients));
        await env.session.put("emails", JSON.stringify(email));
        return new Response(JSON.stringify({ok:false, error: "SESSION_EXPIRED"}), {
          headers: corsHeaders,
        });
      }

      //clients[body.session_id].account = JSON.parse(await env.database.get(body.account.email));
      let pages = JSON.parse(await env.database.get("premium_pages"));
      return new Response(JSON.stringify({ok: true, account: (clients[body.session_id].account)?await encrypt(clients[body.session_id].key, await env.database.get(clients[body.session_id].account.email)):await encrypt(clients[body.session_id].key, "{}"), pages: pages, admin: (clients[body.session_id].admin)?true:false}), {
        headers: corsHeaders,
      });
    } else if (request.headers.get("type") == "LOGIN") {
      let body = await request.json();
      if (!clients[body.session_id]) {
        return new Response(JSON.stringify({ok: false, error: "INVALID_SESSION_ID"}), {
          headers: corsHeaders,
        });
      }

      if (!body.email || !body.password || !body.user_agent) {
        return new Response(JSON.stringify({ok: false, error: "LOGIN_FAILED"}), {
          headers: corsHeaders,
        });
      }

    
      let decryptedEmail = await decrypt(clients[body.session_id].key, body.email);
      let decryptedPassword = await decrypt(clients[body.session_id].key, body.password);
      let decryptedUserAgent = await decrypt(clients[body.session_id].key, body.user_agent);


      let account = await env.database.get(decryptedEmail);
      if (account) {
        let json = JSON.parse(account);
        let password;
        try {
          let buffer = new Array(32).fill(0x00);
          const newPasswordBytes = Array.from(decryptedPassword).map(char => char.charCodeAt(0));
          for (let i = 0; i < newPasswordBytes.length; i++) {
            buffer[i] = newPasswordBytes[i];
          }
          password = await decrypt(ab2str(buffer), json.password);
        } catch (error) {
          return new Response(JSON.stringify({ok: false, account: "WRONG_PASSWORD"}), {
            headers: corsHeaders,
          });
        }
          if(!email[decryptedEmail] || email[decryptedEmail].expired < new Date().getTime()) {
            email[decryptedEmail] = {};
            email[decryptedEmail].user_agent = decryptedUserAgent;
            email[decryptedEmail].expired = new Date().getTime() + 24 * 3600 * 1000;
            clients[body.session_id].expired = new Date().getTime() + 24 * 3600 * 1000;
            clients[body.session_id].account = json;
            await env.session.put("emails", JSON.stringify(email));
            await env.session.put("clients", JSON.stringify(clients));
          } else if (decryptedUserAgent != email[decryptedEmail].user_agent) {
            return new Response(JSON.stringify({ok: false, error: "ACCOUNT_USED"}), {
              headers: corsHeaders,
            });
          } else if (email[decryptedEmail].user_agent == decryptedUserAgent) {
            clients[body.session_id].account = json;
            await env.session.put("emails", JSON.stringify(email));
            await env.session.put("clients", JSON.stringify(clients));
          }
          return new Response(JSON.stringify({ok: true}), {
            headers: corsHeaders,
          });
        
      } else {
        return new Response(JSON.stringify({ok: false, account: "ACCOUNT_NOT_FOUND"}), {
          headers: corsHeaders,
        });
      }
      
    } else if (request.headers.get("type") == "LIST") {
      let body = await request.json();
      if (!clients[body.session_id]) {
        return new Response(JSON.stringify({ok: false, error: "INVALID_SESSION_ID"}), {
          headers: corsHeaders,
        });
      }

      if (clients[body.session_id].admin) {
        let list = await env.database.list();
        delete list.keys["last_id"];
        delete list.keys["premium_pages"];
        return new Response(JSON.stringify({ok: true, list: await encrypt(clients[body.session_id].key, JSON.stringify(list.keys))}), {
          headers: corsHeaders,
        });
      }

      return new Response(JSON.stringify({ok: false, error: "ACCESS_DENIED"}), {
        headers: corsHeaders,
      });
      
    } else if (request.headers.get("type") == "GETUSER") {
      let body = await request.json();
      if (!clients[body.session_id]) {
        return new Response(JSON.stringify({ok: false, error: "INVALID_SESSION_ID"}), {
          headers: corsHeaders,
        });
      }

      let email = await decrypt(clients[body.session_id].key, body.email);

      if (!email) {
        return new Response(JSON.stringify({ok: false, error: "INVALID_EMAIL"}), {
          headers: corsHeaders,
        });
      }

      if (clients[body.session_id].admin) {
        let data = await env.database.get(email);
        return new Response(JSON.stringify({ok: true, account: await encrypt(clients[body.session_id].key, data)}), {
          headers: corsHeaders,
        });
      }

      return new Response(JSON.stringify({ok: false, error: "ACCESS_DENIED"}), {
        headers: corsHeaders,
      });
      
    } else if (request.headers.get("type") == "ACTIVATE") {
      let body = await request.json();
      if (!clients[body.session_id]) {
        return new Response(JSON.stringify({ok: false, error: "INVALID_SESSION_ID"}), {
          headers: corsHeaders,
        });
      }

      let email = await decrypt(clients[body.session_id].key, body.email);

      if (!email) {
        return new Response(JSON.stringify({ok: false, error: "INVALID_EMAIL"}), {
          headers: corsHeaders,
        });
      }

      if (clients[body.session_id].admin) {
        let data = JSON.parse(await env.database.get(email));
        data.activation_level = body.activation_level;
        data.activation_expired = body.timestamp;
        await env.database.put(email, JSON.stringify(data));
        return new Response(JSON.stringify({ok: true}), {
          headers: corsHeaders,
        });
      }

      return new Response(JSON.stringify({ok: false, error: "ACCESS_DENIED"}), {
        headers: corsHeaders,
      });
      
    } else if (request.headers.get("type") == "REGISTER") {
      let body = await request.json();
      if (!clients[body.session_id]) {
        return new Response(JSON.stringify({error: "invalid session id"}), {
          headers: corsHeaders,
        });
      }

      if (!body.name || !body.photo || !body.password || !body.email) {
        return new Response(JSON.stringify({error: "INVALID_REGISTER_REQUEST"}), {
          headers: corsHeaders,
        });
      }

      let decryptedName = await decrypt(clients[body.session_id].key, body.name);
      let decryptedPhoto = await decrypt(clients[body.session_id].key, body.photo);
      let decryptedEmail = await decrypt(clients[body.session_id].key, body.email);
      let decryptedPassword = await decrypt(clients[body.session_id].key, body.password);

      if (!await env.database.get(decryptedEmail).email) {
        let buffer = new Array(32).fill(0x00);
        const newPasswordBytes = Array.from(decryptedPassword).map(char => char.charCodeAt(0));
        for (let i = 0; i < newPasswordBytes.length; i++) {
          buffer[i] = newPasswordBytes[i];
        }
        await env.database.put(decryptedEmail, JSON.stringify({email: decryptedEmail, password: await encrypt(ab2str(buffer), ab2str(buffer)), name: decryptedName, photo: decryptedPhoto, activation_level: 1, activation_expired: new Date().getTime() + 24*3600*1000}));
        return new Response(JSON.stringify({ok: true, status: "SUCCESS"}), {
          headers: corsHeaders,
        });
      } else {
        return new Response(JSON.stringify({ok: false, error: "EMAIL_ALREADY_REGISTERED"}), {
          headers: corsHeaders,
        });
      }
      
      
    } else if (request.headers.get("type") == "LOGOUT") {
      let body = await request.json();
      if (!clients[body.session_id]) {
        return new Response(JSON.stringify({error: "invalid session id"}), {
          headers: corsHeaders,
        });
      }

      delete email[clients[body.session_id].account.email];
      clients[body.session_id].account = {};
      await env.session.put("clients", JSON.stringify(clients));
      await env.session.put("emails", JSON.stringify(email));
      return new Response(JSON.stringify({ok: true}), {
        headers: corsHeaders,
      });
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
