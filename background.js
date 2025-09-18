const MASTER_HASH_KEY = 'masterKeyHash';
const SALT_KEY = 'saltKey';
let cryptoKey = null;
let pendingCredentials = null;

async function generateAndSaveSalt() {
  const saltArray = new Uint8Array(16);
  crypto.getRandomValues(saltArray);
  const saltString = Array.from(saltArray).map(b => b.toString(16).padStart(2, '0')).join('');
  await chrome.storage.local.set({ [SALT_KEY]: saltString });
  return saltString;
}

async function getSalt() {
  const res = await chrome.storage.local.get(SALT_KEY);
  if (res[SALT_KEY]) return res[SALT_KEY];
  return await generateAndSaveSalt();
}

async function deriveKeyFromPassword(masterPassword, saltHex) {
  const encoder = new TextEncoder();
  const saltBytes = new Uint8Array(saltHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(masterPassword),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: 150000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  return key;
}

async function exportKeyHash(key) {
  const rawKey = await crypto.subtle.exportKey('raw', key);
  const hashBuffer = await crypto.subtle.digest('SHA-256', rawKey);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function encryptData(key, data) {
  const encoder = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(data));
  return { encryptedData: new Uint8Array(encrypted), iv };
}

async function decryptData(key, encryptedData, iv) {
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encryptedData);
  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    if (message.action === 'credentialsDetected') {
      pendingCredentials = message;
      chrome.notifications.create('password-notification', {
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: 'Save password?',
        message: `Login detected for ${message.site}.\nUsername: ${message.username || '(blank)'}\nClick to save.`,
        buttons: [{ title: 'Save' }, { title: 'Dismiss' }],
        priority: 2
      });
      sendResponse({ status: 'notified' });
    } else if (message.action === 'setupMasterPassword') {
      const { masterPassword, confirmPassword } = message;
      if (masterPassword !== confirmPassword) return sendResponse({ status: 'error', reason: 'Passwords do not match' });
      if (masterPassword.length < 8) return sendResponse({ status: 'error', reason: 'Password must be at least 8 chars' });
      const salt = await generateAndSaveSalt();
      const key = await deriveKeyFromPassword(masterPassword, salt);
      const hash = await exportKeyHash(key);
      await chrome.storage.local.set({ [MASTER_HASH_KEY]: hash });
      cryptoKey = key;
      return sendResponse({ status: 'success' });
    } else if (message.action === 'verifyMasterPassword') {
      const { masterPassword } = message;
      const salt = await getSalt();
      const key = await deriveKeyFromPassword(masterPassword, salt);
      const hash = await exportKeyHash(key);
      const res = await chrome.storage.local.get(MASTER_HASH_KEY);
      if (res[MASTER_HASH_KEY] === hash) {
        cryptoKey = key;
        return sendResponse({ status: 'success' });
      } else {
        return sendResponse({ status: 'error', reason: 'Incorrect master password' });
      }
    } else if (message.action === 'savePasswordEntry') {
      if (!cryptoKey) return sendResponse({ status: 'locked' });
      const { site, username, password } = message;
      const serialized = JSON.stringify({ site, username, password });
      const { encryptedData, iv } = await encryptData(cryptoKey, serialized);
      const storageData = {};
      storageData[site] = { encrypted: Array.from(encryptedData), iv: Array.from(iv) };
      await chrome.storage.local.set(storageData);
      return sendResponse({ status: 'success' });
    } else if (message.action === 'getPasswordEntry' || message.action === 'requestCredentials') {
      if (!cryptoKey) return sendResponse({ status: 'locked' });
      const site = message.site;
      const res = await chrome.storage.local.get(site);
      if (!res || !res[site]) return sendResponse({ status: 'notfound' });
      const { encrypted, iv } = res[site];
      try {
        const decrypted = await decryptData(cryptoKey, new Uint8Array(encrypted), new Uint8Array(iv));
        const parsed = JSON.parse(decrypted);
        return sendResponse({ status: 'success', entry: parsed });
      } catch (e) {
        return sendResponse({ status: 'error', reason: 'decryption_failed' });
      }
    } else if (message.action === 'lockVault') {
      cryptoKey = null;
      return sendResponse({ status: 'locked' });
    } else {
      return sendResponse({ status: 'unknown_action' });
    }
  })();
  return true; 
});

chrome.notifications.onButtonClicked.addListener((notifId, btnIdx) => {
  if (notifId === 'password-notification' && pendingCredentials) {
    if (btnIdx === 0) {
      chrome.storage.local.set({ detectedCredentials: pendingCredentials }, () => {
        chrome.notifications.clear('password-notification');
        pendingCredentials = null;
      });
    } else {
      chrome.notifications.clear('password-notification');
      pendingCredentials = null;
    }
  }
});

chrome.notifications.onClosed.addListener((notifId, byUser) => {
  if (notifId === 'password-notification') {
    pendingCredentials = null;
  }
});
