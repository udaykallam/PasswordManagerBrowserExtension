let cryptoKey = null;
const MASTER_HASH_KEY = 'masterKeyHash';
const SALT_KEY = 'saltKey';
let detectedCredentials = null;

async function generateAndSaveSalt() {
  let saltArray = new Uint8Array(16);
  window.crypto.getRandomValues(saltArray);
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
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    encoder.encode(masterPassword),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  const key = await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: 150000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  return key;
}

async function exportKeyHash(key) {
  const rawKey = await window.crypto.subtle.exportKey('raw', key);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', rawKey);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function isMasterPasswordSet() {
  const res = await chrome.storage.local.get(MASTER_HASH_KEY);
  return !!res[MASTER_HASH_KEY];
}

async function saveMasterPasswordHash(hash) {
  await chrome.storage.local.set({ [MASTER_HASH_KEY]: hash });
}

async function verifyMasterPassword(masterPassword) {
  const salt = await getSalt();
  const key = await deriveKeyFromPassword(masterPassword, salt);
  const hash = await exportKeyHash(key);
  const res = await chrome.storage.local.get(MASTER_HASH_KEY);
  if (res[MASTER_HASH_KEY] === hash) {
    cryptoKey = key;
    return true;
  }
  return false;
}

async function setupMasterPassword(masterPassword, confirmPassword) {
  if (masterPassword !== confirmPassword) throw new Error('Passwords do not match');
  if (masterPassword.length < 8) throw new Error('Password too short: minimum 8 characters');
  const salt = await generateAndSaveSalt();
  const key = await deriveKeyFromPassword(masterPassword, salt);
  const hash = await exportKeyHash(key);
  await saveMasterPasswordHash(hash);
  cryptoKey = key;
  return true;
}

async function encryptData(key, data) {
  const encoder = new TextEncoder();
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encoder.encode(data)
  );
  return { encryptedData: new Uint8Array(encrypted), iv: iv };
}

async function decryptData(key, encryptedData, iv) {
  const decrypted = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encryptedData
  );
  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}

function savePasswordEntry(site, username, password, key) {
  return encryptData(key, JSON.stringify({site, username, password}))
    .then(({encryptedData, iv}) => {
      const storageData = {};
      storageData[site] = { encrypted: Array.from(encryptedData), iv: Array.from(iv) };
      return chrome.storage.local.set(storageData);
    });
}

function getPasswordEntry(site, key) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get([site], async function(result) {
      if (!result[site]) {
        reject('No data found');
        return;
      }
      const { encrypted, iv } = result[site];
      const encryptedData = new Uint8Array(encrypted);
      const ivArray = new Uint8Array(iv);
      try {
        const decrypted = await decryptData(key, encryptedData, ivArray);
        resolve(JSON.parse(decrypted));
      } catch (e) {
        reject('Decryption failed');
      }
    });
  });
}

chrome.storage.local.get('detectedCredentials', (result) => {
  if (result.detectedCredentials) {
    detectedCredentials = result.detectedCredentials;
    document.getElementById('detectedDiv').style.display = 'block';
    document.getElementById('detectedMsg').textContent =
      `Login detected for ${detectedCredentials.site}. Click below to save.`;
    document.getElementById('site').value = detectedCredentials.site;
    document.getElementById('username').value = detectedCredentials.username;
    document.getElementById('password').value = detectedCredentials.password;
  } else {
    document.getElementById('detectedDiv').style.display = 'none';
  }
});

document.getElementById('saveDetectedBtn').addEventListener('click', async () => {
  if (!cryptoKey) {
    alert('Please unlock vault first');
    return;
  }
  if (!detectedCredentials) {
    alert('No detected credentials to save.');
    return;
  }
  try {
    await savePasswordEntry(
      detectedCredentials.site,
      detectedCredentials.username,
      detectedCredentials.password,
      cryptoKey
    );
    alert('Detected credentials saved securely!');
    detectedCredentials = null;
    chrome.storage.local.remove('detectedCredentials');
    document.getElementById('detectedDiv').style.display = 'none';
  } catch {
    alert('Failed to save detected credentials.');
  }
});

document.getElementById('setupBtn').addEventListener('click', async () => {
  const pw1 = document.getElementById('masterPasswordSetup').value;
  const pw2 = document.getElementById('masterPasswordConfirm').value;
  const message = document.getElementById('message');
  try {
    await setupMasterPassword(pw1, pw2);
    message.textContent = 'Master password set! Vault unlocked.';
    showVaultUI();
  } catch (e) {
    message.textContent = e.message;
  }
});

document.getElementById('unlockBtn').addEventListener('click', async () => {
  const pw = document.getElementById('masterPasswordUnlock').value;
  const message = document.getElementById('message');
  try {
    if (await verifyMasterPassword(pw)) {
      message.textContent = 'Vault unlocked.';
      showVaultUI();
    } else {
      message.textContent = 'Incorrect master password.';
    }
  } catch {
    message.textContent = 'An error occurred during unlock.';
  }
});

document.getElementById('lockBtn').addEventListener('click', () => {
  cryptoKey = null;
  document.getElementById('vault').style.display = 'none';
  document.getElementById('unlockDiv').style.display = 'block';
  document.getElementById('setupMasterDiv').style.display = 'none';
  document.getElementById('message').textContent = 'Vault locked.';
  document.getElementById('detectedDiv').style.display = 'none';
});

document.getElementById('saveBtn').addEventListener('click', async () => {
  if (!cryptoKey) {
    alert('Please unlock vault first');
    return;
  }
  const site = document.getElementById('site').value.trim();
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value.trim();
  if (!site || !username || !password) {
    alert('Please fill all fields');
    return;
  }
  try {
    await savePasswordEntry(site, username, password, cryptoKey);
    alert('Password saved securely');
  } catch {
    alert('Failed to save password');
  }
});

document.getElementById('retrieveBtn').addEventListener('click', async () => {
  if (!cryptoKey) {
    alert('Please unlock vault first');
    return;
  }
  const site = document.getElementById('retrieveSite').value.trim();
  if (!site) {
    alert('Please enter a site to retrieve');
    return;
  }
  try {
    const entry = await getPasswordEntry(site, cryptoKey);
    document.getElementById('result').textContent =
      `Site: ${entry.site}\nUsername: ${entry.username}\nPassword: ${entry.password}`;

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    chrome.tabs.sendMessage(tab.id, {
      action: 'fillCredentials',
      username: entry.username,
      password: entry.password
    }, (response) => {
      if (response && response.status === 'success') {
        alert('Credentials autofilled on the page');
      } else {
        alert('Failed to autofill: ' + (response ? response.reason : 'No response'));
      }
    });
  } catch (e) {
    document.getElementById('result').textContent = e;
  }
});

function generatePassword(length = 16) {
  const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?';
  let password = '';
  const cryptoObj = window.crypto || window.msCrypto;
  let randomValues = new Uint32Array(length);
  cryptoObj.getRandomValues(randomValues);
  for (let i = 0; i < length; i++) {
    password += charset[randomValues[i] % charset.length];
  }
  return password;
}

document.getElementById('generateBtn').addEventListener('click', () => {
  const password = generatePassword(16);
  document.getElementById('generatedPassword').value = password;
});

document.getElementById('exportBtn').addEventListener('click', async () => {
  const allData = await chrome.storage.local.get(null);
  const dataStr = JSON.stringify(allData);
  const blob = new Blob([dataStr], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'vault-backup.json';
  a.click();
  URL.revokeObjectURL(url);
  document.getElementById('backupMessage').textContent = 'Backup exported!';
});

document.getElementById('importBtn').addEventListener('click', () => {
  const fileInput = document.getElementById('importFile');
  if (!fileInput.files.length) {
    alert('Select a file first');
    return;
  }
  const file = fileInput.files[0];
  const reader = new FileReader();
  reader.onload = async (event) => {
    try {
      const importedData = JSON.parse(event.target.result);
      await chrome.storage.local.set(importedData);
      document.getElementById('backupMessage').textContent = 'Vault imported successfully!';
    } catch {
      alert('Failed to import vault. Wrong file format.');
    }
  };
  reader.readAsText(file);
});

function showVaultUI() {
  document.getElementById('vault').style.display = 'block';
  document.getElementById('setupMasterDiv').style.display = 'none';
  document.getElementById('unlockDiv').style.display = 'none';
  document.getElementById('message').textContent = '';
  document.getElementById('detectedDiv').style.display = detectedCredentials ? 'block' : 'none';
}

(async function init() {
  if (!(await isMasterPasswordSet())) {
    document.getElementById('setupMasterDiv').style.display = 'block';
    document.getElementById('unlockDiv').style.display = 'none';
  } else {
    document.getElementById('setupMasterDiv').style.display = 'none';
    document.getElementById('unlockDiv').style.display = 'block';
  }
  document.getElementById('vault').style.display = 'none';
  document.getElementById('message').textContent = '';
  document.getElementById('detectedDiv').style.display = 'none';
})();

window.addEventListener('unload', () => {
  cryptoKey = null;
});
