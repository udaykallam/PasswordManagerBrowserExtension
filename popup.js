let detectedCredentials = null;

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

function sendToBackground(message) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(message, (resp) => {
      resolve(resp);
    });
  });
}

document.getElementById('setupBtn').addEventListener('click', async () => {
  const pw1 = document.getElementById('masterPasswordSetup').value;
  const pw2 = document.getElementById('masterPasswordConfirm').value;
  const message = document.getElementById('message');
  try {
    const resp = await sendToBackground({ action: 'setupMasterPassword', masterPassword: pw1, confirmPassword: pw2 });
    if (resp && resp.status === 'success') {
      message.textContent = 'Master password set! Vault unlocked.';
      showVaultUI();
    } else {
      message.textContent = resp.reason || 'Failed to set master password';
    }
  } catch (e) {
    message.textContent = 'Error setting master password';
  }
});

document.getElementById('unlockBtn').addEventListener('click', async () => {
  const pw = document.getElementById('masterPasswordUnlock').value;
  const message = document.getElementById('message');
  try {
    const resp = await sendToBackground({ action: 'verifyMasterPassword', masterPassword: pw });
    if (resp && resp.status === 'success') {
      message.textContent = 'Vault unlocked.';
      showVaultUI();
    } else {
      message.textContent = resp.reason || 'Incorrect master password.';
    }
  } catch {
    message.textContent = 'An error occurred during unlock.';
  }
});

document.getElementById('lockBtn').addEventListener('click', async () => {
  await sendToBackground({ action: 'lockVault' });
  document.getElementById('vault').style.display = 'none';
  document.getElementById('unlockDiv').style.display = 'block';
  document.getElementById('setupMasterDiv').style.display = 'none';
  document.getElementById('message').textContent = 'Vault locked.';
  document.getElementById('detectedDiv').style.display = 'none';
});

document.getElementById('saveBtn').addEventListener('click', async () => {
  const site = document.getElementById('site').value.trim();
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value.trim();
  if (!site || !username || !password) {
    alert('Please fill all fields');
    return;
  }
  const resp = await sendToBackground({ action: 'savePasswordEntry', site, username, password });
  if (resp && resp.status === 'success') {
    alert('Password saved securely');
  } else if (resp && resp.status === 'locked') {
    alert('Vault locked. Unlock first.');
  } else {
    alert('Failed to save password');
  }
});

document.getElementById('saveDetectedBtn').addEventListener('click', async () => {
  if (!detectedCredentials) { alert('No detected credentials.'); return; }
  const resp = await sendToBackground({
    action: 'savePasswordEntry',
    site: detectedCredentials.site,
    username: detectedCredentials.username,
    password: detectedCredentials.password
  });
  if (resp && resp.status === 'success') {
    alert('Detected credentials saved securely!');
    detectedCredentials = null;
    chrome.storage.local.remove('detectedCredentials');
    document.getElementById('detectedDiv').style.display = 'none';
  } else if (resp && resp.status === 'locked') {
    alert('Please unlock vault first');
  } else {
    alert('Failed to save detected credentials.');
  }
});

document.getElementById('retrieveBtn').addEventListener('click', async () => {
  const site = document.getElementById('retrieveSite').value.trim();
  if (!site) { alert('Please enter a site to retrieve'); return; }
  const resp = await sendToBackground({ action: 'getPasswordEntry', site });
  if (resp && resp.status === 'success') {
    const entry = resp.entry;
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
  } else if (resp && resp.status === 'locked') {
    alert('Vault locked. Unlock first.');
  } else if (resp && resp.status === 'notfound') {
    alert('No credentials found for that site.');
  } else {
    alert('Failed to retrieve entry.');
  }
});

function generatePassword(length = 16) {
  const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?';
  let password = '';
  let randomValues = new Uint32Array(length);
  crypto.getRandomValues(randomValues);
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
  const res = await chrome.storage.local.get('masterKeyHash');
  if (!res.masterKeyHash) {
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
