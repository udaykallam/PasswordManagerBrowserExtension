let pendingCredentials = null;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
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
  }
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
