chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'fillCredentials') {
    const { username, password } = message;
    const usernameField = document.querySelector('input[type="text"], input[type="email"], input[name*="user"], input[name*="email"]');
    const passwordField = document.querySelector('input[type="password"]');
    if (usernameField && passwordField) {
      usernameField.value = username;
      passwordField.value = password;
      sendResponse({ status: 'success' });
    } else {
      sendResponse({ status: 'fail', reason: 'Fields not found' });
    }
  }
  return true;
});
