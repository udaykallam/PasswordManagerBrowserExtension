document.addEventListener('submit', function(e) {
  const form = e.target;
  const passwordField = form.querySelector('input[type="password"]');
  if (passwordField) {
    const usernameField = form.querySelector('input[type="text"], input[type="email"], input[name*="user"], input[name*="email"]');
    const username = usernameField ? usernameField.value : '';
    const password = passwordField.value;
    const site = window.location.hostname;

    chrome.runtime.sendMessage({
      action: 'credentialsDetected',
      site: site,
      username: username,
      password: password
    });
  }
}, true);

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
