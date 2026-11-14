// Register Service Worker
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker
      .register('/sw.js')
      .then((reg) => {
        console.log('[PWA] Service Worker registered with scope:', reg.scope);
      })
      .catch((err) => {
        console.warn('[PWA] Service Worker registration failed:', err);
      });
  });
}

// Handle PWA Installation Prompt
let deferredPrompt = null;
const installBtn = document.getElementById('pwa-install-btn');

window.addEventListener('beforeinstallprompt', (e) => {
  // Prevent mini-infobar on mobile
  e.preventDefault();
  deferredPrompt = e;

  // Show our custom install button
  if (installBtn) {
    installBtn.style.display = 'inline-flex';
  }
});

if (installBtn) {
  installBtn.addEventListener('click', async () => {
    if (!deferredPrompt) {
      alert('To install PhishGuard as an app:\n\n1. In Chrome/Edge, click the "Install" icon in your browser address bar (top-right)\n2. Or click the 3 dots menu -> "Install PhishGuard"');
      return;
    }

    deferredPrompt.prompt();
    const { outcome } = await deferredPrompt.userChoice;
    console.log(`[PWA] User choice: ${outcome}`);
    deferredPrompt = null;
    installBtn.style.display = 'none';
  });
}

window.addEventListener('appinstalled', () => {
  console.log('[PWA] PhishGuard was installed successfully!');
  if (installBtn) {
    installBtn.style.display = 'none';
  }
});
