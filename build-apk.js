const axios = require('axios');
const fs = require('fs');
const path = require('path');

async function generateApk() {
  console.log('Requesting signed Android APK from CloudAPK builder...');
  
  const payload = {
    appVersion: "1.0.0",
    appVersionCode: 1,
    backgroundColor: "#0a0e17",
    display: "standalone",
    enableNotifications: false,
    enableSiteSettingsShortcut: true,
    fallbackType: "customtabs",
    features: {
      locationDelegation: { enabled: false },
      playBilling: { enabled: false }
    },
    host: "192.168.1.6:5000",
    iconUrl: "https://raw.githubusercontent.com/google/material-design-icons/master/png/action/security/materialicons/48dp/2x/baseline_security_black_48dp.png",
    maskableIconUrl: "https://raw.githubusercontent.com/google/material-design-icons/master/png/action/security/materialicons/48dp/2x/baseline_security_black_48dp.png",
    launcherName: "PhishGuard",
    name: "PhishGuard Awareness Simulator",
    shortName: "PhishGuard",
    navigationColor: "#0a0e17",
    navigationColorDark: "#0a0e17",
    navigationDividerColor: "#0a0e17",
    navigationDividerColorDark: "#0a0e17",
    orientation: "default",
    packageId: "com.phishguard.app",
    shortcuts: [],
    signing: {
      file: null,
      alias: "phishguard",
      fullName: "PhishGuard",
      organization: "PhishGuard",
      organizationalUnit: "Security",
      countryCode: "US",
      keyPassword: "phishguardpass",
      storePassword: "phishguardpass"
    },
    splashScreenFadeOutDuration: 300,
    startUrl: "/dashboard",
    themeColor: "#0a0e17",
    themeColorDark: "#0a0e17",
    webManifestUrl: "http://192.168.1.6:5000/manifest.json"
  };

  try {
    const response = await axios.post(
      'https://pwabuilder-cloudapk.azurewebsites.net/generateAppPackage',
      payload,
      { responseType: 'arraybuffer', timeout: 60000 }
    );

    const outZip = path.join('C:', 'Users', 'Monish', 'Downloads', 'PhishGuard-Android-APK.zip');
    fs.writeFileSync(outZip, response.data);
    console.log('APK package downloaded successfully to:', outZip);
  } catch (err) {
    console.error('Cloud APK generation failed:', err.response?.data?.toString() || err.message);
  }
}

generateApk();
