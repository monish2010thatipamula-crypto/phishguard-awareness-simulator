const { app, BrowserWindow, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

process.on('uncaughtException', (err) => {
  console.error('Unhandled Exception:', err);
  dialog.showErrorBox('PhishGuard Application Error', err.stack || err.message);
});

const { createApp } = require('./src/app');

let mainWindow = null;
let server = null;

function createWindow(port) {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 850,
    minWidth: 900,
    minHeight: 600,
    title: 'PhishGuard - Awareness Simulator',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true
    }
  });

  mainWindow.loadURL(`http://127.0.0.1:${port}`);

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  try {
    const userDataPath = app.getPath('userData');
    const databasePath = path.join(userDataPath, 'phishguard.sqlite3');
    fs.mkdirSync(userDataPath, { recursive: true });

    const expressApp = createApp({ database: databasePath });
    const preferredPort = Number(process.env.PORT || 5000);

    server = expressApp.listen(preferredPort, '127.0.0.1', () => {
      const actualPort = server.address().port;
      console.log(`PhishGuard backend running on http://127.0.0.1:${actualPort}`);
      createWindow(actualPort);
    });

    server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        console.warn(`Port ${preferredPort} in use, picking random port...`);
        server = expressApp.listen(0, '127.0.0.1', () => {
          const actualPort = server.address().port;
          createWindow(actualPort);
        });
      } else {
        console.error('Server error:', err);
        dialog.showErrorBox('PhishGuard Server Error', err.message);
      }
    });
  } catch (err) {
    console.error('Startup error:', err);
    dialog.showErrorBox('PhishGuard Startup Error', err.stack || err.message);
  }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0 && server) {
      createWindow(server.address().port);
    }
  });
});

app.on('window-all-closed', () => {
  if (server) {
    server.close();
  }
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
