require('dotenv').config();

const { createApp } = require('./src/app');

const app = createApp();
const host = process.env.HOST || '0.0.0.0';
const port = Number(process.env.PORT || 5000);

app.listen(port, host, () => {
  console.log(`PhishGuard is running at http://localhost:${port}`);
  console.log(`To access on your phone (same Wi-Fi), open: http://192.168.1.6:${port}`);
});
