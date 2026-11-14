const fs = require('fs');
const path = require('path');

const svgPath = path.join(__dirname, 'public', 'icons', 'icon.svg');
const svg = fs.readFileSync(svgPath, 'utf8');

const htmlContent = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body { margin: 0; padding: 0; background: transparent; display: flex; align-items: center; justify-content: center; }
  svg { width: 100vw; height: 100vh; }
</style>
</head>
<body>
${svg}
</body>
</html>`;

fs.writeFileSync(path.join(__dirname, 'public', 'icons', 'icon.html'), htmlContent);
console.log('Icon HTML generated');
