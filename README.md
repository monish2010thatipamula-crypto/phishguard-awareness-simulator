# PhishGuard Awareness Simulator — JavaScript Edition

PhishGuard is a local Node.js + Express + built-in SQLite cybersecurity education project for authorized phishing-awareness exercises. It creates fictional campaigns, shows a clearly labeled training page, records anonymized click/submission events, calculates a transparent risk score, and produces HTML/CSV reports.

## Safety and privacy boundaries

- Fictional campaign content and participant codes only; no real recipient directory.
- No email sending, third-party service targeting, tracking pixels, URL fetching, or reputation lookups.
- Dummy username/password values are accepted only by the mock form and are discarded immediately.
- No IP address, browser fingerprint, GPS data, live location, or sender attribution is collected.
- The link analyzer is offline heuristic guidance, not a production threat verdict.

## Run on Windows

```powershell
cd phishguard-awareness-simulator-js
nvm use 22
npm install
$env:ADMIN_PASSWORD = "choose-a-private-demo-password"
npx playwright install chromium
npm start
```

Node 22.5+ is required because the project uses Node’s built-in `node:sqlite` module, so no native SQLite compiler toolchain is needed.

Open <http://127.0.0.1:5000>. The awareness lab is available without a username or password; it is intended for local or explicitly authorized use.

## Safe exercise flow

1. Create a fictional campaign for an explicitly authorized group.
2. Open the generated simulation link with a dummy participant code such as `student-01`.
3. Use dummy values such as `training-user` / `demo-only` in the mock form.
4. Review the anonymized report and discuss pause, verify, and report behaviors.
5. Print the report or download CSV for a project demonstration.

## Offline link analyzer

The Link analyzer parses a pasted URL without making a network request. It highlights HTTP instead of HTTPS, numeric IP hosts, user-info/`@` tricks, punycode, URL shorteners, known tracking/IP-logging domains, unusual ports, deep subdomains, lure words, and excessive URL length. It also extracts an embedded destination when a URL parameter exposes one. If a tracking service keeps the destination server-side, the analyzer reports that it is not recoverable offline. “No obvious indicators” is not proof of safety.

The analyzer also includes an optional isolated-browser simulation. It launches a fresh disposable Chromium context with no saved cookies, credentials, local storage, permissions, or downloads. It observes bounded redirects and page form metadata, blocks non-GET/HEAD requests, blocks private and local destinations, and never fills or submits forms. This can reveal JavaScript-generated redirects and credential-form indicators that static parsing misses. It cannot guarantee detection of every concealment technique, especially content requiring authentication, CAPTCHAs, malicious downloads, browser exploits, or server-side behavior that changes by user, region, or time.

## Project structure

```text
phishguard-awareness-simulator-js/
├── server.js
├── package.json
├── src/app.js
├── src/db.js
├── src/url-analyzer.js
├── views/                 # EJS dashboard and simulation pages
├── public/style.css       # responsive interface
├── test/                  # Node test runner tests
├── ARCHITECTURE.md
└── PROJECT_REPORT.md
```

## Tests

```powershell
npm test
```

## Production hardening

This is a college/awareness project, not a production service. Before broader deployment: use a long secret, disable debug behavior, put the app behind HTTPS, add an approved consent/retention policy, use a managed database, add role-based access, and have the organization’s privacy/legal owner approve the exercise.
