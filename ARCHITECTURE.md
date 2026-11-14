# PhishGuard JavaScript Architecture

```text
Admin browser
    │ Express session + CSRF token
    ▼
Express routes ───────────► better-sqlite3
    │                         ├── users
    │                         ├── campaigns
    │                         └── events
    ├── EJS dashboard/campaign builder
    ├── labeled simulation page
    ├── anonymized HTML/CSV report
    └── offline URL analyzer
```

## Components

- `src/app.js`: Express app factory, auth, routes, and safe event handling.
- `src/db.js`: SQLite schema, password hashing with Node’s built-in `crypto.scryptSync`, metrics, and participant scoring.
- `src/url-analyzer.js`: URL parsing and explainable static heuristics; it never fetches a URL.
- `views/`: EJS templates for the dashboard and simulation.

## Data model

| Table | Stores | Intentionally absent |
|---|---|---|
| `users` | admin username and password hash | plaintext password |
| `campaigns` | fictional exercise content and public token | real recipient email or external service |
| `events` | participant code, event type, score, timestamp | raw form values, IP, GPS, browser fingerprint |

## Scoring

Click = 40 points. Dummy submission = 60 points. Low is 0–29, Medium is 30–69, High is 70–100. This is an exercise outcome, not a judgment of a person.

## Deliberate non-features

The project does not trace a sender, harvest IP addresses, infer live location, identify a person from a file/link, send phishing emails, or target real third-party login pages. Those features are outside a safe awareness simulator and require separate organizational privacy/legal authority and controls.
