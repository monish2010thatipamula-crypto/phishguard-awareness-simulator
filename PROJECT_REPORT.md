# PhishGuard: JavaScript Phishing-Awareness Simulation Tool

## Abstract

PhishGuard is a Node.js web application for authorized cybersecurity awareness training. It allows a trainer to build fictional campaigns, demonstrate phishing warning signs safely, track anonymized exercise outcomes, and export a report without collecting real credentials or personal location data.

## Objectives

1. Provide a professional admin dashboard with authentication.
2. Create controlled fictional campaigns.
3. Show an unmistakably labeled mock landing page.
4. Track clicks and dummy submissions by participant code.
5. Calculate a transparent risk score and export results.
6. Analyze suspicious URL signals offline.
7. Preserve participant privacy by default.

## Technology

- Node.js and Express for the web server.
- EJS for server-rendered pages.
- better-sqlite3 for a zero-configuration local SQLite database.
- Node `crypto.scryptSync` for password hashing.
- Node’s built-in test runner and Supertest for automated verification.

## Ethics and privacy

An NGO or college use case still needs informed authorization and an approved data policy. PhishGuard intentionally excludes covert sender tracing, IP harvesting, GPS/live-location collection, and identity inference. For any real incident, use the organization’s approved security and legal process instead of extending this educational tool to surveil people.

## Evaluation

Tests cover login protection, campaign creation, safe simulation tracking, raw-password non-persistence, CSV reporting, and offline link classification. The analyzer is a teaching aid and can produce false positives or false negatives; it is not a replacement for a security gateway or professional investigation.
