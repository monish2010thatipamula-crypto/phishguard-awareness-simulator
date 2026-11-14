const fs = require('node:fs');
const path = require('node:path');

class SafePhishingAnalyzer {
  constructor() {
    this.suspiciousDomains = new Set([
      'grabify.link', 'iplogger.org', 'iplogger.com', '2no.co', 'yip.su',
      'bit.ly', 'tinyurl.com', 't.co', 'ow.ly',
      'example-phish.com', 'malicious-site.net', 'fake-login.org'
    ]);
    this.redirectParameters = new Set([
      'url', 'u', 'uri', 'link', 'target', 'dest', 'destination',
      'redirect', 'redirect_url', 'redirect_uri', 'next', 'continue',
      'return', 'return_to', 'ref'
    ]);
    this.secretParameters = /^(password|pass|token|secret|api[_-]?key|auth|authorization|session|cookie|email)$/i;
    this.suspiciousWords = /login|signin|verify|urgent|password|account|payment|wallet|unlock|confirm/i;
  }

  decodeRepeated(value) {
    let decoded = String(value);
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        const next = decodeURIComponent(decoded);
        if (next === decoded) break;
        decoded = next;
      } catch {
        break;
      }
    }
    return decoded;
  }

  redactParameter(key, value) {
    if (this.secretParameters.test(key)) return '[REDACTED]';
    const decoded = this.decodeRepeated(value);
    return decoded.replace(/[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/g, '[REDACTED_EMAIL]');
  }

  safeUrlString(parsed) {
    const copy = new URL(parsed.toString());
    for (const key of [...copy.searchParams.keys()]) {
      const values = copy.searchParams.getAll(key).map((value) => this.redactParameter(key, value));
      copy.searchParams.delete(key);
      values.forEach((value) => copy.searchParams.append(key, value));
    }
    return copy.toString();
  }

  extractUnderlyingUrls(parsed) {
    const found = new Map();
    const add = (source, rawValue) => {
      const decoded = this.decodeRepeated(rawValue);
      const matches = decoded.match(/https?:\/\/[^\s"'<>]+/gi) || [];
      for (const candidate of matches) {
        try {
          const url = new URL(candidate);
          if (!found.has(url.toString())) found.set(url.toString(), { source, url: url.toString() });
        } catch {
          // Ignore malformed embedded values.
        }
      }
    };
    for (const [key, value] of parsed.searchParams.entries()) {
      if (this.redirectParameters.has(key.toLowerCase()) || /https?:\/\//i.test(this.decodeRepeated(value))) {
        add(key, value);
      }
    }
    return [...found.values()];
  }

  analyzeLink(input) {
    const raw = String(input || '').trim();
    if (!raw) return { error: 'A URL is required.' };

    let parsed;
    try {
      parsed = new URL(raw);
    } catch {
      return { error: 'Invalid URL format.' };
    }
    if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) {
      return { error: 'Only HTTP and HTTPS URLs are supported.' };
    }

    const domain = parsed.hostname.toLowerCase();
    const signals = [];
    if (parsed.protocol !== 'https:') signals.push('The link does not use HTTPS.');
    if (parsed.username || parsed.password) signals.push('The URL contains user-info before the host, which can hide the destination.');
    if (/^[0-9.]+$/.test(domain)) signals.push('The destination uses a numeric IP address.');
    if (domain.startsWith('xn--') || domain.includes('.xn--')) signals.push('The domain uses punycode.');
    if (this.suspiciousDomains.has(domain)) signals.push('The domain is associated with tracking, shortening, or known training examples.');
    if (parsed.port && !['80', '443'].includes(parsed.port)) signals.push('The link uses a non-standard port.');
    if (domain.split('.').length > 4) signals.push('The domain has an unusually deep subdomain structure.');
    if (this.suspiciousWords.test(raw)) signals.push('The URL contains language commonly used in credential or payment lures.');

    const underlyingUrls = this.extractUnderlyingUrls(parsed);
    if (underlyingUrls.length) signals.push('The URL exposes an embedded destination in its parameters.');

    const trackingDomain = this.suspiciousDomains.has(domain);
    const resolutionNote = underlyingUrls.length
      ? 'A possible embedded destination was found in the URL text. Verify it through a trusted channel before opening it.'
      : trackingDomain
        ? 'The final destination may be stored server-side. This offline tool will not contact the tracking service to resolve it.'
        : 'No embedded destination was exposed in the URL text.';

    return {
      url: this.safeUrlString(parsed),
      domain,
      classification: signals.length ? 'Likely suspicious' : 'No obvious indicators',
      severity: signals.length ? 'warning' : 'success',
      signals,
      underlyingUrls,
      resolutionNote,
      analyzedAt: new Date().toISOString(),
      privacy: 'Offline analysis only. No URL requests, IP collection, device collection, or location lookup.'
    };
  }

  saveReport(report, filename = 'phishing-analysis.json') {
    const safeName = String(filename).replace(/[^a-zA-Z0-9_.-]/g, '') || 'phishing-analysis.json';
    const outputDir = path.resolve('outputs');
    fs.mkdirSync(outputDir, { recursive: true });
    const outputPath = path.join(outputDir, safeName);
    fs.writeFileSync(outputPath, JSON.stringify(report, null, 2), 'utf8');
    return outputPath;
  }
}

if (require.main === module) {
  const analyzer = new SafePhishingAnalyzer();
  const result = analyzer.analyzeLink(process.argv[2] || 'https://grabify.link/72QD8S');
  console.log(JSON.stringify(result, null, 2));
}

module.exports = SafePhishingAnalyzer;
