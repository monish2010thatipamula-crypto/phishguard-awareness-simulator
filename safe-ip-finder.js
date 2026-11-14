const fs = require('node:fs');
const path = require('node:path');
const dns = require('node:dns').promises;
const net = require('node:net');
const { URL } = require('node:url');

class SafeIPFinder {
  constructor() {
    this.timeoutMs = 5000;
    this.outputDir = path.resolve('outputs');
  }

  validateUrl(value) {
    const input = String(value || '').trim();
    try {
      const parsed = new URL(input);
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        return { error: 'Only HTTP and HTTPS URLs are supported.' };
      }
      if (!parsed.hostname) return { error: 'The URL has no hostname.' };
      return { valid: true, urlObj: parsed };
    } catch {
      return { error: 'Invalid URL format.' };
    }
  }

  async getDnsResolution(domain) {
    try {
      const result = await Promise.race([
        dns.lookup(domain, { all: true, verbatim: true }),
        new Promise((_, reject) => setTimeout(() => reject(new Error('DNS lookup timed out')), this.timeoutMs))
      ]);
      return [...new Set(result.map((entry) => entry.address))];
    } catch {
      return [];
    }
  }

  // Preserved API: deliberately disabled so a suspicious URL is never opened.
  async makeHttpRequest(_url) {
    return {
      statusCode: null,
      headers: {},
      body: '',
      disabled: true,
      note: 'HTTP fetching is disabled. Opening an untrusted link could expose the analyst or create an SSRF risk.'
    };
  }

  // Analyze headers supplied from an authorized server log only.
  extractIpAddress(headers = {}) {
    const candidates = ['x-forwarded-for', 'cf-connecting-ip', 'x-real-ip', 'true-client-ip'];
    for (const name of candidates) {
      const value = headers[name] || headers[name.toLowerCase()];
      if (!value) continue;
      const first = String(value).split(',')[0].trim();
      if (net.isIP(first)) return first;
    }
    return null;
  }

  // Analyze supplied HTML text offline; this does not prove ownership or authorship.
  extractIpFromContent(html = '') {
    const matches = String(html).match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
    return [...new Set(matches.filter((candidate) => net.isIP(candidate)))];
  }

  async findIp(phishingLink) {
    const validation = this.validateUrl(phishingLink);
    if (!validation.valid) return { error: validation.error };

    const { urlObj } = validation;
    const dnsResults = await this.getDnsResolution(urlObj.hostname);
    const httpResponse = await this.makeHttpRequest(urlObj);

    return {
      originalUrl: urlObj.toString(),
      domain: urlObj.hostname,
      dnsResults,
      destinationIp: dnsResults[0] || null,
      httpStatus: httpResponse.statusCode,
      ipFromHeaders: this.extractIpAddress({}),
      ipFromContent: this.extractIpFromContent(''),
      realIp: null,
      note: 'DNS results identify destination infrastructure only. They do not identify the sender or link creator.',
      analysisTime: new Date().toISOString()
    };
  }

  async analyzeLink(phishingLink) {
    try {
      return await this.findIp(phishingLink);
    } catch (error) {
      return { error: error.message };
    }
  }

  saveAnalysis(result, filename = 'ip_analysis.json') {
    fs.mkdirSync(this.outputDir, { recursive: true });
    const safeName = String(filename).replace(/[^a-zA-Z0-9_.-]/g, '') || 'ip_analysis.json';
    const outputPath = path.join(this.outputDir, safeName);
    fs.writeFileSync(outputPath, JSON.stringify(result, null, 2), 'utf8');
    return outputPath;
  }
}

if (require.main === module) {
  const input = process.argv[2] || 'https://grabify.link/72QD8S';
  new SafeIPFinder().analyzeLink(input).then((result) => console.log(JSON.stringify(result, null, 2)));
}

module.exports = SafeIPFinder;
