const dns = require('node:dns').promises;
const net = require('node:net');

function isPrivateAddress(address) {
  if (net.isIP(address) === 6) return address === '::1' || address.startsWith('fc') || address.startsWith('fd') || address.startsWith('fe80:');
  if (net.isIP(address) !== 4) return true;
  const [a, b] = address.split('.').map(Number);
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a === 0 || a >= 224;
}

async function assertPublicHost(hostname) {
  const addresses = await dns.lookup(hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some((entry) => isPrivateAddress(entry.address))) {
    throw new Error(`Blocked private or local destination: ${hostname}`);
  }
  return addresses.map((entry) => entry.address);
}

function registrableDomain(hostname) {
  const labels = hostname.toLowerCase().split('.').filter(Boolean);
  return labels.length >= 2 ? labels.slice(-2).join('.') : hostname.toLowerCase();
}

/**
 * Opens a URL in a disposable Playwright context. This is deliberately a
 * metadata-only inspection: no forms are filled, no credentials are supplied,
 * no cookies or local storage are loaded, and page bodies are not returned.
 */
async function inspectInIsolatedBrowser(rawUrl, options = {}) {
  let playwright;
  try {
    playwright = require('playwright');
  } catch {
    return { checked: false, available: false, warnings: ['Browser simulation is unavailable until Playwright and its Chromium browser are installed.'], privacy: 'No browser was opened; no customer data was accessed.' };
  }

  const maxRedirects = Math.min(Math.max(Number(options.maxRedirects) || 5, 1), 5);
  const timeoutMs = Math.min(Math.max(Number(options.timeoutMs) || 10000, 3000), 15000);
  const redirectChain = [];
  const blockedRequests = [];
  const warnings = [];
  let browser;
  try {
    const initial = new URL(String(rawUrl || '').trim());
    if (!['http:', 'https:'].includes(initial.protocol)) throw new Error('Only HTTP and HTTPS URLs are supported.');
    await assertPublicHost(initial.hostname);
    browser = await playwright.chromium.launch({ headless: true });
    const context = await browser.newContext({
      storageState: undefined,
      serviceWorkers: 'block',
      javaScriptEnabled: true,
      permissions: [],
      acceptDownloads: false,
      ignoreHTTPSErrors: false,
      userAgent: 'PhishGuard-Isolated-Training-Scanner/1.0'
    });
    await context.addInitScript(() => {
      try { localStorage.clear(); sessionStorage.clear(); } catch {}
    });
    const page = await context.newPage();
    page.setDefaultTimeout(timeoutMs);
    await page.route('**/*', async (route) => {
      const request = route.request();
      const requestUrl = new URL(request.url());
      if (!['http:', 'https:'].includes(requestUrl.protocol)) return route.abort();
      if (!['GET', 'HEAD'].includes(request.method())) {
        blockedRequests.push({ method: request.method(), url: requestUrl.origin + requestUrl.pathname });
        return route.abort();
      }
      try { await assertPublicHost(requestUrl.hostname); } catch { blockedRequests.push({ method: request.method(), url: requestUrl.origin + requestUrl.pathname }); return route.abort(); }
      const type = request.resourceType();
      const sameOrigin = requestUrl.origin === initial.origin;
      if (type !== 'document' && !sameOrigin) {
        blockedRequests.push({ method: request.method(), url: requestUrl.origin + requestUrl.pathname });
        return route.abort();
      }
      return route.continue();
    });
    page.on('response', (response) => {
      const responseUrl = response.url();
      try {
        const parsed = new URL(responseUrl);
        if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
          if (!redirectChain.some((item) => item.url === parsed.origin + parsed.pathname)) redirectChain.push({ url: parsed.origin + parsed.pathname, hostname: parsed.hostname.toLowerCase(), status: response.status() });
        }
      } catch {}
    });
    await page.goto(initial.toString(), { waitUntil: 'domcontentloaded', timeout: timeoutMs });
    await page.waitForTimeout(Math.min(1000, timeoutMs / 4));
    const finalUrl = page.url();
    const final = new URL(finalUrl);
    await assertPublicHost(final.hostname);
    const indicators = await page.locator('form').evaluateAll((forms) => forms.slice(0, 20).map((form) => ({ method: (form.getAttribute('method') || 'get').toUpperCase(), action: form.getAttribute('action') || '', fields: [...form.querySelectorAll('input,textarea,select')].slice(0, 30).map((field) => ({ type: field.getAttribute('type') || field.tagName.toLowerCase(), name: field.getAttribute('name') || '' })) })));
    const sensitiveFieldTypes = new Set(['password', 'email', 'tel', 'number']);
    const sensitiveForms = indicators.filter((form) => form.fields.some((field) => sensitiveFieldTypes.has(field.type) || /password|email|phone|card|cvv|token|account/i.test(field.name)));
    const hosts = [...new Set([initial.hostname.toLowerCase(), ...redirectChain.map((item) => item.hostname), final.hostname.toLowerCase()])];
    const domains = [...new Set(hosts.map(registrableDomain))];
    const domainChanged = domains.length > 1;
    if (domainChanged) warnings.push(`The browser simulation crossed registrable domains: ${domains.join(' → ')}.`);
    if (sensitiveForms.length) warnings.push(`The page exposes ${sensitiveForms.length} form(s) with credential or personal-data fields; do not enter real information.`);
    if (blockedRequests.length) warnings.push(`${blockedRequests.length} state-changing, private-network, or cross-origin subresource request(s) were blocked.`);
    return { checked: true, available: true, finalUrl: final.origin + final.pathname, hosts, registrableDomains: domains, domainChanged, redirectChain: redirectChain.slice(0, maxRedirects + 1), forms: indicators, sensitiveFormCount: sensitiveForms.length, blockedRequestCount: blockedRequests.length, warnings, privacy: 'Disposable browser context: no customer cookies, credentials, local storage, permissions, downloads, form submissions, or page content were retained.' };
  } catch (error) {
    warnings.push(error.message || 'The isolated browser simulation could not complete.');
    return { checked: false, available: true, redirectChain, blockedRequestCount: blockedRequests.length, warnings, privacy: 'The disposable context was closed; no customer data was accessed.' };
  } finally {
    if (browser) await browser.close().catch(() => {});
  }
}

module.exports = { inspectInIsolatedBrowser };
