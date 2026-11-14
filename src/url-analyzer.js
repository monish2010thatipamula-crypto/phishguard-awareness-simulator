const { URL } = require('node:url');
const dns = require('node:dns').promises;
const net = require('node:net');

const suspiciousDomains = new Set([
  'grabify.link', 'iplogger.org', 'iplogger.com', '2no.co', 'yip.su',
  'bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly'
]);
const redirectParameters = new Set([
  'url', 'u', 'uri', 'link', 'target', 'dest', 'destination',
  'redirect', 'redirect_url', 'redirect_uri', 'next', 'continue',
  'return', 'return_to', 'go', 'r', 'ref'
]);
const suspiciousTerms = new Set([
  'login', 'signin', 'verify', 'verification', 'account', 'update',
  'urgent', 'password', 'payment', 'wallet', 'unlock', 'confirm', 'reset'
]);
const secretParameter = /^(password|pass|pwd|token|auth[_-]?token|access[_-]?token|secret|api[_-]?key|client[_-]?secret|code|state|session|sid|phpsessid|email|phone)$/i;

function invalidResult(url, message) {
  return { url, classification: 'Invalid', severity: 'error', reasons: [message], embeddedLinks: [], resolutionNote: 'No destination can be extracted from an invalid URL.', riskScore: 0, hasTracking: false };
}

function decodeRepeated(value) {
  let decoded = String(value);
  for (let i = 0; i < 3; i += 1) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    } catch { break; }
  }
  return decoded;
}

function redactValue(key, value) {
  if (secretParameter.test(key)) return '[REDACTED]';
  return decodeRepeated(value).replace(/[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/g, '[REDACTED_EMAIL]');
}

function safeUrlString(parsed) {
  const copy = new URL(parsed.toString());
  for (const key of [...copy.searchParams.keys()]) {
    const values = copy.searchParams.getAll(key).map((value) => redactValue(key, value));
    copy.searchParams.delete(key);
    for (const value of values) copy.searchParams.append(key, value);
  }
  if (copy.hash) copy.hash = '#[REDACTED_FRAGMENT]';
  copy.username = '';
  copy.password = '';
  return copy.toString();
}

function extractEmbeddedLinks(parsed) {
  const found = new Map();
  const add = (source, rawValue) => {
    const decoded = decodeRepeated(rawValue);
    const matches = decoded.match(/https?:\/\/[^\s"'<>]+/gi) || [];
    for (const match of matches) {
      try {
        const normalized = new URL(match).toString();
        if (!found.has(normalized)) found.set(normalized, normalized);
      } catch { /* ignore malformed embedded values */ }
    }
  };
  for (const [key, value] of parsed.searchParams.entries()) {
    const decoded = decodeRepeated(value);
    if (redirectParameters.has(key.toLowerCase()) || /https?:\/\//i.test(decoded)) add(key, value);
  }
  return [...found.values()];
}

function analyzeUrl(rawUrl) {
  const value = String(rawUrl || '').trim();
  if (!value) return invalidResult(value, 'Enter a URL to analyze.');
  const candidate = value.includes('://') ? value : `https://${value}`;
  let parsed;
  try { parsed = new URL(candidate); } catch { return invalidResult(value, 'The value is not a valid URL.'); }
  if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) return invalidResult(value, 'Only HTTP and HTTPS URLs are supported.');

  const domain = parsed.hostname.toLowerCase();
  const reasons = [];
  const indicators = {};
  const tracking = suspiciousDomains.has(domain);
  const embeddedLinks = extractEmbeddedLinks(parsed);
  indicators.nonHttps = parsed.protocol !== 'https:';
  indicators.numericIp = /^[0-9.]+$/.test(domain);
  indicators.punycode = domain.startsWith('xn--') || domain.includes('.xn--');
  indicators.userInfo = Boolean(parsed.username || parsed.password);
  indicators.trackingDomain = tracking;
  indicators.shortener = ['bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly'].includes(domain);
  indicators.nonStandardPort = Boolean(parsed.port && !['80', '443'].includes(parsed.port));
  indicators.deepSubdomain = domain.split('.').length > 4;
  indicators.suspiciousTerm = [...suspiciousTerms].some((term) => `${domain}${parsed.pathname}${parsed.search}`.toLowerCase().includes(term));
  indicators.embeddedDestination = embeddedLinks.length > 0;

  if (indicators.nonHttps) reasons.push('The link does not use HTTPS.');
  if (indicators.numericIp) reasons.push('The destination uses a numeric IP address instead of a domain name.');
  if (indicators.punycode) reasons.push('The domain uses punycode and may imitate another alphabet or brand.');
  if (indicators.userInfo) reasons.push('The URL contains user-info before the host, which can hide the real destination.');
  if (indicators.trackingDomain) reasons.push('The domain is associated with link tracking, IP-logging services, or URL-shortening services.');
  if (indicators.nonStandardPort) reasons.push('The link uses a non-standard web port.');
  if (indicators.deepSubdomain) reasons.push('The domain has an unusually deep subdomain structure.');
  if (indicators.suspiciousTerm) reasons.push('The URL contains language commonly used in credential or payment lures.');
  if (indicators.embeddedDestination) reasons.push('The URL exposes an embedded destination in its parameters.');

  const weights = { nonHttps: 1, numericIp: 2, punycode: 2, userInfo: 2, trackingDomain: 3, shortener: 1, nonStandardPort: 1, deepSubdomain: 1, suspiciousTerm: 1, embeddedDestination: 1 };
  const riskScore = Object.entries(indicators).reduce((total, [key, enabled]) => total + (enabled ? weights[key] : 0), 0);
  const resolutionNote = embeddedLinks.length
    ? 'A possible embedded destination was found in the URL text. Verify it through a trusted channel before opening it.'
    : tracking
      ? 'The final destination may be stored behind a server-side redirect. This offline tool will not contact the tracking service to resolve it.'
      : 'No embedded destination was exposed in the URL text.';

  return {
    url: safeUrlString(parsed), domain,
    classification: riskScore ? 'Likely suspicious' : 'No obvious indicators',
    severity: riskScore >= 5 ? 'high' : riskScore ? 'warning' : 'success',
    riskScore, indicators,
    reasons: reasons.length ? reasons : ['No common lexical red flags were found by this offline check.'],
    embeddedLinks, resolutionNote, hasTracking: tracking,
    privacy: 'Offline analysis only. No URL requests, IP collection, device collection, or location lookup.'
  };
}

async function resolveDestinationIp(domain) {
  if (!domain) return { addresses: [], status: 'unavailable', note: 'No domain was available for DNS lookup.' };
  try {
    const addresses = await Promise.race([
      dns.lookup(domain, { all: true, verbatim: true }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('DNS lookup timed out')), 5000))
    ]);
    const values = [...new Set(addresses.map((entry) => entry.address))];
    return {
      addresses: values,
      status: values.length ? 'resolved' : 'unavailable',
      note: 'These are destination infrastructure addresses. They do not identify the sender or link creator.'
    };
  } catch {
    return { addresses: [], status: 'unavailable', note: 'The destination IP could not be resolved from this environment.' };
  }
}

// Additive, bounded simulation: inspect redirect headers only, without
// submitting forms, sending credentials, retaining cookies, or reading bodies.
function isPrivateAddress(address) {
  if (net.isIP(address) === 6) return address === '::1' || address.startsWith('fc') || address.startsWith('fd') || address.startsWith('fe80:');
  if (net.isIP(address) !== 4) return true;
  const [a, b] = address.split('.').map(Number);
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a === 0 || a >= 224;
}

function registrableDomain(hostname) {
  const labels = hostname.toLowerCase().split('.').filter(Boolean);
  return labels.length >= 2 ? labels.slice(-2).join('.') : hostname.toLowerCase();
}

async function inspectRedirectChain(rawUrl, options = {}) {
  const maxRedirects = Math.min(Math.max(Number(options.maxRedirects) || 5, 1), 5);
  const chain = [];
  const warnings = [];
  let current = String(rawUrl || '').trim();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    for (let hop = 0; hop <= maxRedirects; hop += 1) {
      const parsed = new URL(current);
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        warnings.push('The redirect chain attempted to leave HTTP(S).');
        break;
      }
      const addresses = await dns.lookup(parsed.hostname, { all: true, verbatim: true });
      if (addresses.some((entry) => isPrivateAddress(entry.address))) {
        warnings.push(`Blocked inspection for private or local destination: ${parsed.hostname}.`);
        break;
      }
      chain.push({ hostname: parsed.hostname.toLowerCase(), url: `${parsed.protocol}//${parsed.host}${parsed.pathname}` });
      const response = await fetch(parsed, {
        method: 'HEAD', redirect: 'manual', credentials: 'omit',
        headers: { 'user-agent': 'PhishGuard-authorized-safety-check/1.0' }, signal: controller.signal
      });
      if (response.status < 300 || response.status >= 400) break;
      const location = response.headers.get('location');
      if (!location) break;
      if (hop === maxRedirects) {
        warnings.push(`Redirect chain exceeded the ${maxRedirects}-hop safety limit.`);
        break;
      }
      current = new URL(location, parsed).toString();
    }
  } catch (error) {
    warnings.push(error.name === 'AbortError' ? 'Redirect inspection timed out.' : 'Redirect inspection was unavailable.');
  } finally {
    clearTimeout(timer);
  }
  const hosts = [...new Set(chain.map((item) => item.hostname))];
  const registrableDomains = [...new Set(hosts.map(registrableDomain))];
  const domainChanged = registrableDomains.length > 1;
  if (domainChanged) warnings.unshift(`The link crossed registrable domains: ${registrableDomains.join(' → ')}.`);
  return {
    checked: chain.length > 0, chain, hosts, registrableDomains, domainChanged, warnings,
    privacy: 'Simulation only: no forms, credentials, cookies, customer data, page content, or browser identity were accessed.'
  };
}

module.exports = { analyzeUrl, resolveDestinationIp, inspectRedirectChain };
