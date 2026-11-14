// phishing-analyzer.js
const fs = require('fs');
const path = require('path');
const net = require('net');
const { URL } = require('url');

class PhishingAnalyzer {
  constructor() {
    this.suspiciousDomains = new Set([
      'example-phish.com',
      'malicious-site.net',
      'fake-login.org',
      'grabify.link',
      'iplogger.org',
      'bit.ly',
      'tinyurl.com'
    ]);
    
    this.suspiciousWords = new Set([
      'login', 'account', 'verify', 'update', 'secure', 
      'confirm', 'validate', 'authenticate', 'reset',
      'password', 'security', 'alert', 'warning', 'urgent'
    ]);
    
    this.trackingParameters = new Set([
      'utm_source', 'utm_medium', 'utm_campaign', 
      'ref', 'redirect', 'next', 'url', 'r', 'go', 'redirect_to'
    ]);

    this.ipLoggerDomains = new Set([
      'grabify.link', 'iplogger.org', 'iplogger.com', '2no.co', 'yip.su'
    ]);

    this.urlShortenerDomains = new Set([
      'bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly'
    ]);

    this.sensitiveParameterNames = new Set([
      'password', 'pass', 'pwd', 'token', 'auth_token', 'access_token',
      'client_secret', 'api_key', 'client_id', 'code', 'state', 'secret',
      'key', 'private_key', 'public_key', 'session', 'sid', 'phpsessid',
      'id', 'uid', 'user', 'username', 'email', 'phone'
    ]);
    
    this.secretPatterns = [
      // Email addresses
      /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi,
      
      // Passwords
      /password=[^&]*/gi,
      /pass=[^&]*/gi,
      /pwd=[^&]*/gi,
      
      // Tokens
      /token=[^&]*/gi,
      /auth_token=[^&]*/gi,
      /access_token=[^&]*/gi,
      /client_secret=[^&]*/gi,
      /api_key=[^&]*/gi,
      /client_id=[^&]*/gi,
      /code=[^&]*/gi,
      /state=[^&]*/gi,
      
      // Security keys
      /secret=[^&]*/gi,
      /key=[^&]*/gi,
      /private_key=[^&]*/gi,
      /public_key=[^&]*/gi,
      
      // Session identifiers
      /session=[^&]*/gi,
      /sid=[^&]*/gi,
      /PHPSESSID=[^&]*/gi,
      
      // Other identifiers
      /id=[^&]*/gi,
      /uid=[^&]*/gi,
      /user=[^&]*/gi,
      /username=[^&]*/gi,
      /email=[^&]*/gi,
      /phone=[^&]*/gi
    ];
  }

  // Validate URL format and sanitize
  validateUrl(phishingLink) {
    // Remove leading/trailing whitespace
    phishingLink = phishingLink.trim();
    
    // Reject unsupported schemes
    if (!phishingLink.startsWith('http://') && !phishingLink.startsWith('https://')) {
      return { 
        isValid: false,
        error: 'Unsupported URL scheme',
        warnings: [{ message: 'Unsupported URL scheme detected' }]
      };
    }
    
    try {
      const urlObj = new URL(phishingLink);
      
      // Check for IPv6 addresses
      if (urlObj.hostname.includes(':')) {
        return { 
          isValid: true,
          warnings: [{ message: 'IPv6 address detected' }],
          urlObj: urlObj
        };
      }
      
      // Check for unusual ports
      if (urlObj.port && ![80, 443].includes(parseInt(urlObj.port))) {
        return { 
          isValid: true,
          warnings: [{ message: 'Unusual port detected' }],
          urlObj: urlObj
        };
      }
      
      // Check for suspicious words in domain
      const domainParts = urlObj.hostname.split('.');
      for (const part of domainParts) {
        if (this.suspiciousWords.has(part.toLowerCase())) {
          return { 
            isValid: true,
            warnings: [{ message: `Suspicious word "${part}" in domain` }],
            urlObj: urlObj
          };
        }
      }
      
      return { 
        isValid: true,
        urlObj: urlObj
      };
    } catch (error) {
      return { 
        isValid: false,
        error: 'Invalid URL format',
        warnings: [{ message: 'Invalid URL format detected' }]
      };
    }
  }

  // Parse URL and extract components
  parseUrl(phishingLink) {
    const validationResult = this.validateUrl(phishingLink);
    
    if (!validationResult.isValid) {
      return { 
        error: validationResult.error,
        warnings: validationResult.warnings || []
      };
    }
    
    const urlObj = validationResult.urlObj;
    const domain = urlObj.hostname;
    
    // Check for suspicious domain match with exact boundaries
    const matchesSuspiciousDomain = Array.from(this.suspiciousDomains).some(
      suspDomain => {
        // Match exact domain or subdomain
        return domain === suspDomain || 
               domain.endsWith('.' + suspDomain);
      }
    );
    
    // Check for suspicious words with exact boundaries
    const hasSuspiciousWord = Array.from(this.suspiciousWords).some(
      word => {
        // Match exact word or as part of domain
        return domain === word || 
               domain.endsWith('.' + word) ||
               domain.includes('.' + word + '.');
      }
    );
    
    // Check for suspicious subdomain depth
    const subdomainCount = (domain.match(/\./g) || []).length;
    const hasDeepSubdomain = subdomainCount > 2;
    
    // Check for punycode
    const hasPunycode = domain.includes('xn--');
    
    // Check for user-info in URL
    const hasUserInfo = !!urlObj.username || !!urlObj.password;
    
    // Extract parameters
    const params = {};
    const paramOrder = [];
    
    for (const [key, value] of urlObj.searchParams.entries()) {
      // Track parameter order
      if (!paramOrder.includes(key)) {
        paramOrder.push(key);
      }
      
      // Handle duplicates
      if (params[key]) {
        if (Array.isArray(params[key])) {
          params[key].push(this.redactSensitiveData(key, value));
        } else {
          params[key] = [params[key], this.redactSensitiveData(key, value)];
        }
      } else {
        params[key] = this.redactSensitiveData(key, value);
      }
    }
    
    // Check for tracking parameters
    const hasTracking = Object.keys(params).some(key => 
      this.trackingParameters.has(key)
    );
    
    // Extract redirects
    const redirects = [];
    for (const key of paramOrder) {
      if (this.trackingParameters.has(key) && params[key]) {
        const values = Array.isArray(params[key]) ? params[key] : [params[key]];
        
        for (const value of values) {
          if (value.includes('http://') || value.includes('https://')) {
            redirects.push(value);
          }
        }
      }
    }
    
    // Extract underlying URLs from tracking parameters
    const underlyingUrls = [];
    for (const key of paramOrder) {
      if (this.trackingParameters.has(key) && params[key]) {
        const values = Array.isArray(params[key]) ? params[key] : [params[key]];
        
        for (const value of values) {
          try {
            // Try to parse as URL
            if (value.includes('http://') || value.includes('https://')) {
              underlyingUrls.push({
                source: key,
                url: value,
                type: 'redirect'
              });
            }
            
            // Try to extract URL from common patterns
            const urlMatch = value.match(/https?:\/\/[^\s]+/);
            if (urlMatch) {
              underlyingUrls.push({
                source: key,
                url: urlMatch[0],
                type: 'embedded'
              });
            }
          } catch (error) {
            // Skip invalid URLs
          }
        }
      }
    }
    
    // Deduplicate URLs
    const deduplicatedUrls = [];
    const seenUrls = new Set();
    
    for (const url of underlyingUrls) {
      if (!seenUrls.has(url.url)) {
        seenUrls.add(url.url);
        deduplicatedUrls.push(url);
      }
    }
    
    // Create sanitized URL (no query string or fragment)
    const sanitizedUrl = `${urlObj.protocol}//${urlObj.hostname}${urlObj.pathname}`;
    
    // Check for credential words in path and query
    const pathQueryHasCredentials = 
      urlObj.pathname.toLowerCase().includes('login') ||
      urlObj.pathname.toLowerCase().includes('password') ||
      urlObj.pathname.toLowerCase().includes('account') ||
      Array.from(urlObj.searchParams.values()).some(val => 
        val.toLowerCase().includes('password') ||
        val.toLowerCase().includes('pass') ||
        val.toLowerCase().includes('cred')
      );
    
    // Check for suspicious URL length
    const suspiciousUrlLength = phishingLink.length > 2048;
    
    // Check for numeric IP
    const hasNumericIp = net.isIP(domain) === 4;
    
    // Check for IP logger domains
    const hasIpLogger = Array.from(this.ipLoggerDomains).some(
      knownDomain => domain === knownDomain || domain.endsWith(`.${knownDomain}`)
    );
    
    // Check for URL shorteners
    const hasUrlShortener = this.urlShortenerDomains.has(domain);
    
    return {
      url: phishingLink,
      sanitizedUrl: sanitizedUrl,
      domain: domain,
      suspiciousIndicators: {
        suspiciousDomain: matchesSuspiciousDomain,
        suspiciousWord: hasSuspiciousWord,
        deepSubdomain: hasDeepSubdomain,
        punycode: hasPunycode,
        userInfo: hasUserInfo,
        pathQueryCredentials: pathQueryHasCredentials,
        longUrl: suspiciousUrlLength,
        numericIp: hasNumericIp,
        ipLogger: hasIpLogger,
        urlShortener: hasUrlShortener
      },
      hasTracking: hasTracking,
      parameters: params,
      redirects: [...new Set(redirects)],
      underlyingUrls: deduplicatedUrls,
      path: urlObj.pathname,
      hash: urlObj.hash,
      warnings: validationResult.warnings || [],
      analysisTime: new Date().toISOString()
    };
  }

  // Redact sensitive data from URLs by parameter name
  redactSensitiveData(paramName, paramValue) {
    if (!paramValue) return paramValue;
    
    // Check if parameter name indicates sensitive data
    if (this.sensitiveParameterNames.has(String(paramName).toLowerCase())) {
      return '[REDACTED]';
    }
    
    // Apply general patterns
    let result = paramValue;
    for (const pattern of this.secretPatterns) {
      result = result.replace(pattern, '[REDACTED]');
    }
    
    return result;
  }

  // Generate analysis report
  generateReport(analyzedUrl) {
    if (analyzedUrl.error) {
      return analyzedUrl;
    }

    // Calculate heuristic score
    let score = 0;
    let reasons = [];
    
    if (analyzedUrl.suspiciousIndicators.suspiciousDomain) {
      score += 3;
      reasons.push('Suspicious domain detected');
    }
    
    if (analyzedUrl.suspiciousIndicators.suspiciousWord) {
      score += 2;
      reasons.push('Suspicious word in domain');
    }
    
    if (analyzedUrl.suspiciousIndicators.deepSubdomain) {
      score += 2;
      reasons.push('Deep subdomain detected');
    }
    
    if (analyzedUrl.suspiciousIndicators.punycode) {
      score += 2;
      reasons.push('Punycode domain detected');
    }
    
    if (analyzedUrl.suspiciousIndicators.userInfo) {
      score += 2;
      reasons.push('User info in URL detected');
    }
    
    if (analyzedUrl.suspiciousIndicators.pathQueryCredentials) {
      score += 1;
      reasons.push('Credential words in path/query');
    }
    
    if (analyzedUrl.suspiciousIndicators.longUrl) {
      score += 1;
      reasons.push('Long URL detected');
    }
    
    if (analyzedUrl.suspiciousIndicators.numericIp) {
      score += 1;
      reasons.push('Numeric IP address detected');
    }
    
    if (analyzedUrl.suspiciousIndicators.ipLogger) {
      score += 2;
      reasons.push('IP logging domain detected');
    }
    
    if (analyzedUrl.suspiciousIndicators.urlShortener) {
      score += 2;
      reasons.push('URL shortener detected');
    }

    for (const warning of analyzedUrl.warnings || []) {
      if (!reasons.includes(warning.message)) {
        reasons.push(warning.message);
      }
      score += 1;
    }
    
    // Determine risk level
    let riskLevel;
    if (score >= 5) {
      riskLevel = 'HIGH';
    } else if (score >= 3) {
      riskLevel = 'MEDIUM';
    } else {
      riskLevel = 'LOW';
    }
    
    return {
      originalUrl: analyzedUrl.sanitizedUrl,
      sanitizedUrl: analyzedUrl.sanitizedUrl,
      domain: analyzedUrl.domain,
      suspiciousIndicators: analyzedUrl.suspiciousIndicators,
      hasTracking: analyzedUrl.hasTracking,
      parameters: analyzedUrl.parameters,
      redirects: analyzedUrl.redirects,
      underlyingUrls: analyzedUrl.underlyingUrls,
      analysisTime: analyzedUrl.analysisTime,
      metadata: {
        path: analyzedUrl.path,
        hash: analyzedUrl.hash
      },
      risk: {
        level: riskLevel,
        score: score,
        maxScore: 20,
        reasons: reasons
      },
      warnings: analyzedUrl.warnings
    };
  }

  // Analyze phishing link offline
  analyzeLink(phishingLink) {
    // Parse the URL
    const analyzedUrl = this.parseUrl(phishingLink);

    if (analyzedUrl.error) {
      return analyzedUrl;
    }
    
    // Generate report
    const report = this.generateReport(analyzedUrl);
    
    return report;
  }

  // Save analysis to file
  saveAnalysis(report, filename = 'phishing_analysis.json') {
    try {
      const outputDir = './outputs';
      if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
      }
      
      // Sanitize filename to prevent path traversal
      let sanitizedFilename = filename.replace(/[^a-zA-Z0-9_.-]/g, '');
      
      // Ensure unique filename if exists
      let finalFilename = sanitizedFilename || 'phishing_analysis.json';
      let counter = 1;
      while (fs.existsSync(`${outputDir}/${finalFilename}`)) {
        const ext = sanitizedFilename.lastIndexOf('.') !== -1 ? 
          sanitizedFilename.substring(sanitizedFilename.lastIndexOf('.')) : '';
        const base = sanitizedFilename.substring(0, sanitizedFilename.length - ext.length);
        finalFilename = `${base}_${counter}${ext}`;
        counter++;
      }
      
      const outputPath = path.join(outputDir, finalFilename);
      
      fs.writeFileSync(outputPath, JSON.stringify(report, null, 4));
      console.log(`Analysis saved to ${outputPath}`);
      return outputPath;
    } catch (error) {
      console.error('Error saving analysis:', error);
      return null;
    }
  }
}

// Usage example
function main() {
  const analyzer = new PhishingAnalyzer();
  
  // Example phishing link
  const phishingLink = "https://example-phish.com/login?utm_source=email&utm_campaign=phishing&id=123&next=https://legitimate.com&token=abc123";
  const report = analyzer.analyzeLink(phishingLink);

  if (report.error) {
    console.error(`Analysis failed: ${report.error}`);
    return;
  }
  
  // Save results
  analyzer.saveAnalysis(report);
  
  // Display results
  console.log('\n=== Phishing Link Analysis ===');
  console.log(`Original URL: ${report.originalUrl}`);
  console.log(`Sanitized URL: ${report.sanitizedUrl}`);
  console.log(`Domain: ${report.domain}`);
  console.log(`Suspicious indicators: ${JSON.stringify(report.suspiciousIndicators, null, 2)}`);
  console.log(`Contains tracking: ${report.hasTracking ? 'Yes' : 'No'}`);
  console.log(`Redirects: ${report.redirects.join(', ') || 'None'}`);
  console.log(`Underlying URLs: ${report.underlyingUrls.length} found`);
  console.log(`Risk: ${report.risk.level} (${report.risk.score}/${report.risk.maxScore})`);
  console.log(`Analysis Time: ${report.analysisTime}`);
}

if (require.main === module) {
  main();
}

module.exports = PhishingAnalyzer;
