// Listen for messages from the popup (secure message passing)
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_IOCS") {
    sendResponse(performExtraction());
  }
});
// content_script.js
const DEBUG = true; // Set to false to disable console logs
function debugLog(message, ...optionalParams) {
  if (DEBUG) {
    console.log("[IOCScout365]", message, ...optionalParams);
  }
}

debugLog("IOC Scout 365 content script loaded.");

const legitimateMicrosoftDomains = [
  // Microsoft primary domains
  'microsoft.com', 'windows.com', 'office.com', 'live.com', 'outlook.com', 'office365.com',
  'microsoftonline.com', 'microsoft365.com', 'msn.com', 'azure.com', 'visualstudio.com',
  'sharepoint.com', 'onedrive.com', 'sway.com', 'officeapps.live.com',
  // Microsoft CDN/Infrastructure
  'microsoftsupport.net', 'msecnd.net', 'msocdn.com', 'msftauth.net', 'msauth.net',
  'public-trust.com', // Often related to MS services
  // Common CDNs that are generally safe but should be noted if serving unexpected content
  'cloudflare.com', 'bootstrapcdn.com', 'jquery.com', 'googleapis.com', 'gstatic.com',
  'jsdelivr.net', 'unpkg.com'
];

const officePhishingKitIndicators = {
  generalOfficeKit: [
    /office[._-]login/i, /ms[._-]login\.js/i, /login[._-]office\.js/i,
    /owa_auth\.js/i, /signin_page\.js/i, /next_animation\.js/i,
    /password\.html/i, /verify\.html/i, /auth\.php/i, /login\.php/i,
    // Keywords often found in comments or file paths of kits
    "<!-- main -->", "<!-- /main -->", "<!-- Footer -->",
    "<!-- Copyright (c) Microsoft Corporation -->" // Misleading copyright
  ],
  // Specific file names or patterns observed in O365 phishing kits
  o365KitFiles: [
    /0\.js/i, /1\.js/i, /2\.js/i, // Common in some kits for sequential loading
    /style\.css\?v=\d+/i, // Versioned CSS, sometimes kit related
    /app\.js\?v=\d+/i,
    /jquery\.min\.js\?ver=\d+/i // Locally hosted jQuery can be a sign
  ]
};

function isLegitimateMicrosoftRelated(url) {
  if (!url) return false;
  try {
    const hostname = new URL(url).hostname;
    return legitimateMicrosoftDomains.some(domain => hostname.endsWith(domain));
  } catch (e) {
    // Could be a relative URL or malformed, treat as non-legitimate for safety
    return false;
  }
}

function detectMicrosoftBrand(doc) {
  const patterns = [
    /microsoft/i, /office 365/i, /outlook/i, /onedrive/i, /sharepoint/i,
    /teams/i, /skype/i, /azure/i, /windows live/i, /msn/i,
    /sign in to your microsoft account/i, /enter password/i // Common phrases
  ];
  const titleText = doc.title.toLowerCase();
  const bodyText = doc.body ? doc.body.innerText.toLowerCase() : "";

  // 1. Title/body
  if (patterns.some(pattern => pattern.test(titleText) || pattern.test(bodyText))) {
    return "Microsoft/Office 365";
  }
  // 2. Images
  const images = Array.from(doc.querySelectorAll('img[src*="logo"], img[alt*="logo"]'));
  if (images.some(img => /microsoft|office|outlook/i.test(img.src) || /microsoft|office|outlook/i.test(img.alt))) {
    return "Microsoft/Office 365 (Logo detected)";
  }
  // 3. Meta tags
  const metas = Array.from(doc.querySelectorAll('meta')).map(m => (m.content || '').toLowerCase());
  if (metas.some(content => patterns.some(pattern => pattern.test(content)))) {
    return "Microsoft/Office 365 (Meta tag)";
  }
  // 4. Comments
  const comments = [];
  const nodeIterator = document.createNodeIterator(doc, NodeFilter.SHOW_COMMENT, null, false);
  let currentNode;
  while ((currentNode = nodeIterator.nextNode())) {
    comments.push(currentNode.data.toLowerCase());
  }
  if (comments.some(comment => patterns.some(pattern => pattern.test(comment)))) {
    return "Microsoft/Office 365 (Comment)";
  }
  // 5. Heuristic: any Microsoft domain present
  const msDomains = ['microsoft.com', 'office.com', 'outlook.com', 'live.com', 'microsoftonline.com'];
  const links = Array.from(doc.querySelectorAll('a[href], script[src], link[href]')).map(el => el.href || el.src || '');
  if (links.some(link => msDomains.some(domain => link.includes(domain)))) {
    return "Microsoft/Office 365 (Heuristic)";
  }
  return "Unknown";
}

function detectOfficePhishingKit(doc) {
  const htmlContent = doc.documentElement.innerHTML;
  const scripts = Array.from(doc.querySelectorAll('script')).map(s => s.src || s.textContent).join('\\n');
  let kitSignals = [];

  officePhishingKitIndicators.generalOfficeKit.forEach(indicator => {
    if (typeof indicator === 'string' && (htmlContent.includes(indicator) || scripts.includes(indicator))) {
      kitSignals.push(`General Kit Indicator: "${indicator}"`);
    } else if (indicator instanceof RegExp && (indicator.test(htmlContent) || indicator.test(scripts))) {
      kitSignals.push(`General Kit Indicator (Regex): "${indicator.source}"`);
    }
  });

  officePhishingKitIndicators.o365KitFiles.forEach(indicator => {
    if (Array.from(doc.querySelectorAll('script[src], link[href]')).some(el => indicator.test(el.src || el.href))) {
      kitSignals.push(`Kit File Pattern: "${indicator.source}"`);
    }
  });
  return kitSignals;
}

function isLikelyBase64(str) {
  if (!/^[A-Za-z0-9+\\/]+=*$/.test(str)) return false; // Check for valid Base64 characters
  if (str.length % 4 !== 0) return false; // Length must be a multiple of 4
  try {
    atob(str); // Attempt to decode
    return true;
  } catch (e) { // Changed from empty catch to catch(e) for clarity
    return false;
  }
}

function detectBase64Obfuscation(doc) {
  const scripts = Array.from(doc.querySelectorAll('script:not([src])')).map(s => s.textContent).join('\\n');
  const htmlContent = doc.documentElement.innerHTML; // Get full HTML for broader checks
  // Stricter regex: requires at least 20 Base64 characters, allows for padding, and captures the content.
  // It looks for strings that are likely to be Base64 encoded, enclosed in quotes.
  const base64Regex = /[\"\'\\`]([A-Za-z0-9+\\/]{20,}=*)[\"\'\\`]/g;
  const atobRegex = /atob\s*\(/i; // Corrected regex
  const cryptoJsRegex = /CryptoJS\\.(AES|SHA1|SHA256|MD5|Rabbit|DES|TripleDES|RabbitLegacy|EvpKDF|PBKDF2|HmacSHA1|HmacSHA256|HmacMD5)\\.(encrypt|decrypt|lib|algo|enc|mode|pad|format|x64|kdf)/ig;
  const base91Regex = /base91\.(encode|decode)/i;
  // Looks for globalThis['e'+'v'+'a'+'l'] or similar patterns
  const obfuscatedEvalRegex = /globalThis\[\s*(['"]e['"]\s*\+\s*['"]v['"]\s*\+\s*['"]a['"]\s*\+\s*['"]l['"])\s*\]/i;
  let signals = [];

  if (atobRegex.test(scripts)) {
    signals.push("Found 'atob()' usage (potential Base64 decoding).");
  }
  let match;
  let actualBase64Count = 0;
  // Iterate over all matches in the inline scripts
  while ((match = base64Regex.exec(scripts)) !== null) {
    // match[1] is the captured group - the potential Base64 string
    if (match[1] && isLikelyBase64(match[1])) {
      actualBase64Count++;
    }
  }
  if (actualBase64Count > 0) {
    signals.push(`Found ${actualBase64Count} likely Base64 encoded string(s) in inline scripts.`);
  }

  // Check for CryptoJS usage in scripts or HTML
  if (cryptoJsRegex.test(scripts) || cryptoJsRegex.test(htmlContent)) {
    signals.push('Found references to CryptoJS library methods.');
  }
  if (htmlContent.includes('crypto-js.min.js') || htmlContent.includes('crypto.js')) {
    signals.push('Found script include for CryptoJS (e.g., crypto-js.min.js).');
  }

  // Check for base91.js usage in scripts or HTML
  if (base91Regex.test(scripts) || base91Regex.test(htmlContent)) {
    signals.push('Found references to base91.js library methods.');
  }
  if (htmlContent.includes('base91.min.js') || htmlContent.includes('base91.js')) {
    signals.push('Found script include for base91.js (e.g., base91.min.js).');
  }
  
  // Check for obfuscated eval
  if (obfuscatedEvalRegex.test(scripts)) {
    signals.push("Found obfuscated 'eval' pattern (e.g., globalThis['e'+'v'+'a'+'l']).");
  }

  return signals;
}

function detectAntiAnalysis(doc) {
  const htmlContent = doc.documentElement.innerHTML;
  let signals = [];
  // Check for disabled context menu
  if (doc.body && doc.body.hasAttribute('oncontextmenu') && doc.body.getAttribute('oncontextmenu').toLowerCase().includes('return false')) {
    signals.push("Context menu potentially disabled (oncontextmenu='return false').");
  }
  // Check for F12/DevTools blocking scripts (basic)
  if (htmlContent.match(/event\.keyCode\s*==\s*123/i) || htmlContent.match(/event\.key\s*==\s*["']F12["']/i)) {
    signals.push("Potential DevTools blocking script (keyCode 123 or key 'F12').");
  }
  if (htmlContent.includes('navigator.webdriver')) {
    signals.push("Code checks for 'navigator.webdriver' (bot detection).");
  }
  // Check for meta robots tags
  const metaRobots = doc.querySelector('meta[name="robots"]');
  if (metaRobots) {
    const content = metaRobots.getAttribute('content') ? metaRobots.getAttribute('content').toLowerCase() : '';
    if (content.includes('noindex')) {
      signals.push("Meta tag 'robots' with 'noindex' found.");
    }
    if (content.includes('nofollow')) {
      signals.push("Meta tag 'robots' with 'nofollow' found.");
    }
    if (content.includes('noarchive')) {
      signals.push("Meta tag 'robots' with 'noarchive' found.");
    }
    if (content.includes('nosnippet')) {
      signals.push("Meta tag 'robots' with 'nosnippet' found.");
    }
    if (content.includes('nocache')) {
      signals.push("Meta tag 'robots' with 'nocache' found.");
    }
    if (content.includes('noimageindex')) {
      signals.push("Meta tag 'robots' with 'noimageindex' found.");
    }
    if (content.trim() === 'none') {
      signals.push("Meta tag 'robots' with 'none' found.");
    }
  }
  return signals;
}



function performExtraction() {
  // Brand detection debug
  debugLog("Brand detection debug:", {
    title: document.title,
    bodyText: document.body ? document.body.innerText : "",
    images: Array.from(document.querySelectorAll('img')).map(img => ({src: img.src, alt: img.alt})),
    metas: Array.from(document.querySelectorAll('meta')).map(m => m.content || "")
  });

  debugLog("Performing IOC extraction...");
  const iocs = {
    pageInfo: {
      url: window.location.href,
      title: document.title,
      domain: window.location.hostname
    },
    detectedBrand: detectMicrosoftBrand(document),
    criticalIOCs: {
      formActions: new Set(),
      suspiciousScripts: new Set(), // External scripts not on MS whitelist
      suspiciousDomains: new Set() // Domains from suspicious scripts/forms
    },
    otherIOCs: {
      allLinks: new Set(),
      allScripts: new Set(), // All external scripts
      allDomains: new Set(), // All unique hostnames found
      iframes: new Set(),
      dnsPrefetch: new Set(),
      metaRedirects: new Set()
    },
    phishingKitSignals: detectOfficePhishingKit(document),
    obfuscationSignals: detectBase64Obfuscation(document),
    antiAnalysisSignals: detectAntiAnalysis(document)
  };

  // Fallback: If detectedBrand is 'Unknown', try again after a short delay
  if (iocs.detectedBrand === 'Unknown') {
    setTimeout(() => {
      const retryBrand = detectMicrosoftBrand(document);
      if (retryBrand !== 'Unknown') {
        iocs.detectedBrand = retryBrand;
        debugLog('Brand detected on retry:', retryBrand);
        // Optionally, you could send an update to the popup here
      }
    }, 1500);
  }


  iocs.otherIOCs.allDomains.add(window.location.hostname); // Add current domain

  // 0. Preconnect
  document.querySelectorAll('link[rel="preconnect"][href]').forEach(link => {
    iocs.otherIOCs.preconnect = iocs.otherIOCs.preconnect || new Set();
    iocs.otherIOCs.preconnect.add(link.href);
    try {
      let href = link.getAttribute('href');
      let hostname = '';
      if (href.startsWith('//')) {
        hostname = href.substring(2).split('/')[0];
      } else if (href.startsWith('http')) {
        hostname = new URL(href).hostname;
      } else {
        // fallback: try to parse as https
        try { hostname = new URL('https://' + href).hostname; } catch {}
      }
      if (hostname) {
        iocs.otherIOCs.allDomains.add(hostname);
        // Always check as https for legitimacy
        let testUrl = href.startsWith('//') ? 'https:' + href : (href.startsWith('http') ? href : 'https://' + href);
        if (!isLegitimateMicrosoftRelated(testUrl)) {
          iocs.criticalIOCs.suspiciousDomains.add(hostname);
        }
      }
    } catch (e) { debugLog("Could not parse domain from preconnect: ", link.href); }
  });

  // 1. Links
  document.querySelectorAll('a[href]').forEach(a => {
    if (a.href && a.href.trim() !== '#' && !a.href.startsWith('javascript:')) {
      iocs.otherIOCs.allLinks.add(a.href);
      try {
        const url = new URL(a.href);
        iocs.otherIOCs.allDomains.add(url.hostname);
        if (!isLegitimateMicrosoftRelated(a.href)) {
          iocs.criticalIOCs.suspiciousDomains.add(url.hostname);
        }
      } catch (e) { debugLog("Could not parse domain from href: ", a.href); }
    }
  });

  // 2. Scripts
  document.querySelectorAll('script[src]').forEach(script => {
    iocs.otherIOCs.allScripts.add(script.src);
    try {
      const url = new URL(script.src);
      iocs.otherIOCs.allDomains.add(url.hostname);
      if (!isLegitimateMicrosoftRelated(script.src)) {
        iocs.criticalIOCs.suspiciousScripts.add(script.src);
        iocs.criticalIOCs.suspiciousDomains.add(url.hostname);
      }
    } catch (e) { debugLog("Could not parse domain from script src: ", script.src); }
  });

  // 3. Forms
  document.querySelectorAll('form[action]').forEach(form => {
    // Resolve action URL relative to the page's URL
    const formActionUrl = new URL(form.getAttribute('action'), window.location.href).href;
    iocs.criticalIOCs.formActions.add(formActionUrl);
    try {
      const url = new URL(formActionUrl);
      iocs.otherIOCs.allDomains.add(url.hostname);
      if (!isLegitimateMicrosoftRelated(formActionUrl)) {
        iocs.criticalIOCs.suspiciousDomains.add(url.hostname);
      }
    } catch (e) { debugLog("Could not parse domain from form action: ", formActionUrl); }
  });

  // 4. Iframes
  document.querySelectorAll('iframe[src]').forEach(iframe => {
    iocs.otherIOCs.iframes.add(iframe.src);
    try {
      const url = new URL(iframe.src);
      iocs.otherIOCs.allDomains.add(url.hostname);
      if (!isLegitimateMicrosoftRelated(iframe.src)) {
        iocs.criticalIOCs.suspiciousDomains.add(url.hostname);
      }
    } catch (e) { debugLog("Could not parse domain from iframe src: ", iframe.src); }
  });

  // 5. DNS Prefetch
  document.querySelectorAll('link[rel="dns-prefetch"][href]').forEach(link => {
    iocs.otherIOCs.dnsPrefetch.add(link.href);
    try {
      let href = link.getAttribute('href');
      let hostname = '';
      if (href.startsWith('//')) {
        hostname = href.substring(2).split('/')[0];
      } else if (href.startsWith('http')) {
        hostname = new URL(href).hostname;
      } else {
        // fallback: try to parse as https
        try { hostname = new URL('https://' + href).hostname; } catch {}
      }
      if (hostname) {
        iocs.otherIOCs.allDomains.add(hostname);
        // Always check as https for legitimacy
        let testUrl = href.startsWith('//') ? 'https:' + href : (href.startsWith('http') ? href : 'https://' + href);
        if (!isLegitimateMicrosoftRelated(testUrl)) {
          iocs.criticalIOCs.suspiciousDomains.add(hostname);
        }
      }
    } catch (e) { debugLog("Could not parse domain from dns-prefetch: ", link.href); }
  });

   // 6. Meta Redirects
  document.querySelectorAll('meta[http-equiv="refresh"]').forEach(meta => {
    const content = meta.getAttribute('content');
    if (content) {
      const match = content.match(/url=(.*)/i);
      if (match && match[1]) {
        const redirectUrl = new URL(match[1], window.location.href).href;
        iocs.otherIOCs.metaRedirects.add(redirectUrl);
        try {
          const url = new URL(redirectUrl);
          iocs.otherIOCs.allDomains.add(url.hostname);
           if (!isLegitimateMicrosoftRelated(redirectUrl)) {
            iocs.criticalIOCs.suspiciousDomains.add(url.hostname);
          }
        } catch (e) { debugLog("Could not parse domain from meta refresh: ", redirectUrl); }
      }
    }
  });

  // Convert Sets to Arrays and filter out empty strings in domains
  for (const key in iocs.criticalIOCs) {
    iocs.criticalIOCs[key] = Array.from(iocs.criticalIOCs[key]);
    // Filter out empty strings in suspiciousDomains
    if (key === 'suspiciousDomains') {
      iocs.criticalIOCs[key] = iocs.criticalIOCs[key].filter(domain => domain && domain.trim() !== '');
    }
  }
  for (const key in iocs.otherIOCs) {
    if (iocs.otherIOCs[key] instanceof Set) {
      iocs.otherIOCs[key] = Array.from(iocs.otherIOCs[key]);
    }
    // Filter out empty strings in allDomains
    if (key === 'allDomains') {
      iocs.otherIOCs[key] = iocs.otherIOCs[key].filter(domain => domain && domain.trim() !== '');
    }
  }

  debugLog("Extraction complete:", iocs);
  return iocs;
}

// Make performExtraction available to be called by popup.js
// This is simpler than message passing if the function is self-contained or uses other functions in this script.
// Ensure this is defined globally in the content script's scope.
function extractIOCs() {
  return performExtraction();
}


// --- MutationObserver for Dynamic DOM Changes ---
let domChangeTimeout = null;
const DOM_THROTTLE_MS = 1500; // Reduced throttle for faster reaction, adjust as needed

function handleDomChange(mutationsList, observer) {
  debugLog("DOM changed, re-evaluating IOCs soon...");
  clearTimeout(domChangeTimeout);
  domChangeTimeout = setTimeout(() => {
    debugLog("Re-evaluating IOCs now due to DOM change.");
    const currentIOCs = performExtraction();
    // Send IOC_UPDATE message to popup for real-time updates
    chrome.runtime.sendMessage({ type: "IOC_UPDATE", data: currentIOCs });
  }, DOM_THROTTLE_MS);
}

// Start observing the DOM for changes after the initial load
// Wait for the body to be available
if (document.body) {
    const observer = new MutationObserver(handleDomChange);
    observer.observe(document.documentElement, { // Observe the whole documentElement for broader changes
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['href', 'src', 'action'] // Observe specific attribute changes too
    });
    debugLog("MutationObserver for dynamic DOM changes initialized.");
} else {
    // Fallback if body isn't immediately available (e.g. very early script injection)
    window.addEventListener('DOMContentLoaded', () => {
        const observer = new MutationObserver(handleDomChange);
        observer.observe(document.documentElement, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ['href', 'src', 'action']
        });
        debugLog("MutationObserver initialized after DOMContentLoaded.");
    });
}
