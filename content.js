/**
 * SafeBrowseGov v3.0 — Content Script
 * 
 * Ce script s'exécute dans chaque page web visitée.
 * 
 * Mode par défaut (non agressif) :
 * - Supprime les éléments publicitaires (AD_SELECTORS) du DOM
 * - Bloque les popups provenant de domaines publicitaires connus
 * - Bloque les redirections vers des domaines dangereux
 * - N'interfère PAS avec la navigation normale
 * 
 * Mode strict (activé dans les options) :
 * - Bloque tous les window.open
 * - Bloque tous les liens target="_blank"
 * - Bloque toutes les redirections JavaScript
 * - Comportement agressif de la v2.0
 * 
 * NOTE : Le blocage réseau des publicités est géré par declarativeNetRequest
 * dans le manifest (règles statiques). Ce content script ne fait que le
 * nettoyage DOM côté client.
 */

window.__adsBlockedCount = 0;

// ──────────────────────────────────────────
// Ad element selectors (DOM cleanup only)
// ──────────────────────────────────────────

const AD_SELECTORS = [
  // Ad iframes
  'iframe[src*="doubleclick" i]',
  'iframe[src*="googlesyndication" i]',
  'iframe[src*="adservice" i]',
  'iframe[src*="taboola" i]',
  'iframe[src*="outbrain" i]',
  'iframe[src*="adnxs" i]',
  'iframe[src*="zedo" i]',
  'iframe[src*="revcontent" i]',
  'iframe[src*="popads" i]',
  'iframe[src*="propellerads" i]',

  // Known ad containers
  'div[id*="google_ads" i]',
  'div[class*="google_ads" i]',
  'div[id*="advertisement" i]',
  'div[class*="advertisement" i]',
  'ins.adsbygoogle',
  '[data-ad-slot]',
  '[data-ad-client]',
  '[data-adunit]',

  // Common ad class patterns (specific enough to avoid false positives)
  '[class*="doubleclick" i]',
  '[class*="googleads" i]',
  '[class*="popunder" i]',
  '[id*="popunder" i]'
];

// Known ad domains for popup/redirect blocking
const AD_DOMAIN_PATTERNS = [
  'doubleclick.net',
  'googlesyndication.com',
  'adservice.google.com',
  'adnxs.com',
  'taboola.com',
  'outbrain.com',
  'zedo.com',
  'revcontent.com',
  'popads.net',
  'propellerads.com',
  'adform.net',
  'advertising.com',
  'adroll.com',
  'adsafeprotected.com'
];

// ──────────────────────────────────────────
// Settings
// ──────────────────────────────────────────

let _contentSettings = {
  adBlockEnabled: true,
  strictMode: false
};

// Load settings from storage
function loadContentSettings() {
  if (typeof chrome !== 'undefined' && chrome.storage) {
    chrome.storage.local.get(['adBlockEnabled', 'strictMode'], (result) => {
      _contentSettings.adBlockEnabled = result.adBlockEnabled !== false;
      _contentSettings.strictMode = result.strictMode === true;
      initContentScript();
    });

    // Listen for settings changes
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === 'local') {
        if (changes.adBlockEnabled !== undefined) {
          _contentSettings.adBlockEnabled = changes.adBlockEnabled.newValue !== false;
        }
        if (changes.strictMode !== undefined) {
          _contentSettings.strictMode = changes.strictMode.newValue === true;
        }
      }
    });
  } else {
    initContentScript();
  }
}

// ──────────────────────────────────────────
// DOM ad removal (safe, non-destructive)
// ──────────────────────────────────────────

function removeAds() {
  if (!_contentSettings.adBlockEnabled) return;

  let removed = 0;
  AD_SELECTORS.forEach(selector => {
    try {
      const elements = document.querySelectorAll(selector);
      elements.forEach(el => {
        el.remove();
        removed++;
      });
    } catch (e) {
      // Ignore selector errors
    }
  });

  if (removed > 0) {
    window.__adsBlockedCount += removed;
  }
}

// ──────────────────────────────────────────
// Targeted popup/redirect blocking (default mode)
// ──────────────────────────────────────────

/**
 * Checks if a URL belongs to a known ad domain.
 */
function isAdUrl(url) {
  if (!url || typeof url !== 'string') return false;
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    return AD_DOMAIN_PATTERNS.some(adDomain =>
      hostname === adDomain || hostname.endsWith('.' + adDomain)
    );
  } catch (e) {
    return false;
  }
}

/**
 * Block window.open calls only from ad domains.
 * Normal window.open calls are allowed in default mode.
 */
function blockAdPopups() {
  const originalOpen = window.open;
  window.open = function(url) {
    if (_contentSettings.strictMode) {
      console.log('SafeBrowseGov [strict]: window.open blocked');
      return null;
    }

    if (url && isAdUrl(url)) {
      console.log('SafeBrowseGov: Ad popup blocked:', url);
      window.__adsBlockedCount++;
      return null;
    }

    return originalOpen.apply(this, arguments);
  };
}

/**
 * Block suspicious iframes from ad domains.
 */
function blockSuspiciousIframes() {
  if (!_contentSettings.adBlockEnabled) return;

  const iframes = document.querySelectorAll('iframe');
  iframes.forEach(iframe => {
    const src = iframe.src || '';
    if (src && isAdUrl(src)) {
      iframe.remove();
      window.__adsBlockedCount++;
    }
  });
}

/**
 * Block suspicious scripts from ad domains.
 */
function blockSuspiciousScripts() {
  if (!_contentSettings.adBlockEnabled) return;

  const scripts = document.querySelectorAll('script[src]');
  scripts.forEach(script => {
    const src = script.src || '';
    if (src && isAdUrl(src)) {
      script.remove();
      window.__adsBlockedCount++;
    }
  });
}

// ──────────────────────────────────────────
// Strict mode functions (only active when user enables strict mode)
// ──────────────────────────────────────────

function enableStrictMode() {
  // Block ALL window.open (already handled in blockAdPopups via strictMode flag)

  // Block ALL target="_blank" links
  document.addEventListener('click', function(e) {
    const target = e.target.closest('a[target="_blank"]');
    if (target) {
      e.preventDefault();
      e.stopPropagation();
      console.log('SafeBrowseGov [strict]: target="_blank" blocked');
      return false;
    }

    // Block onclick with window.open or location changes
    const onclick = e.target.getAttribute && e.target.getAttribute('onclick');
    if (onclick && (onclick.includes('window.open') || onclick.includes('location.href') ||
        onclick.includes('window.location'))) {
      e.preventDefault();
      e.stopPropagation();
      console.log('SafeBrowseGov [strict]: onclick redirect blocked');
      return false;
    }
  }, true);

  // Block string-based setTimeout/setInterval (eval-like patterns)
  const originalSetTimeout = window.setTimeout;
  window.setTimeout = function(func, delay) {
    if (typeof func === 'string' &&
        (func.includes('window.open') || func.includes('location.href') ||
         func.includes('window.location'))) {
      console.log('SafeBrowseGov [strict]: setTimeout string eval blocked');
      return 0;
    }
    return originalSetTimeout.call(this, func, delay);
  };

  const originalSetInterval = window.setInterval;
  window.setInterval = function(func, delay) {
    if (typeof func === 'string' &&
        (func.includes('window.open') || func.includes('location.href') ||
         func.includes('window.location'))) {
      console.log('SafeBrowseGov [strict]: setInterval string eval blocked');
      return 0;
    }
    return originalSetInterval.call(this, func, delay);
  };

  console.log('SafeBrowseGov: Strict mode enabled');
}

// ──────────────────────────────────────────
// Heuristic site detection (non-blocking, informational)
// ──────────────────────────────────────────

function detectMaliciousSiteHeuristics() {
  let score = 0;
  const html = document.documentElement.innerHTML.toLowerCase();
  const patterns = [
    /mot de passe|password|passwort|senha|contraseña|пароль|رمز عبور/,
    /login|connexion|sign in|se connecter|authentification/,
    /paypal|crypto|bitcoin|wallet|banque|bank|visa|mastercard|carte bancaire/,
    /document\.write|eval\(|atob\(|unescape\(|fromcharcode\(/,
    /form[^>]+action=["'][^"']*(php|asp|cgi|exe|bin|dll)/,
    /src=["'][^"']*(malware|virus|stealer|phish|scam|hack)/,
    /free gift|win iphone|click here|urgent|limited offer|offre limitée|cadeau gratuit/
  ];
  patterns.forEach((re) => { if (re.test(html)) score++; });

  // Many external links = suspect
  const links = Array.from(document.querySelectorAll('a[href]'));
  const extLinks = links.filter(a => a.hostname && a.hostname !== location.hostname);
  if (extLinks.length > 10) score++;

  // If high score, send info to background (don't use alert() — too disruptive)
  if (score >= 3) {
    try {
      chrome.runtime.sendMessage({
        action: 'heuristicWarning',
        url: window.location.href,
        score: score
      });
    } catch (e) {
      // Extension context may not be available
    }
  }
}

// ──────────────────────────────────────────
// Initialization
// ──────────────────────────────────────────

function initContentScript() {
  // Only proceed if we have a document body
  if (!document.body) return;

  // Ad popup blocking (always active, targeted by default)
  blockAdPopups();

  if (_contentSettings.adBlockEnabled) {
    // DOM cleanup
    blockSuspiciousIframes();
    blockSuspiciousScripts();
    removeAds();

    // Observe new elements added to the DOM
    const observer = new MutationObserver(function(mutations) {
      let hasNewNodes = false;
      for (const mutation of mutations) {
        if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
          hasNewNodes = true;
          break;
        }
      }
      if (hasNewNodes) {
        removeAds();
        blockSuspiciousIframes();
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  // Enable strict mode if the user has opted in
  if (_contentSettings.strictMode) {
    enableStrictMode();
  }

  // Heuristic detection (non-blocking, informational only)
  detectMaliciousSiteHeuristics();

  console.log('SafeBrowseGov: Content script initialized' +
    (_contentSettings.strictMode ? ' [strict mode]' : '') +
    (_contentSettings.adBlockEnabled ? ' [ad blocking on]' : ' [ad blocking off]'));
}

// Start
loadContentSettings();