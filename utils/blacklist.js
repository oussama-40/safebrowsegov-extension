/**
 * SafeBrowseGov — Rules loader
 * 
 * Loads rules.json and provides helper functions.
 * The actual data (blacklist, ad domains, etc.) is now externalized
 * in data/rules.json for versioning and easier updates.
 * 
 * This file is imported by the service worker via importScripts().
 */

// These will be populated from data/rules.json at service worker startup
let BLACKLIST = [];
let AD_DOMAINS = [];
let OFFICIAL_DOMAINS = [];
let POPULAR_DOMAINS = [];
let WHITELIST_DOMAINS = [];
let DANGEROUS_PATTERNS = [];
let RULES_VERSION = '0.0.0';
let RULES_LAST_UPDATED = '';

/**
 * Load rules from data/rules.json.
 * Must be called at service worker startup.
 */
async function loadRulesFromJSON() {
  try {
    const url = self.chrome
      ? chrome.runtime.getURL('data/rules.json')
      : './data/rules.json';
    
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const rules = await response.json();

    BLACKLIST = rules.blacklist || [];
    AD_DOMAINS = rules.adDomains || [];
    OFFICIAL_DOMAINS = rules.officialDomains || [];
    POPULAR_DOMAINS = rules.popularDomains || [];
    WHITELIST_DOMAINS = rules.whitelistDomains || [];
    DANGEROUS_PATTERNS = rules.dangerousPatterns || [];
    RULES_VERSION = rules.version || '0.0.0';
    RULES_LAST_UPDATED = rules.lastUpdated || '';

    // Also load user whitelist from storage and merge
    if (self.chrome && chrome.storage) {
      try {
        const storage = await chrome.storage.local.get(['userWhitelist']);
        const userWhitelist = storage.userWhitelist || [];
        WHITELIST_DOMAINS = [...new Set([...WHITELIST_DOMAINS, ...userWhitelist])];
      } catch (e) {
        console.warn('SafeBrowseGov: Could not load user whitelist:', e.message);
      }
    }

    console.log(`SafeBrowseGov: Rules v${RULES_VERSION} loaded — ${BLACKLIST.length} blacklisted, ${AD_DOMAINS.length} ad domains`);
    return true;
  } catch (error) {
    console.error('SafeBrowseGov: Failed to load rules.json, using defaults:', error.message);
    // Fallback: use minimal hardcoded defaults so the extension still works
    BLACKLIST = ['gov-ma.net', 'gov-ma.com', 'gov-ma.org', 'cnss-maroc.com', 'cnss-ma.net'];
    AD_DOMAINS = ['doubleclick.net', 'googlesyndication.com', 'adnxs.com', 'taboola.com', 'outbrain.com'];
    OFFICIAL_DOMAINS = ['gov.ma', 'service-public.ma', 'cnss.ma', 'ramed.ma', 'tax.gov.ma'];
    POPULAR_DOMAINS = ['google.com', 'facebook.com', 'youtube.com', 'paypal.com', 'amazon.com'];
    WHITELIST_DOMAINS = ['youtube.com', 'google.com', 'facebook.com', 'instagram.com', 'linkedin.com'];
    DANGEROUS_PATTERNS = [];
    RULES_VERSION = '0.0.0-fallback';
    RULES_LAST_UPDATED = '';
    return false;
  }
}

/**
 * Check a domain against dangerous patterns from rules.
 */
function checkDangerousPatterns(domain) {
  const builtinPatterns = [
    /\d+\..*\.(tk|ml|ga|cf)$/,
    /.*-.*-.*-.*\./,
    /.*\.(tk|ml|ga|cf|gq)$/,
    /[0-9]{3,}/,
  ];

  if (builtinPatterns.some(p => p.test(domain))) return true;

  if (DANGEROUS_PATTERNS && Array.isArray(DANGEROUS_PATTERNS)) {
    try {
      return DANGEROUS_PATTERNS.some(ps => new RegExp(ps).test(domain.toLowerCase()));
    } catch (e) {
      return false;
    }
  }

  return false;
}

/**
 * Get rules metadata for display in the popup.
 */
function getRulesInfo() {
  return {
    version: RULES_VERSION,
    lastUpdated: RULES_LAST_UPDATED,
    blacklistCount: BLACKLIST.length,
    adDomainsCount: AD_DOMAINS.length,
    officialDomainsCount: OFFICIAL_DOMAINS.length,
    popularDomainsCount: POPULAR_DOMAINS.length,
    whitelistCount: WHITELIST_DOMAINS.length
  };
}