/**
 * SafeBrowseGov — Remote blocklist management
 * 
 * Downloads and caches community phishing/malware blocklists:
 * - Phishing URL Blocklist (curbengh/phishing-filter): PhishTank + OpenPhish + phishunt.io
 * - URLhaus (abuse.ch): malware domains (optional complement)
 * 
 * All lists are free, require no API key, and are fetched in background
 * via chrome.alarms (every 6–12 hours), never per-navigation.
 * 
 * Graceful degradation: if download fails, the last known list persists.
 */

const REMOTE_BLOCKLIST_SOURCES = {
  phishing: {
    url: 'https://curbengh.github.io/phishing-filter/dist/domains.txt',
    mirrorUrl: 'https://cdn.jsdelivr.net/gh/curbengh/phishing-filter@gh-pages/dist/domains.txt',
    storageKey: 'remotePhishingDomains',
    timestampKey: 'remotePhishingTimestamp'
  },
  malware: {
    url: 'https://urlhaus.abuse.ch/downloads/hostfile/',
    storageKey: 'remoteMalwareDomains',
    timestampKey: 'remoteMalwareTimestamp'
  }
};

// In-memory Set for fast lookups (no network call per navigation)
let _remoteBlocklistSet = new Set();
let _isLoaded = false;

/**
 * Parse a text blocklist into a Set of domains.
 * Handles multiple formats: plain domain list, hosts file format.
 */
function parseBlocklist(text, format) {
  const domains = new Set();
  const lines = text.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    
    // Skip comments and empty lines
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('!') || trimmed.startsWith('//')) {
      continue;
    }

    if (format === 'hosts') {
      // Hosts file format: "127.0.0.1 domain.com" or "0.0.0.0 domain.com"
      const parts = trimmed.split(/\s+/);
      if (parts.length >= 2 && (parts[0] === '127.0.0.1' || parts[0] === '0.0.0.0')) {
        const domain = parts[1].toLowerCase();
        if (domain && domain !== 'localhost' && domain.includes('.')) {
          domains.add(domain);
        }
      }
    } else {
      // Plain domain list (one domain per line)
      const domain = trimmed.toLowerCase();
      if (domain.includes('.') && !domain.includes(' ')) {
        domains.add(domain);
      }
    }
  }

  return domains;
}

/**
 * Fetch a remote blocklist with fallback to mirror URL.
 */
async function fetchBlocklist(source, format) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000); // 30s timeout

  try {
    let response = await fetch(source.url, { signal: controller.signal });
    
    if (!response.ok && source.mirrorUrl) {
      response = await fetch(source.mirrorUrl, { signal: controller.signal });
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const text = await response.text();
    clearTimeout(timeout);
    return parseBlocklist(text, format);
  } catch (error) {
    clearTimeout(timeout);
    console.warn(`SafeBrowseGov: Failed to fetch blocklist from ${source.url}:`, error.message);
    return null;
  }
}

/**
 * Download all remote blocklists and store them.
 * Called by chrome.alarms every 6 hours.
 */
async function updateRemoteBlocklists() {
  console.log('SafeBrowseGov: Updating remote blocklists...');

  // Phishing list (main source)
  const phishingDomains = await fetchBlocklist(REMOTE_BLOCKLIST_SOURCES.phishing, 'domains');
  if (phishingDomains && phishingDomains.size > 0) {
    try {
      // Store as JSON array (Set is not serializable)
      // If too large for storage.local (5MB default), we truncate
      const domainsArray = [...phishingDomains];
      await chrome.storage.local.set({
        [REMOTE_BLOCKLIST_SOURCES.phishing.storageKey]: domainsArray,
        [REMOTE_BLOCKLIST_SOURCES.phishing.timestampKey]: Date.now()
      });
      console.log(`SafeBrowseGov: Phishing list updated — ${domainsArray.length} domains`);
    } catch (storageError) {
      // If storage quota exceeded, store a subset
      console.warn('SafeBrowseGov: Storage quota issue, storing subset:', storageError.message);
      const subset = [...phishingDomains].slice(0, 50000);
      try {
        await chrome.storage.local.set({
          [REMOTE_BLOCKLIST_SOURCES.phishing.storageKey]: subset,
          [REMOTE_BLOCKLIST_SOURCES.phishing.timestampKey]: Date.now()
        });
      } catch (e) {
        console.error('SafeBrowseGov: Cannot store phishing list:', e.message);
      }
    }
  }

  // Malware list (optional complement)
  const malwareDomains = await fetchBlocklist(REMOTE_BLOCKLIST_SOURCES.malware, 'hosts');
  if (malwareDomains && malwareDomains.size > 0) {
    try {
      const domainsArray = [...malwareDomains];
      await chrome.storage.local.set({
        [REMOTE_BLOCKLIST_SOURCES.malware.storageKey]: domainsArray,
        [REMOTE_BLOCKLIST_SOURCES.malware.timestampKey]: Date.now()
      });
      console.log(`SafeBrowseGov: Malware list updated — ${domainsArray.length} domains`);
    } catch (storageError) {
      console.warn('SafeBrowseGov: Storage quota issue for malware list:', storageError.message);
      const subset = [...malwareDomains].slice(0, 30000);
      try {
        await chrome.storage.local.set({
          [REMOTE_BLOCKLIST_SOURCES.malware.storageKey]: subset,
          [REMOTE_BLOCKLIST_SOURCES.malware.timestampKey]: Date.now()
        });
      } catch (e) {
        console.error('SafeBrowseGov: Cannot store malware list:', e.message);
      }
    }
  }

  // Rebuild in-memory Set
  await loadRemoteBlocklistIntoMemory();
}

/**
 * Load the stored blocklists into the in-memory Set for fast lookups.
 * Called at service worker startup and after each update.
 */
async function loadRemoteBlocklistIntoMemory() {
  try {
    const storage = await chrome.storage.local.get([
      REMOTE_BLOCKLIST_SOURCES.phishing.storageKey,
      REMOTE_BLOCKLIST_SOURCES.malware.storageKey
    ]);

    _remoteBlocklistSet = new Set();

    const phishing = storage[REMOTE_BLOCKLIST_SOURCES.phishing.storageKey];
    if (Array.isArray(phishing)) {
      for (const d of phishing) {
        _remoteBlocklistSet.add(d);
      }
    }

    const malware = storage[REMOTE_BLOCKLIST_SOURCES.malware.storageKey];
    if (Array.isArray(malware)) {
      for (const d of malware) {
        _remoteBlocklistSet.add(d);
      }
    }

    _isLoaded = true;
    console.log(`SafeBrowseGov: Remote blocklist loaded — ${_remoteBlocklistSet.size} domains in memory`);
  } catch (error) {
    console.warn('SafeBrowseGov: Could not load remote blocklist from storage:', error.message);
    _isLoaded = true; // Mark as loaded even on error to avoid blocking
  }
}

/**
 * Check if a domain is in the remote blocklist (in-memory, no network call).
 */
function isInRemoteBlocklist(domain) {
  return _remoteBlocklistSet.has(domain);
}

/**
 * Get the in-memory remote blocklist Set (for passing to computeRiskScore).
 */
function getRemoteBlocklistSet() {
  return _remoteBlocklistSet;
}

/**
 * Get timestamps for when each remote list was last updated.
 */
async function getRemoteBlocklistTimestamps() {
  try {
    const storage = await chrome.storage.local.get([
      REMOTE_BLOCKLIST_SOURCES.phishing.timestampKey,
      REMOTE_BLOCKLIST_SOURCES.malware.timestampKey
    ]);
    return {
      phishing: storage[REMOTE_BLOCKLIST_SOURCES.phishing.timestampKey] || null,
      malware: storage[REMOTE_BLOCKLIST_SOURCES.malware.timestampKey] || null,
      totalDomains: _remoteBlocklistSet.size
    };
  } catch (e) {
    return { phishing: null, malware: null, totalDomains: 0 };
  }
}
