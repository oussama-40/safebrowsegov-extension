/**
 * SafeBrowseGov v3.0 — Service Worker (background.js)
 * 
 * Architecture :
 * - Charge les règles depuis data/rules.json (via utils/blacklist.js)
 * - Charge la table de confusables depuis data/confusables.json
 * - Charge les listes distantes depuis data/remote-blocklist.js
 * - Utilise utils/scoring.js pour le calcul du score de risque
 * - Utilise utils/crypto.js pour le chiffrement de l'historique
 * 
 * NOTE : webRequest n'est PAS utilisé ici. Le blocage publicitaire est
 * géré par declarativeNetRequest (règles statiques dans rules/ad-blocking-rules.json).
 * La redirection vers blocked.html pour les menaces de phishing utilise
 * chrome.tabs.onUpdated car le score de risque est calculé dynamiquement en JS,
 * ce que declarativeNetRequest ne permet pas.
 */

importScripts('utils/scoring.js', 'utils/blacklist.js', 'utils/crypto.js', 'data/remote-blocklist.js');

// ──────────────────────────────────────────
// State
// ──────────────────────────────────────────

const BLOCKED_TABS = new Set();
const MAX_HISTORY = 100;
const ALLOW_ONCE_LIST = new Map();
const ALLOW_DURATION = 10 * 60 * 1000; // 10 minutes

let _confusablesMap = {};
let _settings = {
  adBlockEnabled: true,
  strictMode: false,
  sensitivityOffset: 0
};

// ──────────────────────────────────────────
// Initialization
// ──────────────────────────────────────────

async function initializeExtension() {
  // 1. Load rules from data/rules.json
  await loadRulesFromJSON();

  // 2. Load confusables table
  try {
    const confUrl = chrome.runtime.getURL('data/confusables.json');
    const resp = await fetch(confUrl);
    const confData = await resp.json();
    _confusablesMap = confData.map || {};
    console.log(`SafeBrowseGov: Confusables loaded — ${Object.keys(_confusablesMap).length} mappings`);
  } catch (e) {
    console.warn('SafeBrowseGov: Could not load confusables.json:', e.message);
    _confusablesMap = {};
  }

  // 3. Load remote blocklists into memory
  await loadRemoteBlocklistIntoMemory();

  // 4. Load user settings
  try {
    const storage = await chrome.storage.local.get(['adBlockEnabled', 'strictMode', 'sensitivityOffset']);
    _settings.adBlockEnabled = storage.adBlockEnabled !== false; // default true
    _settings.strictMode = storage.strictMode === true; // default false
    _settings.sensitivityOffset = storage.sensitivityOffset || 0;
  } catch (e) {
    console.warn('SafeBrowseGov: Could not load settings:', e.message);
  }

  // 5. Set up alarm for remote blocklist updates (every 6 hours)
  chrome.alarms.create('updateRemoteBlocklist', { periodInMinutes: 360 });

  // 6. Update ad blocking rules based on settings
  await updateAdBlockingRules();

  // 7. Trigger initial remote blocklist download
  updateRemoteBlocklists();

  console.log('SafeBrowseGov v3.0 initialized');
}

/**
 * Enable/disable the declarativeNetRequest ad-blocking ruleset
 * based on the adBlockEnabled setting.
 */
async function updateAdBlockingRules() {
  try {
    if (_settings.adBlockEnabled) {
      await chrome.declarativeNetRequest.updateEnabledRulesets({
        enableRulesetIds: ['ad_blocking']
      });
    } else {
      await chrome.declarativeNetRequest.updateEnabledRulesets({
        disableRulesetIds: ['ad_blocking']
      });
    }
  } catch (e) {
    console.warn('SafeBrowseGov: Could not update ad blocking rules:', e.message);
  }
}

// ──────────────────────────────────────────
// URL Analysis (using scoring module)
// ──────────────────────────────────────────

function isWhitelisted(domain) {
  return WHITELIST_DOMAINS.some(whiteDomain => {
    return domain === whiteDomain || domain.endsWith('.' + whiteDomain);
  });
}

function isTemporarilyAllowed(url) {
  const entry = ALLOW_ONCE_LIST.get(url);
  if (entry && Date.now() < entry.expiry) {
    return true;
  }
  if (entry) {
    ALLOW_ONCE_LIST.delete(url);
  }
  return false;
}

/**
 * Analyse une URL et retourne un résultat de scoring complet.
 * Remplace l'ancien analyzeUrlSync() binaire par un score continu 0–100.
 */
function analyzeUrl(url) {
  // Never block internal browser pages
  if (
    url.startsWith('chrome://') ||
    url.startsWith('chrome-extension://') ||
    url.startsWith('edge://') ||
    url.startsWith('about:')
  ) {
    return {
      score: 0,
      level: 'safe',
      threats: [],
      domain: '',
      isHttps: true,
      analyzed: true,
      timestamp: Date.now()
    };
  }

  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname.toLowerCase();
    const isHttps = urlObj.protocol === 'https:';

    // Whitelist check
    if (isWhitelisted(domain)) {
      return {
        score: 0,
        level: 'safe',
        threats: [],
        domain: domain,
        isHttps: isHttps,
        analyzed: true,
        timestamp: Date.now()
      };
    }

    // Temporary allow check
    if (isTemporarilyAllowed(url)) {
      return {
        score: 0,
        level: 'safe',
        threats: [],
        domain: domain,
        isHttps: isHttps,
        analyzed: true,
        timestamp: Date.now()
      };
    }

    // Compute risk score using the scoring module
    const result = computeRiskScore(domain, {
      isHttps,
      blacklist: BLACKLIST,
      remoteBlocklist: getRemoteBlocklistSet(),
      officialDomains: OFFICIAL_DOMAINS,
      popularDomains: POPULAR_DOMAINS,
      adDomains: AD_DOMAINS,
      confusablesMap: _confusablesMap,
      dangerousPatterns: DANGEROUS_PATTERNS,
      sensitivityOffset: _settings.sensitivityOffset
    });

    return {
      score: result.score,
      level: result.level,
      threats: result.threats,
      domain: domain,
      isHttps: isHttps,
      analyzed: true,
      timestamp: Date.now(),
      isAdDomain: result.isAdDomain
    };
  } catch (e) {
    return {
      score: 0,
      level: 'safe',
      threats: [],
      domain: '',
      isHttps: false,
      analyzed: false,
      timestamp: Date.now()
    };
  }
}

// ──────────────────────────────────────────
// Tab navigation handling
// ──────────────────────────────────────────

async function handleNavigationCheck(tabId, url) {
  if (!url || typeof url !== 'string') return;

  const blockedPagePrefix = chrome.runtime.getURL('blocked.html');
  if (
    url.startsWith('chrome://') ||
    url.startsWith('chrome-extension://') ||
    url.startsWith('edge://') ||
    url.startsWith('about:') ||
    url.startsWith(blockedPagePrefix)
  ) {
    return;
  }

  const result = analyzeUrl(url);

  if (result.level === 'blocked' || result.level === 'alert') {
    const blockUrl = blockedPagePrefix +
      '?url=' + encodeURIComponent(url) +
      '&threats=' + encodeURIComponent(JSON.stringify(result.threats)) +
      '&score=' + result.score +
      '&level=' + result.level +
      '&tabId=' + tabId;

    try {
      await chrome.tabs.update(tabId, { url: blockUrl });
      saveBlockedAlert(url, result.threats, result.score);
      saveActionHistory(url, result.level === 'blocked' ? 'BLOCKED' : 'ALERT', result.threats, result.score);
    } catch (e) {
      console.warn('SafeBrowseGov: Navigation redirect failed:', e.message);
    }
  } else if (result.level === 'warning') {
    saveActionHistory(url, 'WARNING', result.threats, result.score);
  }

  updateBadge(tabId, result);
}

// 1. Intercept BEFORE navigation starts (prior to DNS resolution / NXDOMAIN)
if (chrome.webNavigation && chrome.webNavigation.onBeforeNavigate) {
  chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId === 0) {
      handleNavigationCheck(details.tabId, details.url);
    }
  });
}

// 2. Also watch tabs onUpdated for immediate URL changes
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  const urlToCheck = changeInfo.url || (changeInfo.status === 'loading' && tab && tab.url);
  if (urlToCheck) {
    handleNavigationCheck(tabId, urlToCheck);
  } else if (changeInfo.status === 'complete' && tab && tab.url) {
    const result = analyzeUrl(tab.url);
    updateBadge(tabId, result);
  }
});

// ──────────────────────────────────────────
// Injected page content for blocked sites (fallback)
// ──────────────────────────────────────────

function blockPageContent(threats, originalUrl, tabId, score) {
  document.documentElement.innerHTML = '';

  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Site bloqué — SafeBrowseGov</title>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
          font-family: -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
          background: #0f1b2d;
          color: white;
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          text-align: center;
        }
        .container {
          background: rgba(255,255,255,0.06);
          padding: 40px;
          border-radius: 14px;
          max-width: 600px;
          width: 90%;
          border: 1px solid rgba(255,255,255,0.15);
        }
        h1 { font-size: 28px; margin-bottom: 20px; color: #fff; }
        .score-display {
          font-size: 48px;
          font-weight: 700;
          margin: 20px 0;
          color: ${score >= 80 ? '#ef4444' : score >= 60 ? '#f59e0b' : '#10b981'};
        }
        .score-bar {
          height: 8px;
          background: rgba(255,255,255,0.1);
          border-radius: 4px;
          margin: 10px 0 20px;
          overflow: hidden;
        }
        .score-fill {
          height: 100%;
          width: ${score}%;
          border-radius: 4px;
          background: ${score >= 80 ? '#ef4444' : score >= 60 ? '#f59e0b' : '#10b981'};
        }
        .url {
          background: rgba(255,255,255,0.1);
          padding: 15px;
          border-radius: 8px;
          margin: 20px 0;
          word-break: break-all;
          font-family: monospace;
          border: 1px solid rgba(255,255,255,0.3);
        }
        .threats {
          background: rgba(239,68,68,0.2);
          padding: 20px;
          border-radius: 8px;
          margin: 20px 0;
          border: 1px solid #ef4444;
        }
        .threat-item {
          background: #ef4444;
          color: white;
          padding: 8px 15px;
          margin: 5px;
          border-radius: 20px;
          display: inline-block;
          font-size: 14px;
          font-weight: bold;
        }
        .buttons {
          margin-top: 30px;
          display: flex;
          gap: 15px;
          justify-content: center;
          flex-wrap: wrap;
        }
        button {
          padding: 12px 25px;
          border: none;
          border-radius: 8px;
          font-size: 16px;
          font-weight: bold;
          cursor: pointer;
          transition: all 0.3s;
        }
        .btn-safe { background: #10b981; color: white; }
        .btn-safe:hover { background: #059669; }
        .btn-danger { background: transparent; color: white; border: 2px solid white; }
        .btn-danger:hover { background: white; color: #dc2626; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Site bloqué par SafeBrowseGov</h1>
        <div class="score-display">${score}/100</div>
        <div class="score-bar"><div class="score-fill"></div></div>
        <p style="font-size: 14px; margin-bottom: 20px; color: #cbd5e1;">
          Score de risque : ${score >= 80 ? 'Critique' : score >= 60 ? 'Élevé' : 'Modéré'}
        </p>
        <div class="url">
          <strong>URL bloquée :</strong><br>
          ${originalUrl}
        </div>
        <div class="threats">
          <h3 style="margin-bottom: 15px;">Menaces détectées</h3>
          ${threats.map(t => '<span class="threat-item">' + t + '</span>').join('')}
        </div>
        <div class="buttons">
          <button class="btn-safe" id="go-back-safe-btn">Retour sécurisé</button>
          <button class="btn-danger" id="continue-anyway-btn">Continuer malgré le risque</button>
        </div>
      </div>
      <script>
        document.getElementById('go-back-safe-btn').addEventListener('click', function() {
          chrome.runtime.sendMessage({
            action: 'goBackSafe',
            url: '${originalUrl}',
            tabId: ${tabId}
          });
        });
        document.getElementById('continue-anyway-btn').addEventListener('click', function() {
          if (confirm('Ce site reste potentiellement dangereux. Voulez-vous vraiment continuer ?')) {
            chrome.runtime.sendMessage({
              action: 'allowOnce',
              url: '${originalUrl}',
              tabId: ${tabId}
            });
          }
        });
        history.pushState(null, null, location.href);
        window.onpopstate = function() { history.go(1); };
      </script>
    </body>
    </html>
  `;

  document.documentElement.innerHTML = html;
  document.title = 'Site bloqué — SafeBrowseGov';
}

// ──────────────────────────────────────────
// Badge
// ──────────────────────────────────────────

function updateBadge(tabId, result) {
  try {
    if (result.level === 'blocked') {
      chrome.action.setBadgeText({ text: 'X', tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#b3261e', tabId });
    } else if (result.level === 'alert') {
      chrome.action.setBadgeText({ text: '!!', tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#b3261e', tabId });
    } else if (result.level === 'warning') {
      chrome.action.setBadgeText({ text: '!', tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#9a5b00', tabId });
    } else {
      chrome.action.setBadgeText({ text: '', tabId });
    }
  } catch (e) {
    // Tab may have been closed
  }
}

// ──────────────────────────────────────────
// History & storage
// ──────────────────────────────────────────

async function saveBlockedAlert(url, threats, score) {
  try {
    const alertData = {
      url: url,
      domain: new URL(url).hostname,
      threats: threats,
      score: score,
      timestamp: Date.now(),
      blocked: true,
      type: 'SITE_BLOQUE',
      dateString: new Date().toLocaleString('fr-FR')
    };

    const encrypted = await encryptData(JSON.stringify(alertData));

    const storage = await chrome.storage.local.get(['blockedHistory', 'alerts']);
    let history = storage.blockedHistory || [];
    let alerts = storage.alerts || [];

    history.unshift(encrypted);
    alerts.unshift(encrypted);

    if (history.length > MAX_HISTORY) {
      history = history.slice(0, MAX_HISTORY);
    }
    if (alerts.length > MAX_HISTORY) {
      alerts = alerts.slice(0, MAX_HISTORY);
    }

    await chrome.storage.local.set({
      blockedHistory: history,
      alerts: alerts
    });

    // Update counters
    try {
      const stats = await chrome.storage.local.get(['blockedCount', 'alertCount']);
      const blockedCount = (stats.blockedCount || 0) + 1;
      const alertCount = (stats.alertCount || 0) + 1;
      await chrome.storage.local.set({ blockedCount, alertCount });
    } catch (e) {
      console.warn('SafeBrowseGov: Counter update error:', e);
    }

  } catch (error) {
    console.error('SafeBrowseGov: Alert save error:', error);

    // Fallback: save unencrypted
    try {
      const simpleAlert = {
        url: url,
        domain: new URL(url).hostname,
        threats: threats,
        score: score,
        timestamp: Date.now(),
        blocked: true
      };

      const storage = await chrome.storage.local.get(['blockedHistory']);
      const history = storage.blockedHistory || [];
      history.unshift(simpleAlert);

      if (history.length > MAX_HISTORY) {
        history.splice(MAX_HISTORY);
      }

      await chrome.storage.local.set({ blockedHistory: history });
    } catch (fallbackError) {
      console.error('SafeBrowseGov: Fallback save error:', fallbackError);
    }
  }
}

async function saveActionHistory(url, action, threats = [], score = 0) {
  try {
    const actionData = {
      url: url,
      domain: new URL(url).hostname,
      action: action,
      threats: threats,
      score: score,
      timestamp: Date.now(),
      dateString: new Date().toLocaleString('fr-FR')
    };

    const storage = await chrome.storage.local.get(['actionHistory']);
    let history = storage.actionHistory || [];
    history.unshift(actionData);

    if (history.length > MAX_HISTORY) {
      history = history.slice(0, MAX_HISTORY);
    }

    await chrome.storage.local.set({ actionHistory: history });
  } catch (error) {
    console.error('SafeBrowseGov: Action history save error:', error);
  }
}

async function getBlockedHistory() {
  try {
    const storage = await chrome.storage.local.get(['blockedHistory']);
    const history = storage.blockedHistory || [];

    const decryptedHistory = [];
    for (const item of history) {
      try {
        if (typeof item === 'string') {
          const decrypted = await decryptData(item);
          decryptedHistory.push(JSON.parse(decrypted));
        } else {
          decryptedHistory.push(item);
        }
      } catch (e) {
        console.warn('SafeBrowseGov: Decryption error for history item:', e);
      }
    }

    return decryptedHistory;
  } catch (error) {
    console.error('SafeBrowseGov: History retrieval error:', error);
    return [];
  }
}

async function cleanOldHistory() {
  try {
    const history = await getBlockedHistory();
    const oneWeekAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
    const recentHistory = history.filter(item => item.timestamp > oneWeekAgo);

    if (recentHistory.length !== history.length) {
      const encryptedHistory = [];
      for (const item of recentHistory) {
        const encrypted = await encryptData(JSON.stringify(item));
        encryptedHistory.push(encrypted);
      }

      await chrome.storage.local.set({ blockedHistory: encryptedHistory });
      console.log('SafeBrowseGov: History cleaned,', recentHistory.length, 'items kept');
    }
  } catch (error) {
    console.error('SafeBrowseGov: History cleanup error:', error);
  }
}

// ──────────────────────────────────────────
// Navigation handlers
// ──────────────────────────────────────────

async function handleGoBackSafe(url, tabId) {
  try {
    await saveActionHistory(url, 'RETOUR_SECURISE');
    BLOCKED_TABS.delete(tabId);
    const tabs = await chrome.tabs.query({ currentWindow: true });
    if (tabs.length > 1) {
      await chrome.tabs.remove(tabId);
      const prevTab = tabs.find(t => t.id !== tabId && !t.url.includes('blocked.html'));
      if (prevTab) {
        await chrome.tabs.update(prevTab.id, { active: true });
      } else {
        await chrome.tabs.update(tabs[tabs.length - 2].id, { active: true });
      }
    } else {
      await chrome.tabs.update(tabId, { url: 'chrome://newtab/' });
    }
  } catch (error) {
    console.error('SafeBrowseGov: Go back safe error:', error);
    try {
      await chrome.tabs.update(tabId, { url: 'chrome://newtab/' });
    } catch (fallbackError) {
      console.error('SafeBrowseGov: Fallback go back error:', fallbackError);
    }
  }
}

async function handleAllowOnce(url, tabId) {
  try {
    const expiry = Date.now() + ALLOW_DURATION;
    ALLOW_ONCE_LIST.set(url, { expiry: expiry });

    setTimeout(() => {
      ALLOW_ONCE_LIST.delete(url);
    }, ALLOW_DURATION);

    await saveActionHistory(url, 'CONTINUER_MALGRE_RISQUE');
    BLOCKED_TABS.delete(tabId);
    await chrome.tabs.update(tabId, { url: url });
  } catch (error) {
    console.error('SafeBrowseGov: Allow once error:', error);
    try {
      await chrome.tabs.update(tabId, { url: 'chrome://newtab/' });
    } catch (fallbackError) {
      console.error('SafeBrowseGov: Allow once fallback error:', fallbackError);
    }
  }
}

// ──────────────────────────────────────────
// False positive reporting (Task 13)
// ──────────────────────────────────────────

async function saveFalsePositiveReport(domain, score, reportType) {
  try {
    const reportData = {
      domain: domain,
      score: score,
      reportType: reportType, // 'false_positive' or 'false_negative'
      timestamp: Date.now(),
      dateString: new Date().toLocaleString('fr-FR')
    };

    const encrypted = await encryptData(JSON.stringify(reportData));

    const storage = await chrome.storage.local.get(['falsePositiveReports']);
    let reports = storage.falsePositiveReports || [];
    reports.unshift(encrypted);

    if (reports.length > MAX_HISTORY) {
      reports = reports.slice(0, MAX_HISTORY);
    }

    await chrome.storage.local.set({ falsePositiveReports: reports });
    return true;
  } catch (error) {
    console.error('SafeBrowseGov: Report save error:', error);
    return false;
  }
}

// ──────────────────────────────────────────
// Alarms
// ──────────────────────────────────────────

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'updateRemoteBlocklist') {
    await updateRemoteBlocklists();
  }
});

// ──────────────────────────────────────────
// Event listeners
// ──────────────────────────────────────────

chrome.runtime.onStartup.addListener(() => {
  initializeExtension();
  cleanOldHistory();
});

chrome.runtime.onInstalled.addListener(() => {
  console.log('SafeBrowseGov v3.0 installed — Initializing...');
  initializeExtension();
  cleanOldHistory();
});

chrome.tabs.onRemoved.addListener((tabId) => {
  BLOCKED_TABS.delete(tabId);
});

// Listen for settings changes
chrome.storage.onChanged.addListener(async (changes, area) => {
  if (area === 'local') {
    if (changes.adBlockEnabled !== undefined) {
      _settings.adBlockEnabled = changes.adBlockEnabled.newValue !== false;
      await updateAdBlockingRules();
    }
    if (changes.strictMode !== undefined) {
      _settings.strictMode = changes.strictMode.newValue === true;
    }
    if (changes.sensitivityOffset !== undefined) {
      _settings.sensitivityOffset = changes.sensitivityOffset.newValue || 0;
    }
    if (changes.userWhitelist !== undefined) {
      // Reload whitelist
      const userWhitelist = changes.userWhitelist.newValue || [];
      // Re-merge with default whitelist from rules
      try {
        const url = chrome.runtime.getURL('data/rules.json');
        const resp = await fetch(url);
        const rules = await resp.json();
        WHITELIST_DOMAINS = [...new Set([...(rules.whitelistDomains || []), ...userWhitelist])];
      } catch (e) {
        WHITELIST_DOMAINS = [...new Set([...WHITELIST_DOMAINS, ...userWhitelist])];
      }
    }
  }
});

// ──────────────────────────────────────────
// Message handlers
// ──────────────────────────────────────────

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getBlockedHistory') {
    getBlockedHistory().then(history => {
      sendResponse({ success: true, history: history });
    }).catch(error => {
      sendResponse({ success: false, error: error.message });
    });
    return true;
  }

  if (request.action === 'clearHistory') {
    chrome.storage.local.set({
      blockedHistory: [],
      alerts: [],
      actionHistory: [],
      blockedCount: 0,
      alertCount: 0
    }).then(() => {
      sendResponse({ success: true });
    }).catch(error => {
      sendResponse({ success: false, error: error.message });
    });
    return true;
  }

  if (request.action === 'goBackSafe') {
    let tabId = request.tabId;
    if (!tabId && sender.tab && sender.tab.id) {
      tabId = sender.tab.id;
    }
    if (!tabId) {
      sendResponse({ success: false, error: 'No tabId' });
      return true;
    }
    handleGoBackSafe(request.url, tabId).then(() => {
      sendResponse({ success: true });
    }).catch(error => {
      sendResponse({ success: false, error: error.message });
    });
    return true;
  }

  if (request.action === 'allowOnce') {
    let tabId = request.tabId;
    if (!tabId && sender.tab && sender.tab.id) {
      tabId = sender.tab.id;
    }
    if (!tabId) {
      sendResponse({ success: false, error: 'No tabId' });
      return true;
    }
    handleAllowOnce(request.url, tabId).then(() => {
      sendResponse({ success: true });
    }).catch(error => {
      sendResponse({ success: false, error: error.message });
    });
    return true;
  }

  if (request.action === 'getActionHistory') {
    chrome.storage.local.get(['actionHistory']).then(storage => {
      sendResponse({ success: true, history: storage.actionHistory || [] });
    }).catch(error => {
      sendResponse({ success: false, error: error.message });
    });
    return true;
  }

  if (request.action === 'analyzeCurrentUrl') {
    const result = analyzeUrl(request.url);
    sendResponse({ success: true, result: result });
    return true;
  }

  if (request.action === 'getRulesInfo') {
    const info = getRulesInfo();
    getRemoteBlocklistTimestamps().then(timestamps => {
      sendResponse({
        success: true,
        rules: info,
        remote: timestamps
      });
    }).catch(() => {
      sendResponse({ success: true, rules: info, remote: { phishing: null, malware: null, totalDomains: 0 } });
    });
    return true;
  }

  if (request.action === 'reportFalsePositive') {
    saveFalsePositiveReport(
      request.domain,
      request.score,
      request.reportType || 'false_positive'
    ).then(success => {
      sendResponse({ success });
    }).catch(error => {
      sendResponse({ success: false, error: error.message });
    });
    return true;
  }

  if (request.action === 'getFalsePositiveReports') {
    chrome.storage.local.get(['falsePositiveReports']).then(async (storage) => {
      const reports = storage.falsePositiveReports || [];
      const decrypted = [];
      for (const item of reports) {
        try {
          if (typeof item === 'string') {
            const d = await decryptData(item);
            decrypted.push(JSON.parse(d));
          } else {
            decrypted.push(item);
          }
        } catch (e) {
          // Skip corrupted entries
        }
      }
      sendResponse({ success: true, reports: decrypted });
    }).catch(error => {
      sendResponse({ success: false, error: error.message });
    });
    return true;
  }

  if (request.action === 'clearFalsePositiveReports') {
    chrome.storage.local.set({ falsePositiveReports: [] }).then(() => {
      sendResponse({ success: true });
    }).catch(error => {
      sendResponse({ success: false, error: error.message });
    });
    return true;
  }

  if (request.action === 'getSettings') {
    chrome.storage.local.get(['adBlockEnabled', 'strictMode', 'sensitivityOffset', 'userWhitelist']).then(storage => {
      sendResponse({
        success: true,
        settings: {
          adBlockEnabled: storage.adBlockEnabled !== false,
          strictMode: storage.strictMode === true,
          sensitivityOffset: storage.sensitivityOffset || 0,
          userWhitelist: storage.userWhitelist || []
        }
      });
    }).catch(error => {
      sendResponse({ success: false, error: error.message });
    });
    return true;
  }

  if (request.action === 'getAdsBlockedCount') {
    // Return the count from content script via tab execution
    if (request.tabId) {
      chrome.scripting.executeScript({
        target: { tabId: request.tabId },
        func: () => window.__adsBlockedCount || 0
      }).then(results => {
        sendResponse({ success: true, count: results[0]?.result || 0 });
      }).catch(() => {
        sendResponse({ success: true, count: 0 });
      });
    } else {
      sendResponse({ success: true, count: 0 });
    }
    return true;
  }
});