/**
 * SafeBrowseGov v3.0 — Popup Controller
 * 
 * Manages the extension popup UI:
 * - Active tab risk score and threats
 * - Protection statistics (blocked, alerts, ads)
 * - Decrypted alert history with export
 * - False positive reporting for current site
 * - Navigation to options & privacy
 */

let _currentTabDomain = '';
let _currentTabScore = 0;

document.addEventListener('DOMContentLoaded', async () => {
  await Promise.all([
    updateStats(),
    loadCurrentTab(),
    loadAlerts(),
    loadRulesInfo()
  ]);

  // Event listeners with robust error handling
  document.getElementById('clear-history').addEventListener('click', clearHistory);
  document.getElementById('export-history').addEventListener('click', exportHistory);
  document.getElementById('report-fp-btn').addEventListener('click', reportCurrentSiteFP);

  // Settings & Privacy links
  document.getElementById('open-settings').addEventListener('click', (e) => {
    e.preventDefault();
    if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else {
      window.open(chrome.runtime.getURL('options.html'));
    }
  });

  document.getElementById('open-privacy').addEventListener('click', (e) => {
    e.preventDefault();
    chrome.tabs.create({ url: chrome.runtime.getURL('options.html#privacy') });
  });
});

/**
 * Load and analyze the active tab
 */
async function loadCurrentTab() {
  const urlEl = document.getElementById('current-url');
  const statusEl = document.getElementById('status');
  const threatsEl = document.getElementById('current-threats');
  const meterContainer = document.getElementById('risk-meter-container');
  const scoreVal = document.getElementById('risk-score-value');
  const scoreFill = document.getElementById('risk-score-fill');
  const progressBar = document.getElementById('risk-progress-bar');

  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const tab = tabs[0];

    if (!tab || !tab.url) {
      urlEl.textContent = 'Aucun onglet actif';
      statusEl.textContent = 'Inactif';
      statusEl.className = 'status-pill status-safe';
      return;
    }

    if (
      tab.url.startsWith('chrome://') ||
      tab.url.startsWith('chrome-extension://') ||
      tab.url.startsWith('edge://') ||
      tab.url.startsWith('about:')
    ) {
      urlEl.textContent = 'Page interne du navigateur';
      statusEl.textContent = 'Protégé';
      statusEl.className = 'status-pill status-safe';
      meterContainer.style.display = 'none';
      return;
    }

    const urlObj = new URL(tab.url);
    _currentTabDomain = urlObj.hostname;
    urlEl.textContent = _currentTabDomain;

    // Request analysis from service worker
    chrome.runtime.sendMessage({ action: 'analyzeCurrentUrl', url: tab.url }, (response) => {
      if (chrome.runtime.lastError || !response || !response.success) {
        // Fallback to checking badge
        chrome.action.getBadgeText({ tabId: tab.id }).then(badge => {
          if (badge === 'X' || badge === '!!') {
            statusEl.textContent = 'Menace';
            statusEl.className = 'status-pill status-danger';
          } else if (badge === '!') {
            statusEl.textContent = 'Avertissement';
            statusEl.className = 'status-pill status-warn';
          } else {
            statusEl.textContent = 'Sécurisé';
            statusEl.className = 'status-pill status-safe';
          }
        }).catch(() => {});
        return;
      }

      const res = response.result;
      _currentTabScore = res.score;

      // Show risk meter
      meterContainer.style.display = 'block';
      scoreVal.textContent = `${res.score} / 100`;
      scoreFill.style.width = `${Math.min(100, Math.max(0, res.score))}%`;
      progressBar.setAttribute('aria-valuenow', res.score);

      // Classes based on risk score / level
      scoreFill.className = 'risk-meter-fill ' + (
        res.level === 'blocked' ? 'blocked' :
        res.level === 'alert' ? 'alert' :
        res.level === 'warning' ? 'warn' : 'safe'
      );

      if (res.level === 'blocked') {
        statusEl.textContent = 'Bloqué';
        statusEl.className = 'status-pill status-danger';
      } else if (res.level === 'alert') {
        statusEl.textContent = 'Risque élevé';
        statusEl.className = 'status-pill status-danger';
      } else if (res.level === 'warning') {
        statusEl.textContent = 'Suspect';
        statusEl.className = 'status-pill status-warn';
      } else {
        statusEl.textContent = 'Sécurisé';
        statusEl.className = 'status-pill status-safe';
      }

      // Threats display
      if (res.threats && res.threats.length > 0) {
        threatsEl.innerHTML = res.threats.map(t =>
          `<div class="threat">${escapeHtml(t)}</div>`
        ).join('');
      } else {
        threatsEl.innerHTML = '';
      }
    });

    // Update ads blocked count for current tab
    chrome.runtime.sendMessage({ action: 'getAdsBlockedCount', tabId: tab.id }, (resp) => {
      if (resp && resp.success) {
        document.getElementById('ads-blocked-count').textContent = resp.count || 0;
      }
    });

  } catch (e) {
    console.error('SafeBrowseGov: Error loading tab:', e);
    urlEl.textContent = 'Erreur de lecture';
  }
}

/**
 * Update global statistics
 */
async function updateStats() {
  try {
    const stats = await chrome.storage.local.get(['blockedCount', 'alertCount']);
    document.getElementById('blocked-count').textContent = stats.blockedCount || 0;
    document.getElementById('alert-count').textContent = stats.alertCount || 0;
  } catch (e) {
    document.getElementById('blocked-count').textContent = '0';
    document.getElementById('alert-count').textContent = '0';
  }
}

/**
 * Load rules version and remote lists info
 */
async function loadRulesInfo() {
  const rulesEl = document.getElementById('rules-info');
  chrome.runtime.sendMessage({ action: 'getRulesInfo' }, (response) => {
    if (chrome.runtime.lastError || !response || !response.success) {
      rulesEl.textContent = 'Règles : v3.0.0 • Protection active';
      return;
    }

    const { rules, remote } = response;
    const versionStr = rules ? `v${rules.version}` : 'v3.0.0';
    const remoteCount = remote && remote.totalDomains ? `${remote.totalDomains.toLocaleString('fr-FR')} domaines distants` : 'Listes distantes actives';
    rulesEl.textContent = `Règles ${versionStr} • ${remoteCount}`;
  });
}

/**
 * Load and decrypt recent alerts
 */
async function loadAlerts() {
  const listEl = document.getElementById('alerts-list');
  try {
    const data = await chrome.storage.local.get(['alerts']);
    const alerts = data.alerts || [];

    if (alerts.length === 0) {
      listEl.innerHTML = '<div class="no-alerts">Aucune alerte récente</div>';
      return;
    }

    const alertsHtml = await Promise.all(
      alerts.slice(0, 5).map(async (encrypted) => {
        try {
          let alertObj;
          if (typeof encrypted === 'string') {
            const decrypted = await decryptData(encrypted);
            alertObj = JSON.parse(decrypted);
          } else {
            alertObj = encrypted;
          }

          const date = new Date(alertObj.timestamp).toLocaleDateString('fr-FR', {
            hour: '2-digit',
            minute: '2-digit',
            day: 'numeric',
            month: 'short'
          });

          const threatsHtml = (alertObj.threats || [])
            .map(t => `<span class="threat-tag">${escapeHtml(t)}</span>`)
            .join('');

          const scoreBadge = alertObj.score !== undefined
            ? `<span class="threat-score-pill">Score: ${alertObj.score}</span>`
            : '';

          return `
            <div class="alert-item">
              <div class="alert-item-header">
                <span class="alert-domain">${escapeHtml(alertObj.domain || '')}</span>
                ${scoreBadge}
              </div>
              <div class="alert-threats">${threatsHtml}</div>
              <div class="alert-date">${date}</div>
            </div>
          `;
        } catch (e) {
          return '<div class="alert-item error">Erreur de lecture de l\'alerte</div>';
        }
      })
    );

    listEl.innerHTML = alertsHtml.join('');
  } catch (e) {
    console.error('SafeBrowseGov: Error loading alerts:', e);
    listEl.innerHTML = '<div class="error">Erreur lors du chargement des alertes</div>';
  }
}

/**
 * Report current site as false positive
 */
async function reportCurrentSiteFP() {
  const btn = document.getElementById('report-fp-btn');
  const feedback = document.getElementById('fp-feedback');

  if (!_currentTabDomain) {
    feedback.textContent = 'Aucun domaine actif à signaler.';
    feedback.style.display = 'block';
    feedback.className = 'fp-feedback warn';
    return;
  }

  try {
    btn.disabled = true;
    btn.textContent = 'Signalement…';

    const resp = await new Promise((resolve) => {
      chrome.runtime.sendMessage({
        action: 'reportFalsePositive',
        domain: _currentTabDomain,
        score: _currentTabScore,
        reportType: 'false_positive'
      }, resolve);
    });

    feedback.style.display = 'block';
    if (resp && resp.success) {
      feedback.textContent = 'Signalement enregistré localement (aucun envoi externe).';
      feedback.className = 'fp-feedback safe';
    } else {
      feedback.textContent = 'Erreur lors du signalement.';
      feedback.className = 'fp-feedback danger';
    }
  } catch (e) {
    feedback.style.display = 'block';
    feedback.textContent = 'Erreur de communication.';
    feedback.className = 'fp-feedback danger';
  } finally {
    btn.disabled = false;
    btn.textContent = 'Signaler une erreur';
    setTimeout(() => {
      feedback.style.display = 'none';
    }, 4500);
  }
}

/**
 * Clear threat and statistics history
 */
async function clearHistory() {
  const button = document.getElementById('clear-history');
  try {
    button.textContent = 'Suppression…';
    button.disabled = true;

    // Send clear command to background
    await new Promise((resolve) => {
      chrome.runtime.sendMessage({ action: 'clearHistory' }, resolve);
    });

    document.getElementById('alerts-list').innerHTML =
      '<div class="no-alerts">Historique supprimé avec succès</div>';
    document.getElementById('blocked-count').textContent = '0';
    document.getElementById('alert-count').textContent = '0';

  } catch (e) {
    console.error('SafeBrowseGov: Clear error:', e);
    alert('Erreur lors de la suppression : ' + e.message);
  } finally {
    button.textContent = "Effacer l'historique";
    button.disabled = false;
  }
}

/**
 * Export encrypted history as clear JSON file
 */
async function exportHistory() {
  const button = document.getElementById('export-history');
  try {
    button.textContent = 'Préparation…';
    button.disabled = true;

    const data = await chrome.storage.local.get(['alerts', 'actionHistory', 'falsePositiveReports']);
    const alerts = data.alerts || [];

    if (alerts.length === 0 && (!data.actionHistory || data.actionHistory.length === 0)) {
      alert('Aucune donnée d\'alerte à exporter');
      return;
    }

    // Decrypt alerts
    const decryptedAlerts = [];
    for (const item of alerts) {
      try {
        if (typeof item === 'string') {
          const decrypted = await decryptData(item);
          decryptedAlerts.push(JSON.parse(decrypted));
        } else {
          decryptedAlerts.push(item);
        }
      } catch (e) {
        // Skip corrupted entries
      }
    }

    const exportData = {
      app: 'SafeBrowseGov',
      version: '3.0.0',
      exportDate: new Date().toISOString(),
      nombreAlertes: decryptedAlerts.length,
      alertes: decryptedAlerts,
      historiqueActions: data.actionHistory || []
    };

    const jsonStr = JSON.stringify(exportData, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = `safebrowsegov-historique-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();

    URL.revokeObjectURL(url);
    button.textContent = 'Exporté !';
  } catch (e) {
    console.error('SafeBrowseGov: Export error:', e);
    alert('Erreur lors de l\'export : ' + e.message);
  } finally {
    setTimeout(() => {
      button.textContent = 'Exporter';
      button.disabled = false;
    }, 1500);
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}