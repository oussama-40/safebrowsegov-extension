/**
 * SafeBrowseGov v3.0 — Options Page Controller
 * 
 * Manages user settings, custom whitelist, false positive reports,
 * and privacy documentation tabs.
 */

let _currentSettings = {
  adBlockEnabled: true,
  strictMode: false,
  sensitivityOffset: 0,
  userWhitelist: []
};

document.addEventListener('DOMContentLoaded', async () => {
  setupNavigation();
  await loadSettings();
  await loadReports();
  setupEventListeners();

  // Check URL hash for initial tab
  handleHash(window.location.hash);
  window.addEventListener('hashchange', () => handleHash(window.location.hash));
});

/**
 * Handle tab switching via anchors or clicks
 */
function setupNavigation() {
  const tabs = {
    '#settings': { link: document.getElementById('tab-settings-link'), sec: document.getElementById('section-settings') },
    '#reports': { link: document.getElementById('tab-reports-link'), sec: document.getElementById('section-reports') },
    '#privacy': { link: document.getElementById('tab-privacy-link'), sec: document.getElementById('section-privacy') }
  };

  Object.entries(tabs).forEach(([hash, config]) => {
    config.link.addEventListener('click', (e) => {
      e.preventDefault();
      window.location.hash = hash;
    });
  });
}

function handleHash(hash) {
  const target = hash === '#privacy' ? '#privacy' : (hash === '#reports' ? '#reports' : '#settings');
  
  const sections = {
    '#settings': { link: document.getElementById('tab-settings-link'), sec: document.getElementById('section-settings') },
    '#reports': { link: document.getElementById('tab-reports-link'), sec: document.getElementById('section-reports') },
    '#privacy': { link: document.getElementById('tab-privacy-link'), sec: document.getElementById('section-privacy') }
  };

  Object.entries(sections).forEach(([h, item]) => {
    if (h === target) {
      item.link.classList.add('active');
      item.sec.style.display = 'block';
    } else {
      item.link.classList.remove('active');
      item.sec.style.display = 'none';
    }
  });
}

/**
 * Load user settings from storage
 */
async function loadSettings() {
  try {
    const data = await chrome.storage.local.get(['adBlockEnabled', 'strictMode', 'sensitivityOffset', 'userWhitelist']);
    _currentSettings.adBlockEnabled = data.adBlockEnabled !== false;
    _currentSettings.strictMode = data.strictMode === true;
    _currentSettings.sensitivityOffset = data.sensitivityOffset || 0;
    _currentSettings.userWhitelist = data.userWhitelist || [];

    // Populate form
    document.getElementById('ad-block-toggle').checked = _currentSettings.adBlockEnabled;
    document.getElementById('strict-mode-toggle').checked = _currentSettings.strictMode;
    
    const slider = document.getElementById('sensitivity-slider');
    slider.value = _currentSettings.sensitivityOffset;
    updateSensitivityLabel(_currentSettings.sensitivityOffset);

    renderWhitelist();
  } catch (e) {
    console.error('SafeBrowseGov: Error loading settings:', e);
  }
}

/**
 * Setup input event listeners
 */
function setupEventListeners() {
  // Ad block toggle
  document.getElementById('ad-block-toggle').addEventListener('change', async (e) => {
    _currentSettings.adBlockEnabled = e.target.checked;
    await saveSettings();
    showToast('Bloqueur de pubs ' + (_currentSettings.adBlockEnabled ? 'activé' : 'désactivé'));
  });

  // Strict mode toggle
  document.getElementById('strict-mode-toggle').addEventListener('change', async (e) => {
    _currentSettings.strictMode = e.target.checked;
    await saveSettings();
    showToast('Mode strict ' + (_currentSettings.strictMode ? 'activé' : 'désactivé'));
  });

  // Sensitivity slider
  const slider = document.getElementById('sensitivity-slider');
  slider.addEventListener('input', (e) => {
    const val = parseInt(e.target.value, 10);
    updateSensitivityLabel(val);
  });
  slider.addEventListener('change', async (e) => {
    _currentSettings.sensitivityOffset = parseInt(e.target.value, 10);
    await saveSettings();
    showToast('Sensibilité enregistrée');
  });

  // Whitelist add
  document.getElementById('add-whitelist-btn').addEventListener('click', addWhitelistDomain);
  document.getElementById('whitelist-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      addWhitelistDomain();
    }
  });

  // Reports clear
  document.getElementById('clear-reports-btn').addEventListener('click', clearReports);
}

function updateSensitivityLabel(val) {
  const lbl = document.getElementById('sensitivity-value');
  slider = document.getElementById('sensitivity-slider');
  slider.setAttribute('aria-valuenow', val);

  if (val > 0) {
    lbl.textContent = `Renforcé (+${val})`;
    lbl.style.color = 'var(--warn)';
  } else if (val < 0) {
    lbl.textContent = `Tolérant (${val})`;
    lbl.style.color = 'var(--safe)';
  } else {
    lbl.textContent = 'Normal (0)';
    lbl.style.color = 'var(--ink-900)';
  }
}

/**
 * Save settings to chrome.storage.local
 */
async function saveSettings() {
  try {
    await chrome.storage.local.set({
      adBlockEnabled: _currentSettings.adBlockEnabled,
      strictMode: _currentSettings.strictMode,
      sensitivityOffset: _currentSettings.sensitivityOffset,
      userWhitelist: _currentSettings.userWhitelist
    });
  } catch (e) {
    console.error('SafeBrowseGov: Error saving settings:', e);
    showToast('Erreur lors de l\'enregistrement');
  }
}

/**
 * Custom Whitelist Logic
 */
function cleanDomain(input) {
  let domain = (input || '').trim().toLowerCase();
  // Strip protocol
  domain = domain.replace(/^https?:\/\//i, '');
  // Strip paths, query params, ports
  domain = domain.split('/')[0].split(':')[0].split('?')[0];
  return domain;
}

function isValidDomain(domain) {
  const pattern = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i;
  return pattern.test(domain);
}

async function addWhitelistDomain() {
  const input = document.getElementById('whitelist-input');
  const errorEl = document.getElementById('whitelist-error');
  const domain = cleanDomain(input.value);

  errorEl.style.display = 'none';

  if (!domain) {
    errorEl.textContent = 'Veuillez saisir un nom de domaine.';
    errorEl.style.display = 'block';
    return;
  }

  if (!isValidDomain(domain)) {
    errorEl.textContent = 'Format de domaine invalide (ex: exemple.ma ou sous.domaine.ma).';
    errorEl.style.display = 'block';
    return;
  }

  if (_currentSettings.userWhitelist.includes(domain)) {
    errorEl.textContent = 'Ce domaine figure déjà dans votre liste blanche.';
    errorEl.style.display = 'block';
    return;
  }

  _currentSettings.userWhitelist.push(domain);
  input.value = '';
  await saveSettings();
  renderWhitelist();
  showToast(`Domaine ${domain} ajouté à la liste blanche`);
}

async function removeWhitelistDomain(domain) {
  _currentSettings.userWhitelist = _currentSettings.userWhitelist.filter(d => d !== domain);
  await saveSettings();
  renderWhitelist();
  showToast(`Domaine ${domain} retiré`);
}

function renderWhitelist() {
  const container = document.getElementById('whitelist-container');
  if (!_currentSettings.userWhitelist || _currentSettings.userWhitelist.length === 0) {
    container.innerHTML = '<li class="no-items">Aucun domaine personnalisé dans votre liste blanche.</li>';
    return;
  }

  container.innerHTML = '';
  _currentSettings.userWhitelist.forEach(domain => {
    const li = document.createElement('li');
    li.className = 'whitelist-item';

    const span = document.createElement('span');
    span.className = 'whitelist-domain';
    span.textContent = domain;

    const delBtn = document.createElement('button');
    delBtn.className = 'btn btn-danger-outline';
    delBtn.textContent = 'Supprimer';
    delBtn.setAttribute('aria-label', `Retirer ${domain} de la liste blanche`);
    delBtn.addEventListener('click', () => removeWhitelistDomain(domain));

    li.appendChild(span);
    li.appendChild(delBtn);
    container.appendChild(li);
  });
}

/**
 * False Positive Reports
 */
async function loadReports() {
  const container = document.getElementById('reports-container');
  try {
    const response = await new Promise(resolve => {
      chrome.runtime.sendMessage({ action: 'getFalsePositiveReports' }, resolve);
    });

    const reports = (response && response.success) ? response.reports : [];

    if (!reports || reports.length === 0) {
      container.innerHTML = '<p class="no-items">Aucun signalement enregistré.</p>';
      return;
    }

    let html = `
      <table class="reports-table">
        <thead>
          <tr>
            <th>Domaine</th>
            <th>Score</th>
            <th>Type</th>
            <th>Date</th>
          </tr>
        </thead>
        <tbody>
    `;

    reports.forEach(r => {
      const date = new Date(r.timestamp).toLocaleString('fr-FR');
      html += `
        <tr>
          <td><code>${escapeHtml(r.domain || '')}</code></td>
          <td>${r.score !== undefined ? r.score : 'N/A'}</td>
          <td>${escapeHtml(r.type || 'Faux positif')}</td>
          <td>${date}</td>
        </tr>
      `;
    });

    html += `</tbody></table>`;
    container.innerHTML = html;
  } catch (e) {
    container.innerHTML = '<p class="no-items">Erreur lors de la lecture des signalements.</p>';
  }
}

async function clearReports() {
  if (!confirm('Voulez-vous supprimer tous les signalements locaux enregistrés ?')) {
    return;
  }

  try {
    await new Promise(resolve => {
      chrome.runtime.sendMessage({ action: 'clearFalsePositiveReports' }, resolve);
    });
    await loadReports();
    showToast('Signalements supprimés');
  } catch (e) {
    showToast('Erreur lors de la suppression');
  }
}

/**
 * Utility notification toast
 */
let toastTimeout;
function showToast(msg) {
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.style.display = 'block';

  clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => {
    toast.style.display = 'none';
  }, 2500);
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
