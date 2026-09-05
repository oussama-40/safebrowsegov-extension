/**
 * SafeBrowseGov v3.0 — Controller pour la page de blocage (blocked.html)
 * 
 * Ce fichier est externalisé car le Manifest V3 interdit les scripts inline
 * (Content Security Policy : script-src 'self').
 */

document.addEventListener('DOMContentLoaded', async () => {
  const params = new URLSearchParams(window.location.search);
  const blockedUrl = params.get('url') || '';
  let tabId = params.get('tabId') ? Number(params.get('tabId')) : null;
  const scoreParam = parseInt(params.get('score'), 10);
  const riskScore = isNaN(scoreParam) ? 80 : Math.max(0, Math.min(100, scoreParam));
  const levelParam = params.get('level') || (riskScore >= 80 ? 'blocked' : 'alert');

  // Try to get current tabId if missing from URL
  if (!tabId && window.chrome && chrome.tabs && chrome.tabs.getCurrent) {
    try {
      const tab = await chrome.tabs.getCurrent();
      if (tab && tab.id) tabId = tab.id;
    } catch (e) {
      // Ignore
    }
  }

  let threats = [];
  try {
    threats = JSON.parse(params.get('threats') || '[]');
  } catch (e) {
    threats = [];
  }

  // 1. Affichage de l'URL ciblée
  const urlBox = document.getElementById('blocked-url');
  if (urlBox) {
    urlBox.textContent = blockedUrl || 'Adresse non disponible';
  }

  // 2. Affichage du score et du badge
  const badge = document.getElementById('threat-badge');
  const scoreText = document.getElementById('score-text');
  const scoreFill = document.getElementById('score-fill');
  const progressBar = document.getElementById('progress-bar');
  const pageTitle = document.getElementById('dialog-title');

  if (scoreText) scoreText.textContent = `${riskScore} / 100`;
  if (scoreFill) scoreFill.style.width = `${riskScore}%`;
  if (progressBar) progressBar.setAttribute('aria-valuenow', riskScore);

  if (levelParam === 'alert') {
    if (badge) {
      badge.textContent = 'Avertissement — Risque élevé';
      badge.className = 'eyebrow alert';
    }
    if (scoreText) scoreText.className = 'score-value alert';
    if (scoreFill) scoreFill.className = 'score-bar-fill alert';
    if (pageTitle) pageTitle.textContent = 'Avertissement de sécurité';
  } else {
    if (badge) {
      badge.textContent = 'Menace critique détectée';
      badge.className = 'eyebrow blocked';
    }
    if (scoreText) scoreText.className = 'score-value blocked';
    if (scoreFill) scoreFill.className = 'score-bar-fill blocked';
    if (pageTitle) pageTitle.textContent = 'Ce site a été bloqué';
  }

  // 3. Liste des menaces
  const list = document.getElementById('threat-list');
  if (list) {
    list.innerHTML = '';
    if (threats.length === 0) {
      const li = document.createElement('li');
      li.textContent = 'Indice de risque élevé relevé par l\'analyse heuristique';
      list.appendChild(li);
    } else {
      threats.forEach(t => {
        const li = document.createElement('li');
        li.innerHTML = '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M12 9v4M12 16.5h.01M10.3 3.9 2.7 17.3A1.7 1.7 0 0 0 4.2 20h15.6a1.7 1.7 0 0 0 1.5-2.7L13.7 3.9a1.7 1.7 0 0 0-3.4 0Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg><span></span>';
        li.querySelector('span').textContent = t;
        list.appendChild(li);
      });
    }
  }

  // Helper pour communiquer avec le background
  function sendToBackground(action, extra = {}) {
    return new Promise((resolve) => {
      if (!window.chrome || !chrome.runtime || !chrome.runtime.sendMessage) {
        resolve({ success: false });
        return;
      }
      chrome.runtime.sendMessage({ action, url: blockedUrl, tabId, ...extra }, (response) => {
        resolve(response || { success: false });
      });
    });
  }

  // 4. Bouton : Retour en sécurité
  const goBackBtn = document.getElementById('go-back');
  if (goBackBtn) {
    goBackBtn.addEventListener('click', async () => {
      try {
        goBackBtn.disabled = true;
        const res = await sendToBackground('goBackSafe');
        if (!res.success) {
          if (window.history.length > 1) {
            window.history.back();
          } else {
            window.location.href = 'https://www.google.com';
          }
        }
      } catch (e) {
        console.error('Erreur go-back:', e);
        window.location.href = 'https://www.google.com';
      } finally {
        goBackBtn.disabled = false;
      }
    });
  }

  // 5. Bouton : Continuer malgré le risque (Affiche la confirmation)
  const continueAnywayBtn = document.getElementById('continue-anyway');
  const confirmBox = document.getElementById('confirm-box');
  const mainActions = document.getElementById('main-actions');

  if (continueAnywayBtn && confirmBox && mainActions) {
    continueAnywayBtn.addEventListener('click', () => {
      confirmBox.classList.add('visible');
      mainActions.style.display = 'none';
    });
  }

  // 6. Bouton : Annuler dans la boîte de confirmation
  const cancelContinueBtn = document.getElementById('cancel-continue');
  if (cancelContinueBtn && confirmBox && mainActions) {
    cancelContinueBtn.addEventListener('click', () => {
      confirmBox.classList.remove('visible');
      mainActions.style.display = 'flex';
    });
  }

  // 7. Bouton : Confirmer la continuation (Allow Once)
  const confirmBtn = document.getElementById('confirm-continue');
  if (confirmBtn) {
    confirmBtn.addEventListener('click', async () => {
      try {
        confirmBtn.disabled = true;
        const res = await sendToBackground('allowOnce');
        if (blockedUrl) {
          window.location.href = blockedUrl;
        }
      } catch (e) {
        console.error('Erreur allowOnce:', e);
        if (blockedUrl) window.location.href = blockedUrl;
      } finally {
        confirmBtn.disabled = false;
      }
    });
  }

  // 8. Bouton : Signaler une erreur (Faux positif)
  const reportBtn = document.getElementById('report-false-positive');
  const reportStatus = document.getElementById('report-status');
  if (reportBtn && reportStatus) {
    reportBtn.addEventListener('click', async () => {
      try {
        reportBtn.disabled = true;
        let domain = '';
        try {
          domain = new URL(blockedUrl).hostname;
        } catch (e) {
          domain = blockedUrl;
        }

        const res = await sendToBackground('reportFalsePositive', {
          domain,
          score: riskScore,
          reportType: 'false_positive'
        });

        reportStatus.style.display = 'block';
        if (res && res.success) {
          reportStatus.textContent = 'Signalement enregistré localement (aucun envoi externe).';
          reportStatus.style.color = 'var(--safe)';
        } else {
          reportStatus.textContent = 'Impossible d\'enregistrer le signalement.';
          reportStatus.style.color = 'var(--danger)';
        }
      } catch (e) {
        reportStatus.style.display = 'block';
        reportStatus.textContent = 'Erreur lors de l\'enregistrement.';
        reportStatus.style.color = 'var(--danger)';
      } finally {
        reportBtn.disabled = false;
      }
    });
  }

  // Protection contre le bouton 'page suivante' du navigateur
  history.pushState(null, null, location.href);
  window.addEventListener('popstate', () => {
    history.pushState(null, null, location.href);
  });
});
