/**
 * SafeBrowseGov — Module de scoring pur (sans dépendance chrome.*)
 * 
 * Ce module contient toute la logique de détection et de scoring,
 * extraite pour être testable unitairement sans mocks.
 * 
 * PONDÉRATIONS DU SCORE DE RISQUE (0–100) :
 * ──────────────────────────────────────────
 * | Signal                                    | Poids |
 * |-------------------------------------------|-------|
 * | Blacklist locale                          | +40   |
 * | Liste distante phishing                   | +40   |
 * | Levenshtein <= 2 d'un domaine officiel    | +25   |
 * | Levenshtein <= 2 d'un domaine populaire   | +20   |
 * | Homographe détecté (avec cible probable)  | +25   |
 * | Homographe détecté (sans cible)           | +15   |
 * | Typosquatting détecté                     | +20   |
 * | Pattern dangereux (regex)                 | +15   |
 * | HTTP sur domaine gov/ma                   | +15   |
 * | Nom de domaine trompeur                   | +10   |
 * | TLD suspect pour gov                      | +15   |
 * | Domaine publicitaire                      | +10   |
 * | Caractères suspects                       | +10   |
 * 
 * PALIERS :
 * ──────────
 * < 30          → safe     : aucune action
 * 30–59         → warning  : bandeau non bloquant
 * 60–79         → alert    : interstitiel avec confirmation
 * >= 80 OU blacklist → blocked : redirection vers blocked.html
 */

// ──────────────────────────────────────────
// Levenshtein distance
// ──────────────────────────────────────────

function levenshteinDistance(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const matrix = Array(b.length + 1).fill(null).map(() => Array(a.length + 1).fill(null));

  for (let i = 0; i <= a.length; i += 1) matrix[0][i] = i;
  for (let j = 0; j <= b.length; j += 1) matrix[j][0] = j;

  for (let j = 1; j <= b.length; j += 1) {
    for (let i = 1; i <= a.length; i += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[j][i] = Math.min(
        matrix[j][i - 1] + 1,
        matrix[j - 1][i] + 1,
        matrix[j - 1][i - 1] + cost
      );
    }
  }

  return matrix[b.length][a.length];
}

// ──────────────────────────────────────────
// Homograph detection (extended Unicode)
// ──────────────────────────────────────────

/**
 * Détecte les caractères homographes dans un domaine en utilisant
 * une table de confusables Unicode.
 * 
 * @param {string} domain - Le domaine à analyser
 * @param {Object} confusablesMap - Table { char_unicode: char_latin }
 * @param {string[]} officialDomains - Liste de domaines officiels
 * @param {string[]} popularDomains - Liste de domaines populaires
 * @returns {{ detected: boolean, likelyTarget: boolean, convertedDomain: string, mixedScript: boolean }}
 */
function containsHomographs(domain, confusablesMap, officialDomains, popularDomains) {
  if (!confusablesMap || typeof confusablesMap !== 'object') {
    return { detected: false, likelyTarget: false, convertedDomain: domain, normalized: domain, homographCount: 0, mixedScript: false };
  }

  let detected = false;
  let convertedDomain = '';
  let hasLatin = false;
  let hasNonLatin = false;
  let homographCount = 0;

  for (const char of domain) {
    if (confusablesMap[char]) {
      detected = true;
      hasNonLatin = true;
      homographCount += 1;
      convertedDomain += confusablesMap[char];
    } else {
      convertedDomain += char;
      // Check if char is basic Latin letter
      if (/[a-zA-Z]/.test(char)) {
        hasLatin = true;
      }
    }
  }

  // Mixed script = has both Latin and non-Latin look-alikes (stronger signal)
  const mixedScript = hasLatin && hasNonLatin;

  let likelyTarget = false;
  if (detected) {
    const allKnown = [...(officialDomains || []), ...(popularDomains || [])];
    likelyTarget = allKnown.some(knownDomain => {
      const distance = levenshteinDistance(convertedDomain, knownDomain);
      return distance <= 2;
    });
  }

  return {
    detected,
    likelyTarget,
    convertedDomain,
    normalized: convertedDomain,
    homographCount,
    mixedScript
  };
}

/**
 * Détecte les domaines punycode (xn--) et vérifie s'ils ressemblent
 * à des domaines officiels/populaires une fois décodés.
 * 
 * @param {string} domain - Le domaine à analyser (peut contenir xn--)
 * @param {Object} confusablesMap - Table de confusables
 * @param {string[]} officialDomains - Liste de domaines officiels
 * @param {string[]} popularDomains - Liste de domaines populaires
 * @returns {{ isPunycode: boolean, decoded: string|null, suspicious: boolean }}
 */
function detectPunycodeHomograph(domain, confusablesMap, officialDomains, popularDomains) {
  const hasPunycode = domain.split('.').some(part => part.startsWith('xn--'));
  
  if (!hasPunycode) {
    return { isPunycode: false, decoded: null, suspicious: false };
  }

  let decoded = domain;
  try {
    // Use URL constructor to decode punycode
    const url = new URL('http://' + domain);
    decoded = url.hostname;
  } catch (e) {
    return { isPunycode: true, decoded: domain, suspicious: false };
  }

  // Check if decoded domain looks like an official/popular domain
  const allKnown = [...(officialDomains || []), ...(popularDomains || [])];
  
  // Also run homograph detection on the decoded domain
  const homographResult = containsHomographs(decoded, confusablesMap, officialDomains, popularDomains);
  
  const suspicious = homographResult.likelyTarget || allKnown.some(known => {
    const distance = levenshteinDistance(decoded, known);
    return distance <= 2 && decoded !== known;
  });

  return { isPunycode: true, decoded, suspicious };
}

// ──────────────────────────────────────────
// Typosquatting detection
// ──────────────────────────────────────────

/**
 * Détecte les techniques de typosquatting sur un domaine.
 * 
 * @param {string} domain - Le domaine à analyser
 * @param {string[]} knownDomains - Liste de domaines connus (officiels + populaires)
 * @returns {{ detected: boolean, reason: string }}
 */
function detectTyposquatting(domain, knownDomains) {
  if (!knownDomains || !Array.isArray(knownDomains)) {
    return { detected: false, reason: '', target: null };
  }

  for (const known of knownDomains) {
    if (domain === known) continue;

    // 1. Transposition de caractères adjacents (ex: mraoc.ma vs maroc.ma)
    if (domain.length === known.length) {
      for (let i = 0; i < known.length - 1; i++) {
        const swapped = known.slice(0, i) + known[i + 1] + known[i] + known.slice(i + 2);
        if (swapped === domain) {
          return { detected: true, reason: 'Transposition de caractères détectée', target: known };
        }
      }
    }

    // 2. Doublement de caractère (ex: marooc.ma vs maroc.ma)
    if (domain.length === known.length + 1) {
      for (let i = 0; i < known.length; i++) {
        const doubled = known.slice(0, i) + known[i] + known.slice(i);
        if (doubled === domain) {
          return { detected: true, reason: 'Doublement de caractère détecté', target: known };
        }
      }
    }

    // 3. Insertion de caractère (ex: maroc1.ma vs maroc.ma)
    if (domain.length === known.length + 1) {
      for (let i = 0; i <= known.length; i++) {
        for (const c of 'abcdefghijklmnopqrstuvwxyz0123456789-') {
          if (known.slice(0, i) + c + known.slice(i) === domain) {
            return { detected: true, reason: 'Insertion de caractère détectée', target: known };
          }
        }
      }
    }

    // 4. Suppression / omission de caractère (ex: mroc.ma vs maroc.ma)
    if (domain.length === known.length - 1) {
      for (let i = 0; i < known.length; i++) {
        if (known.slice(0, i) + known.slice(i + 1) === domain) {
          return { detected: true, reason: 'Suppression de caractère détectée', target: known };
        }
      }
    }

    // 5. Substitution de caractère (distance 1 avec même longueur, ex: naroc.ma vs maroc.ma)
    if (domain.length === known.length) {
      let diffCount = 0;
      for (let i = 0; i < known.length; i++) {
        if (domain[i] !== known[i]) diffCount++;
      }
      if (diffCount === 1) {
        return { detected: true, reason: 'Substitution de caractère détectée', target: known };
      }
    }
  }

  return { detected: false, reason: '', target: null };
}

// ──────────────────────────────────────────
// Dangerous patterns detection
// ──────────────────────────────────────────

/**
 * Vérifie si un domaine correspond à des patterns dangereux connus.
 * 
 * @param {string} domain - Le domaine à vérifier
 * @param {string[]} [patternStrings] - Liste de regex patterns sous forme de strings
 * @returns {boolean}
 */
function checkDangerousPatterns(domain, patternStrings) {
  const builtinPatterns = [
    /\d+\..*\.(tk|ml|ga|cf)$/,
    /.*-.*-.*-.*\./,
    /.*\.(tk|ml|ga|cf|gq)$/,
    /[0-9]{3,}/,
  ];

  const hasBuiltinMatch = builtinPatterns.some(pattern => pattern.test(domain));
  if (hasBuiltinMatch) return true;

  if (patternStrings && Array.isArray(patternStrings)) {
    try {
      return patternStrings.some(ps => new RegExp(ps).test(domain.toLowerCase()));
    } catch (e) {
      // Invalid regex in config — ignore
      return false;
    }
  }

  return false;
}

// ──────────────────────────────────────────
// Risk score computation
// ──────────────────────────────────────────

/**
 * Calcule un score de risque progressif (0–100) pour un domaine.
 * 
 * @param {string} domain - Le domaine à analyser
 * @param {Object} options - Configuration
 * @param {boolean} options.isHttps - Le site utilise-t-il HTTPS
 * @param {string[]} options.blacklist - Liste noire locale
 * @param {Set|string[]} options.remoteBlocklist - Liste distante de phishing
 * @param {string[]} options.officialDomains - Domaines officiels
 * @param {string[]} options.popularDomains - Domaines populaires
 * @param {string[]} options.adDomains - Domaines publicitaires
 * @param {Object} options.confusablesMap - Table de confusables Unicode
 * @param {string[]} [options.dangerousPatterns] - Patterns regex dangereux
 * @param {number} [options.sensitivityOffset=0] - Ajustement du seuil (-20 à +20)
 * @returns {{ score: number, level: string, threats: string[], isAdDomain: boolean }}
 */
function computeRiskScore(domain, options) {
  const {
    isHttps = true,
    blacklist = [],
    remoteBlocklist = null,
    officialDomains = [],
    popularDomains = [],
    adDomains = [],
    confusablesMap = {},
    dangerousPatterns = [],
    sensitivityOffset = 0
  } = options;

  let score = 0;
  const threats = [];
  let forceBlocked = false;

  // 1. Blacklist locale (poids fort : +40, blocage forcé)
  const isBlacklisted = blacklist.some(d => domain === d || domain.endsWith('.' + d));
  if (isBlacklisted) {
    score += 40;
    threats.push('Domaine sur liste noire');
    forceBlocked = true;
  }

  // 2. Liste distante phishing (poids fort : +40, blocage forcé)
  let isInRemoteList = false;
  if (remoteBlocklist) {
    if (remoteBlocklist instanceof Set) {
      isInRemoteList = remoteBlocklist.has(domain);
    } else if (Array.isArray(remoteBlocklist)) {
      isInRemoteList = remoteBlocklist.includes(domain);
    }
  }
  if (isInRemoteList) {
    score += 40;
    threats.push('Signalé dans la liste distante de phishing/malware');
    forceBlocked = true;
  }

  // 3. Levenshtein close to official domain (+25)
  const closeToOfficial = officialDomains.some(d => {
    const distance = levenshteinDistance(domain, d);
    return distance <= 2 && domain !== d;
  });
  if (closeToOfficial) {
    score += 25;
    threats.push('Usurpation de domaine officiel');
  }

  // 4. Levenshtein close to popular domain (+20)
  const closeToPopular = popularDomains.some(d => {
    const distance = levenshteinDistance(domain, d);
    return distance <= 2 && domain !== d && distance > 0;
  });
  if (closeToPopular) {
    score += 20;
    threats.push('Usurpation de site populaire');
  }

  // 5. Homograph detection (+25 with target, +15 without)
  const homographResult = containsHomographs(domain, confusablesMap, officialDomains, popularDomains);
  if (homographResult.detected) {
    if (homographResult.likelyTarget) {
      score += 25;
      threats.push('Homographe visant un domaine connu');
    } else {
      score += 15;
      threats.push('Caractères homographes détectés');
    }
  }

  // 6. Punycode IDN detection
  const punycodeResult = detectPunycodeHomograph(domain, confusablesMap, officialDomains, popularDomains);
  if (punycodeResult.isPunycode && punycodeResult.suspicious) {
    score += 25;
    threats.push('Domaine punycode suspect (IDN homographe)');
  }

  // 7. Typosquatting (+20)
  const allKnown = [...officialDomains, ...popularDomains];
  const typoResult = detectTyposquatting(domain, allKnown);
  if (typoResult.detected) {
    score += 20;
    threats.push(typoResult.reason);
  }

  // 8. Dangerous patterns (+15)
  if (checkDangerousPatterns(domain, dangerousPatterns)) {
    score += 15;
    threats.push('Pattern de domaine dangereux');
  }

  // 9. HTTP on gov/ma domain (+15)
  if (!isHttps && (domain.includes('gov') || domain.includes('.ma') ||
      domain.includes('cnss') || domain.includes('ramed') ||
      domain.includes('service-public') || domain.includes('douane'))) {
    score += 15;
    threats.push('Site gouvernemental non sécurisé (HTTP)');
  }

  // 10. Deceptive domain name (+10)
  if (domain.includes('https') || domain.includes('secure') ||
      domain.includes('ssl') || domain.includes('cert') ||
      domain.includes('official') || domain.includes('government')) {
    score += 10;
    threats.push('Nom de domaine trompeur');
  }

  // 11. Suspicious TLD for gov (+15)
  if ((domain.includes('gov') || domain.includes('cnss')) &&
      !domain.endsWith('.ma') && !domain.endsWith('.gov.ma')) {
    score += 15;
    threats.push('TLD suspect pour site gouvernemental');
  }

  // 12. Ad domain (+10)
  const isAdDomain = adDomains.some(adDomain => domain === adDomain || domain.endsWith('.' + adDomain));
  if (isAdDomain) {
    score += 10;
    threats.push('Domaine publicitaire');
  }

  // 13. Suspicious chars (general regex check) (+10)
  const suspiciousCharsRegex = /[а-я]|[αβγδεζηθικλμνξοπρστυφχψω]|[0-9]{4,}/;
  if (suspiciousCharsRegex.test(domain) && !homographResult.detected) {
    score += 10;
    threats.push('Caractères suspects');
  }

  // If force-blocked (blacklist or remote blocklist), ensure score reflects blocked status
  if (forceBlocked) {
    score = Math.max(score, 85);
  }

  // Cap at 100
  score = Math.min(score, 100);

  // Apply sensitivity offset to thresholds
  const offset = Math.max(-20, Math.min(20, sensitivityOffset));
  const thresholdWarning = Math.max(10, 30 - offset);
  const thresholdAlert = Math.max(30, 60 - offset);
  const thresholdBlocked = Math.max(50, 80 - offset);

  // Determine level
  let level;
  if (forceBlocked || score >= thresholdBlocked) {
    level = 'blocked';
  } else if (score >= thresholdAlert) {
    level = 'alert';
  } else if (score >= thresholdWarning) {
    level = 'warning';
  } else {
    level = 'safe';
  }

  return { score, level, threats, isAdDomain };
}

// ──────────────────────────────────────────
// Exports (compatible with both ES modules for tests and global scope for extension)
// ──────────────────────────────────────────

// For Vitest / Node.js ES module tests
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    levenshteinDistance,
    containsHomographs,
    detectPunycodeHomograph,
    detectTyposquatting,
    checkDangerousPatterns,
    computeRiskScore
  };
}

// For extension global scope (service worker importScripts)
if (typeof self !== 'undefined' && typeof self.levenshteinDistance === 'undefined') {
  self.levenshteinDistance = levenshteinDistance;
  self.containsHomographs = containsHomographs;
  self.detectPunycodeHomograph = detectPunycodeHomograph;
  self.detectTyposquatting = detectTyposquatting;
  self.checkDangerousPatterns = checkDangerousPatterns;
  self.computeRiskScore = computeRiskScore;
}
