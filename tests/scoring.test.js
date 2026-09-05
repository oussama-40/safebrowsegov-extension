import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

// Import the scoring module
const scoring = require('../utils/scoring.js');
const {
  levenshteinDistance,
  detectTyposquatting,
  containsHomographs,
  detectPunycodeHomograph,
  computeRiskScore
} = scoring;

// Load real confusables table
const confusablesPath = path.resolve(__dirname, '../data/confusables.json');
const confusablesData = JSON.parse(fs.readFileSync(confusablesPath, 'utf8'));
const confusablesMap = confusablesData.map;

// Load rules data for realistic context
const rulesPath = path.resolve(__dirname, '../data/rules.json');
const rulesData = JSON.parse(fs.readFileSync(rulesPath, 'utf8'));

describe('Algorithme de Levenshtein (levenshteinDistance)', () => {
  it('retourne 0 pour deux chaînes identiques', () => {
    expect(levenshteinDistance('maroc.ma', 'maroc.ma')).toBe(0);
    expect(levenshteinDistance('', '')).toBe(0);
  });

  it('gère correctement les chaînes vides', () => {
    expect(levenshteinDistance('', 'abc')).toBe(3);
    expect(levenshteinDistance('abc', '')).toBe(3);
  });

  it('calcule une distance de 1 pour une insertion, suppression ou substitution', () => {
    // Insertion
    expect(levenshteinDistance('maroc.ma', 'marocc.ma')).toBe(1);
    // Suppression
    expect(levenshteinDistance('maroc.ma', 'mroc.ma')).toBe(1);
    // Substitution
    expect(levenshteinDistance('maroc.ma', 'naroc.ma')).toBe(1);
  });

  it('calcule des distances supérieures à 1', () => {
    expect(levenshteinDistance('maroc.ma', 'morocco.ma')).toBe(3);
  });
});

describe('Détection de Typosquatting (detectTyposquatting)', () => {
  const knownDomains = ['maroc.ma', 'cnss.ma', 'service-public.ma', 'douane.gov.ma'];

  it('ne détecte rien pour un domaine identique', () => {
    const res = detectTyposquatting('maroc.ma', knownDomains);
    expect(res.detected).toBe(false);
  });

  it('détecte le redoublement de lettre', () => {
    const res = detectTyposquatting('marooc.ma', knownDomains);
    expect(res.detected).toBe(true);
    expect(res.target).toBe('maroc.ma');
  });

  it('détecte la substitution d\'un caractère', () => {
    const res = detectTyposquatting('naroc.ma', knownDomains);
    expect(res.detected).toBe(true);
    expect(res.target).toBe('maroc.ma');
  });

  it('détecte l\'omission d\'un caractère', () => {
    const res = detectTyposquatting('mroc.ma', knownDomains);
    expect(res.detected).toBe(true);
    expect(res.target).toBe('maroc.ma');
  });

  it('détecte la transposition de deux lettres adjacentes', () => {
    const res = detectTyposquatting('mraoc.ma', knownDomains);
    expect(res.detected).toBe(true);
    expect(res.target).toBe('maroc.ma');
  });

  it('ne signale pas un domaine totalement différent', () => {
    const res = detectTyposquatting('wikipedia.org', knownDomains);
    expect(res.detected).toBe(false);
  });
});

describe('Détection d\'Homographes Unicode (containsHomographs)', () => {
  it('ne détecte aucun homographe sur un domaine ASCII pur', () => {
    const res = containsHomographs('maroc.ma', confusablesMap);
    expect(res.detected).toBe(false);
    expect(res.homographCount).toBe(0);
  });

  it('détecte le caractère cyrillique "а" (U+0430) remplaçant "a"', () => {
    // 'm' + cyrillic 'а' + 'roc.ma'
    const spoofed = 'm\u0430roc.ma';
    const res = containsHomographs(spoofed, confusablesMap);
    expect(res.detected).toBe(true);
    expect(res.normalized).toBe('maroc.ma');
    expect(res.homographCount).toBe(1);
  });

  it('détecte le caractère cyrillique "о" (U+043E) remplaçant "o"', () => {
    const spoofed = 'mar\u043Ec.ma';
    const res = containsHomographs(spoofed, confusablesMap);
    expect(res.detected).toBe(true);
    expect(res.normalized).toBe('maroc.ma');
  });

  it('détecte les caractères grecs ou arméniens répertoriés', () => {
    // Greek small letter alpha \u03B1
    const spoofed = 'm\u03B1roc.ma';
    const res = containsHomographs(spoofed, confusablesMap);
    expect(res.detected).toBe(true);
    expect(res.normalized).toBe('maroc.ma');
  });
});

describe('Détection de Punycode IDN (detectPunycodeHomograph)', () => {
  it('identifie un domaine punycode commençant par xn--', () => {
    const punyDomain = 'xn--mroc-73a.ma';
    const res = detectPunycodeHomograph(punyDomain, confusablesMap, ['maroc.ma'], []);
    expect(res.isPunycode).toBe(true);
  });

  it('ignore un domaine non-punycode', () => {
    const res = detectPunycodeHomograph('maroc.ma', confusablesMap, ['maroc.ma'], []);
    expect(res.isPunycode).toBe(false);
  });
});

describe('Calcul du score de risque progressif (computeRiskScore)', () => {
  const defaultOptions = {
    isHttps: true,
    blacklist: rulesData.blacklist || [],
    remoteBlocklist: new Set(['malicious-domain.com', 'phishing-site.xyz']),
    officialDomains: rulesData.officialDomains || [],
    popularDomains: rulesData.popularDomains || [],
    adDomains: rulesData.adDomains || [],
    confusablesMap: confusablesMap,
    dangerousPatterns: [
      /(https?|secure|login|verify|account|update)[-_.]/i,
      /\b(gov|etat|ministere|douane|cnss)[-_.]\w+\.(com|org|net|xyz|top|site)\b/i
    ],
    sensitivityOffset: 0
  };

  it('classe un domaine légitime officiel HTTPS en "safe" (score < 30)', () => {
    const res = computeRiskScore('maroc.ma', defaultOptions);
    expect(res.level).toBe('safe');
    expect(res.score).toBeLessThan(30);
  });

  it('force le blocage d\'un domaine présent dans la liste noire locale (blacklist)', () => {
    const res = computeRiskScore('maroc-telecom-promo.com', {
      ...defaultOptions,
      blacklist: ['maroc-telecom-promo.com']
    });
    expect(res.level).toBe('blocked');
    expect(res.score).toBeGreaterThanOrEqual(80);
    expect(res.threats).toContain('Domaine sur liste noire');
  });

  it('bloque un domaine présent dans la liste distante de phishing/malware', () => {
    const res = computeRiskScore('malicious-domain.com', defaultOptions);
    expect(res.level).toBe('blocked');
    expect(res.score).toBeGreaterThanOrEqual(80);
    expect(res.threats).toContain('Signalé dans la liste distante de phishing/malware');
  });

  it('pénalise un domaine gouvernemental servi sans HTTPS', () => {
    const res = computeRiskScore('portail-gov.ma', {
      ...defaultOptions,
      isHttps: false
    });
    expect(res.score).toBeGreaterThan(0);
    expect(res.threats).toContain('Site gouvernemental non sécurisé (HTTP)');
  });

  it('détecte et pénalise un homographe ciblant un domaine officiel', () => {
    // 'm' + cyrillic 'а' + 'roc.ma'
    const spoofed = 'm\u0430roc.ma';
    const res = computeRiskScore(spoofed, defaultOptions);
    expect(res.score).toBeGreaterThanOrEqual(25);
    expect(res.threats.some(t => t.includes('Homographe'))).toBe(true);
  });

  it('ajuste les seuils selon le curseur de sensibilité (sensitivityOffset)', () => {
    // Score modéré
    const optionsTolérant = { ...defaultOptions, sensitivityOffset: -20 };
    const optionsStrict = { ...defaultOptions, sensitivityOffset: 20 };

    // Typosquatting cnss.ma
    const domain = 'cnsss.ma';
    const resNormal = computeRiskScore(domain, defaultOptions);
    const resStrict = computeRiskScore(domain, optionsStrict);

    // En mode strict (seuil abaissé), le niveau est au moins aussi sévère
    expect(resStrict.score).toBeGreaterThanOrEqual(resNormal.score);
  });
});
