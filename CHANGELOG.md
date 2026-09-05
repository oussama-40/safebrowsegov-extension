# Journal des modifications (CHANGELOG)

Toutes les modifications notables apportées au projet **SafeBrowseGov** sont consignées dans ce document.

---

## [3.0.0] - 2026-09-05

### 🚀 Nouveautés majeures

- **Score de risque progressif (0–100) :** Remplacement de l'évaluation binaire (bloqué/non bloqué) par un indice de risque continu avec 4 paliers :
  - `< 30` : Sécurisé (aucun impact).
  - `30–59` : Avertissement (badge ambre informatif).
  - `60–79` : Alerte (écran d'avertissement intermédiaire avec confirmation de navigation).
  - `≥ 80` ou liste noire : Blocage direct avec redirection vers `blocked.html`.
- **Listes de blocage distantes automatiques :** Intégration de flux ouverts de renseignement sur les menaces (Phishing URL Filter et URLhaus), mis à jour automatiquement en arrière-plan toutes les 6 heures via `chrome.alarms` avec repli gracieux hors-ligne.
- **Migration vers `declarativeNetRequest` :** Remplacement de l'ancien mécanisme de blocage publicitaire (qui tentait d'utiliser incorrectement `chrome.webRequest` dans les content scripts) par des règles natives déclaratives MV3 ultra-rapides et économes en ressources (`rules/ad-blocking-rules.json`).
- **Détection étendue des homographes et punycode IDN :**
  - Table de confusables Unicode embarquée (`data/confusables.json`) couvrant plus de 2000 variantes visuelles (cyrillique, grec, arménien, latins étendus).
  - Décodage automatique et analyse des domaines internationalisés au format Punycode (`xn--`).
- **Page d'options complète (`options.html`) :**
  - Gestion d'une liste blanche personnalisée de noms de domaine avec validation stricte.
  - Curseur d'ajustement de la sensibilité du score de risque.
  - Bascule indépendante du bloqueur de publicités.
  - Activation optionnelle du mode strict.
  - Tableau de consultation et suppression des signalements locaux de faux positifs.
  - Section intégrée de documentation sur la confidentialité (`#privacy`).
- **Module de scoring pur et testable (`utils/scoring.js`) :** Architecture découplée et autonome, sans dépendance à l'API `chrome.*`, compatible Node.js et Navigateur, facilitant la réalisation de tests automatisés.
- **Signalement de faux positifs :** Possibilité pour l'utilisateur de marquer un domaine comme faux positif depuis la page de blocage ou le menu popup, stocké de façon chiffrée en local.

### 🛡️ Corrections et améliorations

- **Suppression du blocage agressif par défaut :** Retrait des fonctions `blockAllClicks()` et `blockAllPopups()` du flux standard dans `content.js` qui cassaient la navigation sur des sites légitimes (comme YouTube ou Google). L'ancien comportement est relégué en option dans le "Mode strict".
- **Élimination des erreurs de Service Worker :** Suppression des références à l'objet `document` (DOM) dans le service worker MV3 (`background.js`), éliminant les exceptions silencieuses.
- **Fiabilisation des boutons interactifs :** Encapsulation systématique des gestionnaires d'événements dans des blocs `try / catch / finally` garantissant la réactivation des boutons en cas d'erreur réseau ou asynchrone.
- **Synchronisation de la suppression d'historique :** L'action d'effacement de l'historique dans le popup synchronise désormais correctement le nettoyage des historiques d'actions et des compteurs dans le service worker.
- **Accessibilité WCAG AA :**
  - Ajout des attributs `aria-label`, `aria-live="polite"`, `role="progressbar"`, `role="alertdialog"`.
  - Rehaussement des contrastes de couleur sur les textes et étiquettes.
  - Support complet de la navigation au clavier (`:focus-visible`).
- **Externalisation des règles statiques :** Séparation des données de détection dans `data/rules.json` pour faciliter les futures mises à jour sans modifier la logique de l'extension.

---

## [2.1.0] - Version antérieure

- Détection basique par distance de Levenshtein (seuil ≤ 2).
- Table statique restreinte d'homographes cyrilliques dans le code.
- Chiffrement AES-GCM local de l'historique des alertes.
- Interception expérimentale de clics et popups.
