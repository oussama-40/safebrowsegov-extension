# Politique de Confidentialité — SafeBrowseGov

**Version :** 3.0.0  
**Dernière mise à jour :** 5 septembre 2026  
**Champ d'application :** Extension de navigateur Manifest V3 (Chrome, Edge, Brave, Chromium)

---

## 1. Engagement de respect de la vie privée

SafeBrowseGov est une extension open-source conçue pour protéger les citoyens marocains contre l'usurpation d'identité institutionnelle (phishing gouvernemental, attaques par homographes Unicode, typosquatting) et filtrer les publicités malveillantes.

**Notre principe absolu : AUCUNE collecte de données personnelles et AUCUN traçage.**  
Votre historique de navigation ne quitte jamais votre appareil.

---

## 2. Données traitées et fonctionnement technique

### 2.1 Analyse locale des URLs
Chaque fois qu'une page web est consultée :
- L'URL et le nom de domaine sont analysés **exclusivement au sein de votre navigateur** par les algorithmes heuristiques de l'extension (distance de Levenshtein, détection d'homographes, analyse syntaxique de patterns).
- Aucune requête de télémétrie ou de journalisation d'URL n'est envoyée à des serveurs tiers ou au créateur de l'extension.

### 2.2 Téléchargement des listes de menaces distantes
Pour protéger contre les vagues récentes d'usurpation :
- L'extension télécharge périodiquement (toutes les 6 heures) les listes publiques de domaines malveillants fournies par des initiatives ouvertes :
  - **Phishing URL Blocklist** (curbengh/phishing-filter)
  - **URLhaus** (abuse.ch)
- Ces requêtes sont de simples requêtes HTTP GET anonymes vers des dépôts statiques GitHub ou serveurs de listes.
- **Aucune donnée sur votre navigation, votre profil ou votre identifiant n'est transmise.**

### 2.3 Stockage local et chiffrement
- L'historique des sites bloqués et des alertes est stocké dans `chrome.storage.local`.
- Pour garantir votre confidentialité en cas d'accès physique à votre session de navigateur, ces données sont **chiffrées localement** à l'aide de l'API standard Web Cryptography (AES-GCM 256 bits avec clé dérivée par PBKDF2).
- Les signalements locaux de faux positifs restent cantonnés à votre navigateur jusqu'à ce que vous décidiez vous-même de les effacer.

---

## 3. Permissions requises et justifications (Manifest V3)

L'extension demande uniquement les permissions strictement nécessaires à sa mission défensive :

| Permission | Justification |
| :--- | :--- |
| `declarativeNetRequest` | Bloque les publicités et domaines de traçage de manière native et haute performance sans exécuter de code JavaScript intrusif. |
| `storage` | Conserve vos réglages, votre liste blanche personnalisée et vos compteurs de protection. |
| `alarms` | Déclenche à intervalle régulier (6h) la vérification et le rafraîchissement des listes communautaires de phishing. |
| `scripting` | Affiche l'écran de blocage en cas d'attaque critique et compte les publicités supprimées. |
| `tabs` | Permet d'analyser l'URL active afin de calculer l'indice de risque et d'afficher le badge d'alerte. |

---

## 4. Vos droits et contrôle de vos données

- **Effacement complet :** Vous pouvez supprimer à tout moment l'historique complet des alertes, statistiques et signalements via le bouton *"Effacer l'historique"* dans le menu popup ou la page d'options.
- **Désinstallation :** La désinstallation de l'extension supprime instantanément et définitivement l'ensemble des données stockées dans `chrome.storage.local`.
- **Désactivation ciblée :** Vous pouvez activer ou désactiver à votre guise le bloqueur de publicités ou ajuster la sensibilité de l'algorithme depuis la page des options.

---

## 5. Contact & Audits

Le code source de SafeBrowseGov est transparent et auditable. Toute question relative à la sécurité ou à la confidentialité peut être soumise via le dépôt officiel du projet.
