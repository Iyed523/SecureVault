# Threat model — candidat v0.1.0

Ce document décrit les mécanismes du dépôt, leurs limites et les hypothèses de
déploiement. Tests et scanners apportent des observations, pas une preuve
mathématique d'absence de vulnérabilités. Les ADR 0001 à 0009 sont historiques :
leurs mentions « futur » décrivent leur phase, pas toutes les capacités actuelles.

## Actifs et frontières

Actifs : contenus en clair, keyring AES, clé JWT, secret HMAC des quotas,
passwords/hashes, tokens/sessions, métadonnées, sauvegardes et intégrité du code.
Le client est non fiable. HTTP entre dans la couche API, puis les services
contrôlent les cas d'usage ; les repositories accèdent à PostgreSQL. Redis ne
porte que les quotas éphémères, jamais la vérité des sessions. L'application
détient les clés et déchiffre pour une réponse autorisée. La chaîne CI/build et
les opérateurs constituent d'autres frontières de confiance.

| Menace | Protection réellement implémentée | Risque résiduel / hypothèse |
| --- | --- | --- |
| Attaquant non authentifié, brute-force | Argon2id 64 MiB/3/1, vérification dummy, quotas IP/account login et IP register | Pas de DDoS réseau ; validation invalide non comptée ; coût mémoire concurrent ; 409 inscription permet l'énumération ; email non vérifié |
| JWT falsifié ou session révoquée | HS256 fixé, signature/issuer/audience/claims/temps vérifiés, lookup Session lié au user sur chaque accès protégé | Clé JWT et horloge fiables ; JWT signé non chiffré ; une révocation ne retire pas une réponse déjà autorisée |
| Utilisateur authentifié malveillant / IDOR | SQL filtre id ET propriétaire, listes owner-scoped, même 404 absent/tiers, pas d'owner fourni par le client | Pas de garantie d'égalité temporelle ; UUID incorrect donne 422 ; opérateur DB puissant hors contrôle API |
| Vol d'un refresh token | 256 bits aléatoires, SHA-256 seul en base, rotation à usage unique, expiration absolue | Un token brut volé reste utilisable avant détection/révocation ; confidentialité TLS et stockage client nécessaires |
| Replay | Verrou Session puis token ; réutilisation consommée commit la révocation de famille avant 401 | Deux refresh concurrents ou réponse perdue peuvent révoquer une session légitime ; pas de grâce, pas de rate limit avant détection |
| Fuite PostgreSQL en lecture | Contenu AES-256-GCM, nonce aléatoire 96 bits, AAD versions/user/secret, contrainte nonce/version | Titres, emails, hashes, IDs, dates, tailles visibles ; attaque hors ligne des passwords possible ; JWT/AES doivent rester séparés de la DB |
| Modification PostgreSQL | Tag GCM/AAD détectent corruption ou déplacement du blob vers un autre contexte | Titre hors AAD ; restauration d'un ancien blob valide non détectée ; DB compromise en écriture peut altérer comptes/sessions ; pas de protection globale d'intégrité DB |
| Fuite Redis | Clés HMAC avec secret dédié, membres aléatoires, TTL ; aucun password/token/contenu | Corrélation de buckets et timestamps ; possession du secret HMAC permet des essais d'identifiants ; écriture hostile/éviction peut altérer les quotas |
| Redis indisponible | Login/register fail-closed avec 503 ; readiness 503 | Indisponibilité de ces opérations ; refresh/logout restent possibles via PostgreSQL ; redémarrage Redis perd les quotas |
| Compromission AES | Versions de clés, ajout de clé indépendante, PATCH content sous clé active | Clé compromise permet de lire les blobs correspondants ; nouvelle clé ne répare pas les fuites passées ; pas de protection contre compromission totale du serveur avec les clés |
| Fuite par logs/erreurs | Allowlist JSON HTTP, route template, ID serveur, pas de body/query/credentials ; 422 expurgées | Logs tiers et erreurs serveur non intégralement contrôlés ; pas d'effacement mémoire garanti ; accès et rétention des logs à gérer |
| Supply-chain | Pins runtime, digests images/actions, Bandit/pip-audit/Gitleaks/Trivy, permissions CI réduites | Scanners limités aux connaissances/règles disponibles ; huit CVE OS temporairement acceptées ; pinning exige maintenance |
| Suppression et sauvegardes | DELETE owner-scoped, conservation versionnée des clés pour la restauration | MVCC/WAL/backups peuvent conserver des blobs ; pas de suppression cryptographique garantie |

## Hypothèses de déploiement explicites

- Terminaison TLS et protection des accès réseau hors application ; ne pas
  exposer le Compose local tel quel sur Internet. `--no-proxy-headers` reste
  actif ; derrière un proxy, le quota peut viser son IP commune. Aucune nouvelle
  politique de confiance proxy n'est implicite.
- PostgreSQL et Redis accessibles uniquement aux composants autorisés ; comptes,
  ACL, chiffrement transport et sauvegardes à configurer pour l'environnement.
- Générer JWT, HMAC et chaque clé AES indépendamment ; accès opérateur minimal,
  stockage séparé des clés et des sauvegardes. Ne pas utiliser les fixtures CI.
- Conserver `DEBUG=false`, les options Uvicorn sûres, UID 10001, read-only,
  capabilities supprimées et no-new-privileges. Ces barrières n'annulent pas une
  compromission du noyau, du daemon ou du processus qui possède déjà les clés.
- Définir capacité, rétention, RPO/RTO et surveillance avant un déploiement réel.

## Risques acceptés et hors périmètre

Les huit IDs exacts sont dans `.trivyignore.yaml` et l'ADR 0009, expiration
**2026-10-31**. Le scan brut HIGH/CRITICAL précède tout filtrage ; une CRITICAL,
un HIGH corrigible ou non Debian bloque le contrôle JSON. Le gate natif bloque
les autres HIGH non exceptées et les exceptions expirées. Aucun seuil ni aucune
exception ne sont étendus par cette phase.

MFA, reset password, email verification, KMS, rotation planifiée, chiffrement
côté client, réchiffrement global, audit immuable et déploiement cloud sont hors
périmètre. Voir le [runbook](operations.md) pour la rotation manuelle et la
[revue](release-readiness.md) pour les preuves de validation disponibles.
