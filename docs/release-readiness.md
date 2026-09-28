# Revue et checklist — candidat v0.1.0

Revue locale du 28 septembre 2026, branche `phase/11-release-readiness`, base
`6651eea54265f4e29ca9f59652a5df4aa074bfe2`. Dépôt propre au début de la mission.
Aucune modification de production, dépendance, migration ou exception CI.
Ce rapport prépare une revue humaine ; il ne constitue pas un audit professionnel.

## Architecture examinée

- API : adaptation HTTP, dépendances, quotas transverses, traduction des erreurs.
  Les transactions, rotation, chiffrement et décisions métier restent dans les
  services. Les schémas valident les entrées et limitent les réponses.
- Repositories : ajout/flush et requêtes SQL ; aucun commit. Toutes les lectures,
  listes, mutations et suppressions de Secret sont owner-scoped en SQL.
  Les services contrôlent commit/rollback ; la dépendance Secret termine la
  transaction de lecture d'authentification avant le cas d'usage.
- Security : primitives dédiées, sans dépendance vers les routes. Le limiter
  dépend du client Redis réel ; Configuration fournit les paramètres validés.
- Models : contenu uniquement en ciphertext, nonce/versions ; pas de colonne
  plaintext ni refresh brut. Emails, titres et métadonnées restent en clair,
  conformément au threat model. Le dummy PHC et les credentials Compose sont
  des fixtures publiques, pas des secrets de déploiement.
- Infrastructure : engine et Redis au lifespan, fermeture en finally ; session
  SQL par requête. Sondes parallèles bornées. Aucun pool créé par requête.
- Aucun cycle trouvé par analyse des imports internes des 51 modules Python
  (imports TYPE_CHECKING exclus) ; imports et suite complète passent également.
- Petites fonctions actuellement utilisées seulement par les tests :
  `password_needs_rehash`, `SessionRepository.get_by_id`,
  `RefreshTokenRepository.get_by_hash`. Elles sont préexistantes et testées,
  conservées sans refactoring esthétique. Aucun framework d'abstraction ajouté.
- Pas de branche métier conditionnelle à APP_ENV. Les tests utilisent des
  secrets publics et souvent des quotas élevés ; certains injectent des erreurs
  et des sessions transactionnelles. Le nouveau parcours utilise le vrai lifespan,
  les commits et les limites par défaut, sans dependency override ni mock.

## Parcours de référence ajouté

`tests/integration/test_release_journey.py` : inscription A/B, login A,
création/lecture, liste metadata-only, recherche titre, PATCH titre puis contenu,
vérification du contenu et refus GET/PATCH/DELETE de B. Le contenu de A reste
intact après ces refus. Refresh fournit une nouvelle paire et `/users/me`
accepte le nouvel access token. Logout invalide les deux access tokens et les
refresh tokens de la session. Une nouvelle session A permet ensuite de supprimer
le secret ; GET/PATCH/DELETE donnent 404 et la collection est vide.

PostgreSQL/Redis, auth et AES sont réels. Le secret HMAC de test est indépendant
pour isoler ses buckets. Nettoyage en finally des seuls deux utilisateurs et
quatre clés Redis, sans FLUSHDB. Les tests spécialisés existants restent en place.

## Invariants et preuves ciblées

| Invariant observé | Code et tests de référence |
| --- | --- |
| Argon2id, sans plaintext password persisté | `security/passwords.py`, `test_passwords.py`, tests registration |
| JWT strict et contrôle Session/User | `security/tokens.py`, `services/authentication.py`, `test_tokens.py`, `integration/test_login.py` |
| Refresh aléatoire 256 bits, SHA-256 seul persisté | `security/refresh_tokens.py`, `test_refresh_tokens.py`, tests login/refresh |
| Rotation, replay révoquant la famille, logout idempotent | `services/refresh.py`, `services/logout.py`, `integration/test_refresh.py` : durable replay, descendants, old token, locks et rollback |
| AES-256-GCM, nonce aléatoire, AAD user/secret/versions | `security/secrets.py`, `test_secret_crypto.py` : roundtrip/AAD exact, tampering, rotation |
| Isolation A/B, mêmes 404 absent/tiers | `repositories/secrets.py`, tests secrets/CRUD et nouveau parcours |
| Liste metadata-only et recherche title-only | `list_owned`, `test_collection_search_isolation_and_no_decrypt` ; pas de recherche ciphertext |
| Rate limit login/register, Redis fail-closed | `security/rate_limit.py`, tests Redis et `integration/test_auth_rate_limit.py` |
| Pas de quota avant détection replay | Routes refresh/logout, `test_refresh_replay_and_logout_remain_available_without_rate_limiter` |
| Logs minimisés et erreurs privées | Middleware/formatter/handler 422, tests observability/validation, smoke réel |

Ces preuves sont limitées aux chemins et scénarios examinés. Aucune nouvelle
réponse d'erreur n'est introduite par cette phase.

## Cohérence documentaire

README : endpoints réellement présents, Bearer, contrats JSON, pagination,
recherche, 404/429/503 et headers. Threat model : protections/risques/hypothèses.
Runbook : configuration, migrations, sauvegarde/restauration isolée, diagnostic,
rotation manuelle AES. Les neuf ADR ont été relues et gardent leur contexte
historique, sans réécriture ni ADR inventée.

OpenAPI généré : version `0.1.0`, 12 opérations métier/sondes vérifiées, schémas
PublicUser/TokenPair/Secret cohérents avec les réponses et HTTPBearer sur les
routes protégées. Limite préexistante : les erreurs métier et headers middleware
ne sont pas tous déclarés ; le schéma FastAPI générique de validation comporte
`input`/`ctx` optionnels, alors que le handler réel les retire. La documentation
décrit le contrat réel sans prétendre que ce schéma générique est exhaustif.
Ce constat documentaire n'est pas une fuite observée et n'a pas conduit à une
modification de production.

## Validation réalisée

| Contrôle | Résultat |
| --- | --- |
| CI du commit fusionné | Jobs `checks`, `security`, `image-security` et leurs étapes : success |
| PostgreSQL/Redis | Services Compose réels healthy ; tests exécutés sans skip infrastructure |
| Parcours ajouté seul | 1 passed en 4,24 s |
| Suite complète | **472 passed en 98,71 s**, aucun warning Pytest |
| pip check | No broken requirements found |
| Ruff check / format | All checks passed ; 104 files already formatted |
| Alembic current | `b1f2d6535a21 (head)` |
| Alembic check | No new upgrade operations detected |
| Docker | Build final réussi, Python 3.13.15 / Debian 13.7, pip absent |
| Smoke Docker | 15 requêtes : health/ready/register/login/me/create/get/list/search/PATCH titre/PATCH contenu/get/delete/refresh/logout |
| Durcissement effectif | UID 10001, root read-only, CapEff=0, CapBnd=0, NoNewPrivs=1 |
| Headers/logs | IDs serveur uniques, no-store/nosniff, 204 vides ; aucune sentinelle sensible/token/UUID concret/query/access log brut dans les logs capturés |
| Bandit | 3 LOW connus, 0 MEDIUM/HIGH ; gate réussi, aucun nosec |
| pip-audit runtime | No known vulnerabilities found |
| Gitleaks historique | 10 commits analysés, aucune fuite, seul fingerprint autorisé |
| Trivy brut final | 44 HIGH OS, huit IDs autorisés, 0 CRITICAL, 0 HIGH corrigible, aucun HIGH/CRITICAL Python |
| Trivy gate final | Code 0, exceptions inchangées, expiration 2026-10-31 |

CI consultée : [run 36397477032](https://github.com/Iyed523/SecureVault/actions/runs/36397477032).
Elle valide la base fusionnée, pas les changements Phase 11 non poussés.
Image locale testée : `securevault:phase11-final`, ID
`sha256:5929355c748a7685e8811c2b4e6510fa990adb8b985c1aad9d5b94ad7f01469c`.
Rapports bruts locaux : répertoire temporaire `securevault-phase11-validation`
(`visibility.json`, `gate.json`, `bandit.json`). Le scan brut conserve les huit
risques visibles avant filtrage ; la CI ne publie pas ce fichier en artifact durable.

Avertissements observés : daemon Docker avec profil seccomp non standard et
`DOCKER_INSECURE_NO_IPTABLES_RAW` ; pip root pendant build ; pip-audit recommande
des pins avec hashes ; Trivy avertit sur un SBOM tiers et certaines sévérités
fournisseur. Aucun de ces avertissements n'est présenté comme un test échoué,
mais les scanners ne sont pas une garantie exhaustive.

## Checklist proposée avant publication

- [x] Relire les frontières et les invariants ; aucun changement métier ajouté.
- [x] Ajouter et exécuter le parcours réel ; suite complète et Alembic verts.
- [x] Préparer README, threat model et runbook, dont rotation AES et limites.
- [x] Reconstruire et tester l'image durcie ; scanners locaux disponibles exécutés.
- [ ] Faire approuver le diff Phase 11 et les risques résiduels par le Team Lead.
- [ ] Sur autorisation distincte, committer/pousser puis vérifier tous les jobs CI
  du commit exact candidat ; le résultat du commit parent ne suffit pas.
- [ ] Réévaluer les huit CVE avant le 31 octobre 2026 et avant publication si les
  bases de vulnérabilités changent ; ne jamais étendre une exception implicitement.
- [ ] Pour usage de données réelles : valider TLS/réseau/secrets indépendants,
  accès opérateurs, RPO/RTO et restauration isolée avec déchiffrement d'un contrôle.
- [ ] Préparer notes de release et identification du commit/image ; créer tag et
  GitHub Release uniquement sur demande explicite ultérieure.

Aucun commit, push, tag ou GitHub Release n'est créé dans cette mission. Aucune
restauration sur le volume existant n'est effectuée. La restauration documentée
reste une procédure opérateur, non un exercice réalisé dans cette validation.
