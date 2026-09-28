# SecureVault

API REST FastAPI, **en développement**. Le socle inclut PostgreSQL 17,
SQLAlchemy async, Alembic, Redis 8 et les sondes de disponibilité.

## Prérequis

- CPython 3.13.x standard 64 bits, `pip`, `venv` et Git.
- Docker avec moteur Linux actif et Docker Compose v2.
- Ports locaux 8000, 5432 et 6379 disponibles.

## Installation et configuration locale

Depuis la racine, utiliser `.venv` existant. Sur une nouvelle installation
uniquement : `python -m venv .venv` avec CPython 3.13.

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -c constraints-runtime.txt -e ".[dev]"
```

Sous Linux/macOS : `python3.13 -m venv .venv`, puis `source .venv/bin/activate`.

`DATABASE_URL`, `REDIS_URL`, `JWT_SECRET`, `RATE_LIMIT_SECRET` et
`SECRETS_ENCRYPTION_KEYS` sont obligatoires. Avant de démarrer l'API, Alembic
ou Pytest localement, fournir ces variables dans l'environnement ou copier
`.env.example` vers `.env` (valeurs fictives de développement). Ne pas écraser un
`.env` existant. Les variables d'environnement sont prioritaires sur `.env`,
lu depuis le répertoire courant. `DEBUG=false` par défaut ; `LOG_LEVEL` accepte
`DEBUG`, `INFO`, `WARNING`, `ERROR` ou `CRITICAL`.

`DATABASE_URL` utilise `postgresql+asyncpg://` ; `REDIS_URL` utilise `redis://`
ou `rediss://`. Les URLs de `.env.example` ciblent l'hôte. Compose fournit
explicitement ses propres URLs utilisant les noms `postgres` et `redis` ;
`JWT_SECRET`, `RATE_LIMIT_SECRET`, `SECRETS_ENCRYPTION_KEYS` et
`SECRETS_ACTIVE_KEY_VERSION` sont repris
explicitement de l'environnement ou du `.env` local pour l'API conteneurisée.

Générer une clé JWT locale avec une source cryptographique :

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

Placer cette valeur dans `JWT_SECRET` de votre `.env` local non versionné ou
dans l'environnement. Les 64 caractères hexadécimaux représentent 32 octets.
Le placeholder vide de `.env.example` est volontairement invalide. Ne jamais
publier cette valeur. Compose refuse une variable absente ou vide, même pour
les commandes ciblant seulement PostgreSQL/Redis. Les tests utilisent une clé
fictive publique distincte, définie dans leur configuration et dans la CI.
Les valeurs par défaut sont `ACCESS_TOKEN_TTL_MINUTES=15`, `SESSION_TTL_DAYS=30`,
`JWT_ISSUER=securevault`, `JWT_AUDIENCE=securevault-api`. HS256 est fixé en code.

Les identifiants `securevault` / `local_dev_only` sont fictifs et réservés à
ce Compose de développement. Redis local n'a pas d'authentification ; les ports
publiés sont limités à `127.0.0.1`. Ne pas utiliser cette configuration en production.

Générer séparément le keyring AES-256-GCM dans un terminal local privé :

```powershell
python -c "import json,secrets; print(json.dumps({'1': secrets.token_hex(32)}))"
```

Placer le JSON dans `SECRETS_ENCRYPTION_KEYS` (entouré de quotes simples dans
`.env`). Ne jamais versionner ou journaliser cette valeur. Chaque clé comporte
exactement 64 caractères hexadécimaux, soit 32 octets. Les versions sont des
entiers positifs jusqu'à 2147483647, sans doublons. `SECRETS_ACTIVE_KEY_VERSION`
vaut 1 par défaut et doit exister dans le keyring. Le placeholder vide est
volontairement invalide ; Compose exige aussi le keyring pour ses commandes.
Pour changer de clé, ajouter une nouvelle version avec une nouvelle clé et
la rendre active ; conserver les anciennes clés pour lire les anciens secrets.
Ne pas réassigner une version ni réutiliser une même clé sous plusieurs versions.
Cette phase ne réchiffre pas les données existantes. Voir
[ADR 0006](docs/adr/0006-encrypted-secrets.md) pour le format et ses limites.

## Docker Compose

```powershell
 docker compose up -d --build --wait
 docker compose ps
```

Services : API non-root sur le port 8000, PostgreSQL sur 5432, Redis sur 6379.
Compose attend les healthchecks PostgreSQL/Redis avant de lancer l'API.
PostgreSQL conserve ses données dans le volume nommé `postgres_data` du projet ;
Redis est éphémère. Les images sont fixées par digest et les versions runtime
par `constraints-runtime.txt`. Toute mise à jour doit revalider ces contraintes
avec `pip check`, les tests et une reconstruction Docker.

```powershell
 docker compose down
```

Cette commande préserve le volume PostgreSQL. Ne pas ajouter `--volumes` pour
un arrêt normal.

## API locale hors conteneur

Lancer seulement l'infrastructure, puis l'API avec `.venv` activé :

```powershell
 docker compose up -d --wait postgres redis
 python -m uvicorn app.main:app --reload --host 127.0.0.1 --no-access-log --no-proxy-headers
```

Arrêter auparavant l'API Compose si elle occupe le port 8000 :
`docker compose stop api`.
`LOG_LEVEL` contrôle le logging applicatif ; Uvicorn utilise `--log-level`.

## Observabilité et sécurité CI

Chaque requête reçoit un `X-Request-ID` serveur (UUID v4 hex, 32 caractères) ;
un identifiant entrant est ignoré. Les réponses traitées portent
`Cache-Control: no-store` et `X-Content-Type-Options: nosniff`, y compris les
erreurs métier contrôlées. Les réponses 204 restent vides.

Le logger HTTP `app.http` produit du JSON à champs explicitement autorisés :
`timestamp`, `level`, `logger`, `event`, `request_id`, `method`, `route`,
`status_code`, `duration_ms`. Les routes utilisent leur template ; une route
inconnue vaut `<unmatched>`. Aucun body, query string, header credential, IP,
email, token ou identifiant de secret concret n'est ajouté à ces logs.
La durée est monotone et le contexte est restauré après chaque requête.
Conserver `--no-access-log --no-proxy-headers` dans la commande Uvicorn.
Les logs d'erreur serveur restent actifs ; ceci n'est pas un audit trail
immuable et ne garantit pas le contenu de futurs handlers externes.

L'image runtime utilise Python 3.13.15 sur Debian Trixie, UID 10001, sans pip
après installation des dépendances. Le service API Compose est en lecture
seule, sans capabilities et avec `no-new-privileges`. Pas de tmpfs nécessaire
au parcours validé ; PostgreSQL et Redis gardent leur configuration existante.

Installer les outils locaux dans `.venv`, puis exécuter :

```powershell
python -m pip install -c constraints-runtime.txt -e ".[dev,security]"
python -m bandit -r app --exit-zero
python -m bandit -r app --severity-level medium
python -m pip_audit -r constraints-runtime.txt --no-deps --disable-pip --strict --progress-spinner off
```

La CI conserve pytest/Ruff et les services réels ; elle ajoute ces gates,
Gitleaks sur l'historique complet et deux scans Trivy de l'image finale :
inventaire HIGH/CRITICAL non filtré puis gate avec exceptions exactes expirant
le 2026-10-31. Toute CRITICAL ou vulnérabilité corrigible bloque avant les
exceptions. Huit risques OS temporaires restent suivis dans
[l'ADR 0009](docs/adr/0009-observability-ci-security.md), qui documente aussi
les trois LOW Bandit et l'unique fingerprint Gitleaks de fixture autorisé.
L'image n'est pas présentée comme sans vulnérabilité. Dependabot vérifie chaque
semaine pip, Docker et GitHub Actions, sans auto-merge.

- `GET /health` : liveness, HTTP 200 avec `{"status":"ok"}`, même si les services
  sont indisponibles. Le démarrage ne nécessite pas de connexion aux services.
- `POST /auth/register` : inscription avec `email` et `password`. Email validé
  sans DNS puis canonicalisé ; mot de passe de 15 à 128 caractères, conservé
  sans transformation et stocké sous forme Argon2id. Réponse 201 contenant
  uniquement `id`, `email`, `is_active`, `created_at`. Doublon : 409 ; entrée
  invalide : 422 sans restitution des valeurs soumises.
- `POST /auth/login` : body JSON `email`/`password`. Réponse 200 contenant
  `access_token`, `refresh_token`, `token_type="bearer"`, `expires_in=900` par défaut.
  Un login réussi crée une Session de 30 jours et un refresh token opaque.
  Credentials incorrects ou compte inactif :
  401 avec `{"detail":"Invalid credentials."}` et `WWW-Authenticate: Bearer`.
- `POST /auth/refresh` : body JSON `refresh_token`, sans access token requis.
  Réponse 200 avec les mêmes quatre champs que le login. Le refresh token est
  à usage unique : chaque rotation le consomme et fournit un remplacement.
  Leur expiration absolue reste celle de la Session, sans prolongation.
  Réutiliser un token consommé révoque toute la Session, ses refresh tokens
  et l'accès via ses JWT. Tout refus retourne 401 `Invalid refresh token.`.
- `POST /auth/logout` : body JSON `refresh_token`, sans access token requis.
  Révoque la Session et sa famille de refresh tokens, y compris avec un ancien
  token consommé. Idempotent : 204 sans body, également pour un token inconnu.
- `GET /users/me` : Bearer obligatoire, réponse 200 avec `id`, `email`,
  `is_active`, `created_at`. Le token et la Session PostgreSQL sont vérifiés à
  chaque appel ; révocation, expiration ou compte désactivé entraînent un 401.
  Aucune écriture de `last_used_at` n'est effectuée.
- `GET /ready` : `SELECT 1` PostgreSQL et `PING` Redis, contrôlés en parallèle
  avec une limite de trois secondes par service. HTTP 200 avec
  `{"status":"ready","services":{"database":"ok","redis":"ok"}}`.
  En cas d'échec : HTTP 503, `status=not_ready`, service concerné à `unavailable`,
  sans URL, credential ou détail d'exception.
- `POST /secrets` : Bearer obligatoire, JSON `title` et `content`, sans propriétaire
  fourni par le client. Titre de 1 à 200 caractères, non exclusivement blanc ;
  contenu de 1 à 65536 octets UTF-8. Aucune normalisation. Réponse 201 avec
  `id`, `title`, `content`, `created_at`, `updated_at`.
- `GET /secrets/{id}` : mêmes cinq champs pour le propriétaire authentifié.
  Un identifiant absent ou appartenant à un tiers retourne le même 404
  `Secret not found.` ; un contenu du propriétaire indéchiffrable retourne
  500 `Secret content unavailable.`. Le contenu est chiffré en base avec
  AES-256-GCM ; titre, propriétaire, identifiants, dates, versions et longueur
  restent visibles. La réponse autorisée contient le contenu en clair : TLS
  est nécessaire en déploiement.
- `GET /secrets` : collection du propriétaire, metadata seulement (`id`, `title`,
  `created_at`, `updated_at`), sans déchiffrement. Réponse `items`, `limit`, `offset`,
  `has_more`, sans total. `limit` vaut 20 par défaut (1–100), `offset` vaut 0
  (0–9223372036854775807, borne technique PostgreSQL). Ordre `created_at DESC,
  id DESC`. Les pages peuvent se déplacer, omettre ou répéter un item si des
  écritures interviennent entre deux requêtes.
  `q` facultatif recherche une sous-chaîne dans le titre uniquement, sans strip
  ni normalisation, avec `ILIKE` selon la collation PostgreSQL ; `%`, `_` et `\`
  sont littéraux. `q` contient 1–200 caractères, non exclusivement blancs,
  UTF-8 valide et sans U+0000. Aucune recherche dans le contenu chiffré.
- `PATCH /secrets/{id}` : `title` et/ou `content`, au moins un champ, sans `null`
  ni champ supplémentaire. Réponse 200 contenant uniquement les quatre champs
  de metadata. Une modification du titre ne chiffre ni ne déchiffre le contenu.
  Fournir `content`, même identique, chiffre avec un nouveau nonce et la clé
  active, en conservant l'identifiant et la construction AAD. C'est uniquement
  cette opération qui peut faire passer un ancien secret à la nouvelle clé.
  Un tiers ou un identifiant absent retourne 404 `Secret not found.`.
  Une collision nonce/clé retourne 500 `Secret could not be stored.` après rollback.
- `DELETE /secrets/{id}` : propriétaire, 204 avec body vide. Un tiers, un secret
  absent ou déjà supprimé retourne le même 404 `Secret not found.`. La suppression
  SQL ne garantit pas l'effacement physique immédiat dans WAL, backups ou snapshots.

Les choix CRUD et recherche sont détaillés dans
[ADR 0007](docs/adr/0007-secret-crud-search.md).

## Limitation des tentatives d'authentification

`POST /auth/login` et `POST /auth/register` utilisent le client Redis partagé
pour une sliding window log atomique : Sorted Set, script Lua et temps serveur
Redis (`TIME`). Les quotas sont communs aux instances API partageant Redis,
le secret HMAC et la même configuration ; aucun compteur process-local.

| Variable | Défaut | Bornes |
| --- | --- | --- |
| `RATE_LIMIT_WINDOW_SECONDS` | 60 | 1–86400 secondes |
| `LOGIN_RATE_LIMIT_PER_IP` | 20 | 1–100000 |
| `LOGIN_RATE_LIMIT_PER_ACCOUNT` | 5 | 1–100000 |
| `REGISTER_RATE_LIMIT_PER_IP` | 10 | 1–100000 |

Les paramètres doivent être entiers ; les booléens sont refusés.
`RATE_LIMIT_SECRET` est obligatoire : générer **séparément** 32 octets avec
`python -c "import secrets; print(secrets.token_hex(32))"` dans un terminal privé.
Placer les 64 caractères hexadécimaux dans l'environnement ou le `.env` ignoré.
Ne pas réutiliser JWT_SECRET ni une clé AES. Le placeholder vide est invalide,
et Compose exige sa présence. Une rotation de ce secret change les buckets ;
les anciens expirent, mais les quotas repartent sur de nouvelles clés.

Le login vérifie l'IP avant l'email canonique du `LoginRequest`. Une IP refusée
ne crée aucun bucket account. Si l'IP passe mais le compte refuse, la tentative
IP reste comptée. L'inscription utilise uniquement l'IP. Toutes les tentatives
syntaxiquement valides arrivées dans la route comptent : succès, mauvais mot de
passe, compte absent/inactif et doublon d'inscription. Aucun reset au succès.
Les entrées rejetées par validation FastAPI ne sont pas comptées.

Un quota atteint retourne 429 `{"detail":"Too many requests."}` et
`Retry-After`, entier positif arrondi vers le haut depuis l'expiration de la
plus ancienne tentative encore dans la fenêtre (minimum 1 seconde). Un refus
n'ajoute pas de membre ni ne renouvelle le TTL. Une panne Redis retourne 503
`{"detail":"Service temporarily unavailable."}` : fail closed avant Argon2,
inscription et création de Session/RefreshToken. Les erreurs de programmation
ne sont pas masquées. `/ready` continue sa vérification Redis existante.

Les clés `securevault:ratelimit:v1:<bucket>:<hmac_hex>` utilisent HMAC-SHA256
sur `bucket + NUL + identifiant UTF-8`, avec le secret dédié. Ni email ni IP
bruts dans Redis : les membres sont des valeurs aléatoires indépendantes de
16 octets, les scores des timestamps millisecondes, et chaque bucket a un TTL.
Cette pseudonymisation ne supprime pas la corrélation dans une même fenêtre.
Le secret utilise SecretStr, est absent des représentations en clair et des
logs. Comme les autres secrets Pydantic, les données structurées de
`ValidationError.errors()/json()` peuvent contenir les entrées : ne pas les
journaliser. Aucune garantie d'effacement mémoire n'est revendiquée.

L'IP vient exclusivement de `request.client.host` ; sans client, tous partagent
`unknown`. Les headers Forwarded, X-Forwarded-For et X-Real-IP ne sont pas
interprétés. Les commandes Uvicorn fournies désactivent aussi leur traitement
avec `--no-proxy-headers` : conserver cette option tant qu'aucune politique
trusted proxy n'est définie. Derrière un proxy, son adresse peut devenir celle
du bucket ; NAT/proxy partagé peut donc pénaliser plusieurs utilisateurs.
Un botnet distribué n'est pas arrêté par le seul quota IP : le quota account
ajoute une seconde barrière, mais permet aussi à un attaquant de limiter
temporairement un compte ciblé. La fenêtre par défaut de 60 s borne cet effet
après l'arrêt des tentatives ; des tentatives continues peuvent le prolonger.
Ce dispositif n'est pas une protection DDoS complète.

Refresh reste volontairement sans limite : un 429 avant le service pourrait
retarder l'observation d'un replay et la révocation immédiate de sa famille.
Logout reste disponible pour révoquer les sessions même en panne Redis.
`/users/me` et `/secrets` ne sont pas limités. Aucun lockout persistant ni
changement PostgreSQL. Voir [ADR 0008](docs/adr/0008-auth-rate-limiting.md).

La configuration globale de test utilise des quotas de 100000 et un secret
public fictif ; les tests Phase 9 utilisent de petits quotas isolés. Les tests
Redis ne font pas de FLUSHDB : ils nettoient uniquement leurs propres clés.

## Alembic

Depuis l'hôte, PostgreSQL démarré et `.venv` activé :

```powershell
 python -m alembic current
 python -m alembic upgrade head
```

Ou dans l'API démarrée : `docker compose exec api python -m alembic current`.
Alembic lit la configuration centralisée et `Base.metadata` via une connexion
async. La révision `296081feebfa` crée `users`, `sessions` et `refresh_tokens`
avec leurs contraintes et indexes. `python -m alembic check` vérifie la cohérence
avec les modèles. Aucune table n'est créée au démarrage de l'API ; exécuter
`upgrade head` avant les tests d'intégration.

La révision `b1f2d6535a21`, descendante de `296081feebfa`, ajoute `secrets`,
son index propriétaire, sa FK avec suppression en cascade et ses contraintes
de longueur, de versions positives et d'unicité `(key_version, nonce)`.

Exemple de header pour `/users/me` (remplacer le placeholder localement) :

```http
GET /users/me
Authorization: Bearer <access_token_obtenu_localement>
```

## Tests et lint

Tests rapides sans Docker :

```powershell
 python -m pytest -m "not integration"
```

Tests d'intégration (PostgreSQL et Redis réels, sans mocks ni SQLite) :

```powershell
 docker compose up -d --wait postgres redis
 python -m alembic upgrade head
 python -m pytest -m integration
```

Toute la suite, avec l'infrastructure démarrée :

```powershell
 python -m pip check
 python -m ruff check .
 python -m ruff format --check .
 python -m pytest
```

Les tests d'intégration échouent si les services sont absents ; ils ne sont pas
silencieusement ignorés. La CI fournit PostgreSQL/Redis par services GitHub
Actions et exécute toute la suite avec des URLs explicites.

Les tests de persistance utilisent une transaction externe rollbackée par test
et une session jointe via savepoint. Ils ne font pas de nettoyage global des
tables ; utiliser néanmoins une base PostgreSQL de test dédiée dans `DATABASE_URL`.
Les repositories ne valident pas les transactions : leurs méthodes `add` font
un `flush`, et les services contrôlent commit et rollback. Les tests de rotation
utilisent aussi des commits réels et une autre connexion pour vérifier la
persistance des révocations ; ils nettoient uniquement leurs propres utilisateurs.
