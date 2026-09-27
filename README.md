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

`DATABASE_URL`, `REDIS_URL`, `JWT_SECRET` et `SECRETS_ENCRYPTION_KEYS` sont obligatoires. Avant de démarrer l'API, Alembic
ou Pytest localement, fournir ces variables dans l'environnement ou copier
`.env.example` vers `.env` (valeurs fictives de développement). Ne pas écraser un
`.env` existant. Les variables d'environnement sont prioritaires sur `.env`,
lu depuis le répertoire courant. `DEBUG=false` par défaut ; `LOG_LEVEL` accepte
`DEBUG`, `INFO`, `WARNING`, `ERROR` ou `CRITICAL`.

`DATABASE_URL` utilise `postgresql+asyncpg://` ; `REDIS_URL` utilise `redis://`
ou `rediss://`. Les URLs de `.env.example` ciblent l'hôte. Compose fournit
explicitement ses propres URLs utilisant les noms `postgres` et `redis` ;
`JWT_SECRET`, `SECRETS_ENCRYPTION_KEYS` et `SECRETS_ACTIVE_KEY_VERSION` sont repris
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
 python -m uvicorn app.main:app --reload --host 127.0.0.1 --no-access-log
```

Arrêter auparavant l'API Compose si elle occupe le port 8000 :
`docker compose stop api`.
`LOG_LEVEL` contrôle le logging applicatif ; Uvicorn utilise `--log-level`.

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
