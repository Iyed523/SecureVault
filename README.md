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

`DATABASE_URL` et `REDIS_URL` sont obligatoires. Avant de démarrer l'API, Alembic
ou Pytest localement, fournir ces variables dans l'environnement ou copier
`.env.example` vers `.env` (valeurs fictives de développement). Ne pas écraser un
`.env` existant. Les variables d'environnement sont prioritaires sur `.env`,
lu depuis le répertoire courant. `DEBUG=false` par défaut ; `LOG_LEVEL` accepte
`DEBUG`, `INFO`, `WARNING`, `ERROR` ou `CRITICAL`.

`DATABASE_URL` utilise `postgresql+asyncpg://` ; `REDIS_URL` utilise `redis://`
ou `rediss://`. Les URLs de `.env.example` ciblent l'hôte. Compose fournit
explicitement ses propres URLs utilisant les noms `postgres` et `redis` ;
le `.env` de l'hôte n'est pas injecté dans l'API conteneurisée.

Les identifiants `securevault` / `local_dev_only` sont fictifs et réservés à
ce Compose de développement. Redis local n'a pas d'authentification ; les ports
publiés sont limités à `127.0.0.1`. Ne pas utiliser cette configuration en production.

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
- `GET /ready` : `SELECT 1` PostgreSQL et `PING` Redis, contrôlés en parallèle
  avec une limite de trois secondes par service. HTTP 200 avec
  `{"status":"ready","services":{"database":"ok","redis":"ok"}}`.
  En cas d'échec : HTTP 503, `status=not_ready`, service concerné à `unavailable`,
  sans URL, credential ou détail d'exception.

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
`upgrade head` avant les tests d'intégration. L'authentification n'est pas encore
implémentée.

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
un `flush`, et le service d'inscription contrôle le `commit` et le rollback.
