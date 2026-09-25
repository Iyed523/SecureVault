# SecureVault

Socle d'une API REST FastAPI. **Projet en développement.**
Seul `GET /health` est implémenté : HTTP 200 et `{"status":"ok"}`.

## Prérequis

CPython 3.13.x standard 64 bits, avec `pip` et `venv`, et Git.

## Installation locale

Depuis la racine du projet, dans PowerShell, créer l'environnement uniquement
s'il n'existe pas encore (remplacer `python` par le chemin de CPython au besoin) :

```powershell
python -m venv .venv
```

Activer l'environnement existant et installer les dépendances :

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Sous Linux/macOS : `python3.13 -m venv .venv`, puis `source .venv/bin/activate`
et la même commande d'installation.

La configuration lit les variables d'environnement et, s'il existe, `.env`
dans le répertoire courant. Les variables d'environnement sont prioritaires.
Les valeurs de développement sont illustrées dans `.env.example` ; aucune copie
n'est nécessaire pour démarrer. `DEBUG` est désactivé par défaut et `LOG_LEVEL`
accepte `DEBUG`, `INFO`, `WARNING`, `ERROR` ou `CRITICAL`.

## Lancement local

Depuis la racine, environnement activé :

```powershell
python -m uvicorn app.main:app --reload --host 127.0.0.1 --no-access-log
```

Endpoint : <http://127.0.0.1:8000/health>.
`LOG_LEVEL` règle les logs applicatifs ; Uvicorn possède son propre réglage
`--log-level`. Les logs d'accès sont désactivés dans cette commande.

## Tests

```powershell
python -m pytest
```

## Ruff

```powershell
python -m ruff check .
python -m ruff format --check .
```
