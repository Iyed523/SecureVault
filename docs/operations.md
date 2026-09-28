# Runbook opérationnel — v0.1.0

Le Compose est un environnement local, avec identifiants DB fictifs et Redis
sans authentification. Les hypothèses d'un autre déploiement sont dans le
[threat model](threat-model.md). Les commandes partent de la racine du dépôt,
en PowerShell avec `.venv` activé. Ne pas afficher `.env`, les tokens, les clés
ou une configuration Compose résolue dans un rapport public.

## Préparer et démarrer

Prérequis : CPython 3.13 standard 64 bits, `.venv`, Docker Linux/Compose v2,
ports locaux 8000/5432/6379. Vérifier `docker version`, `docker info` (Server),
`docker compose version`. L'interface Docker ouverte ne suffit pas.

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -c constraints-runtime.txt -e ".[dev,security]"
```

Créer `.env` depuis `.env.example` uniquement s'il n'existe pas, puis remplir
`DATABASE_URL`, `REDIS_URL`, `JWT_SECRET`, `RATE_LIMIT_SECRET`,
`SECRETS_ENCRYPTION_KEYS`. Les URLs locales de l'exemple ciblent l'hôte ; Compose
remplace ses URLs par les noms des services. Ne pas installer globalement.

Générer **trois matériaux indépendants** dans un terminal privé, sans capture
ni journalisation de sa sortie :

```powershell
# Exécuter séparément pour JWT_SECRET puis RATE_LIMIT_SECRET.
python -c "import secrets; print(secrets.token_hex(32))"
python -c "import secrets; print(secrets.token_hex(32))"
# Keyring AES initial indépendant des deux valeurs précédentes.
python -c "import json,secrets; print(json.dumps({'1': secrets.token_hex(32)}))"
```

Reporter les résultats dans le stockage local protégé ; JSON AES entre quotes
simples dans `.env`, `SECRETS_ACTIVE_KEY_VERSION=1`. Ne pas versionner ce fichier.
Le format 64 hex ne prouve pas l'aléa. Valeurs de test publiques interdites pour
des données réelles. `DEBUG=false`, `LOG_LEVEL=INFO` pour les logs HTTP.
Les défauts TTL/issuer/audience et quotas sont décrits dans le README ; modifier
la configuration requiert de recréer le processus API, pas seulement le fichier.

```powershell
docker compose up -d --wait postgres redis
python -m alembic current
python -m alembic upgrade head
python -m alembic check
docker compose up -d --build --wait api
docker compose ps
```

Sauvegarder avant toute migration d'une base contenant des données utiles.
Head attendu : `b1f2d6535a21`. Aucune création de table automatique au démarrage.
Le check attendu est `No new upgrade operations detected.`.
Pour Alembic depuis l'image : `docker compose run --rm --no-deps api python -m
alembic current` (écrire la commande sur une seule ligne).

## Santé, tests et arrêt

`GET /health` indique le processus ; `/ready` vérifie SELECT 1 et PING avec
trois secondes par service en parallèle. Une réponse 200 n'est pas une preuve
de migration ni de capacité. En panne : 503 générique, jamais les URLs.

Utiliser une base dédiée aux tests. Les fixtures remplacent les secrets et
augmentent généralement les quotas ; les tests ciblés imposent leurs limites.
Les tests de concurrence et le parcours de référence font des commits réels,
puis nettoient uniquement leurs utilisateurs ; les autres utilisent aussi des
transactions externes/savepoints. PostgreSQL et Redis doivent être réels.

```powershell
python -m pip check
python -m ruff check .
python -m ruff format --check .
python -m pytest
python -m alembic current
python -m alembic check
docker compose stop api postgres redis
docker volume inspect securevault_postgres_data --format '{{.Name}}'
```

Ne jamais ajouter `--volumes` à l'arrêt normal. `docker compose down` sans
`--volumes` conserve également PostgreSQL. Redis est éphémère : ses quotas sont
perdus à sa recréation. Le lifespan ferme pools SQL et Redis à l'arrêt API.

## Sauvegarder PostgreSQL

Politique à faire approuver avant usage réel : fixer RPO/RTO, fréquence,
rétention et responsable ; conserver plusieurs générations chiffrées hors
machine, avec accès restreint et contrôles réguliers de restauration. Le dépôt
ne fournit aucun ordonnanceur de backup. Inclure une sauvegarde avant migration
ou changement de clés et enregistrer révision Alembic/version image sans secrets.

Exemple local de dump logique PostgreSQL 17 (pas une copie à chaud du volume).
La copie évite une redirection binaire PowerShell pouvant altérer le dump.
Le répertoire de destination doit être privé, hors dépôt et protégé sur disque :

```powershell
$backupDir = Read-Host 'Répertoire privé de sauvegarde hors dépôt'
$backupName = 'securevault-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.dump'
docker compose exec -T postgres pg_dump -U securevault -d securevault -Fc -f /tmp/securevault-backup.dump
if ($LASTEXITCODE -ne 0) { throw 'pg_dump a échoué' }
docker compose cp postgres:/tmp/securevault-backup.dump (Join-Path $backupDir $backupName)
if ($LASTEXITCODE -ne 0) { throw 'Copie du dump échouée' }
docker compose exec -T postgres rm /tmp/securevault-backup.dump
Get-FileHash (Join-Path $backupDir $backupName) -Algorithm SHA256
```

Ne pas lancer deux dumps simultanés avec ce même chemin temporaire. Le dump
contient emails, titres, hashes et blobs ; le chiffrement applicatif ne dispense
pas de chiffrer/protéger l'archive entière. `pg_dump` ne sauvegarde pas les
rôles globaux ni les clés applicatives : conserver leur procédure de recréation
et les clés séparément, sous contrôle d'accès. Un checksum ne chiffre rien.

## Restaurer exclusivement dans un environnement de test isolé

Ne jamais utiliser le volume `securevault_postgres_data` pour cet exercice.
Utiliser un conteneur neuf, sans port publié, sans montage du volume existant.
L'image exacte provient du Compose versionné. Ne restaurer qu'un dump de
confiance, dans un environnement pouvant traiter ses données sensibles.

```powershell
$restoreName = 'securevault-restore-' + [guid]::NewGuid().ToString('N')
$pgImage = (docker compose config --format json | ConvertFrom-Json).services.postgres.image
$env:POSTGRES_PASSWORD = python -c "import secrets; print(secrets.token_hex(32))"
docker run -d --name $restoreName -e POSTGRES_PASSWORD $pgImage
# Répéter jusqu'au code 0, sans poursuivre si le serveur ne démarre pas.
docker exec $restoreName pg_isready -U postgres
$dumpPath = Read-Host 'Chemin absolu du dump de confiance'
docker cp $dumpPath "${restoreName}:/tmp/restore.dump"
if ($LASTEXITCODE -ne 0) { throw 'Copie du dump échouée' }
docker exec $restoreName createdb -U postgres securevault_restore
if ($LASTEXITCODE -ne 0) { throw 'Création base de test échouée' }
docker exec $restoreName pg_restore -U postgres -d securevault_restore --no-owner --no-privileges --exit-on-error /tmp/restore.dump
if ($LASTEXITCODE -ne 0) { throw 'Restauration échouée' }
docker exec $restoreName psql -U postgres -d securevault_restore -c 'SELECT version_num FROM alembic_version;'
```

Vérifier contraintes, volumes de lignes attendus et accès à des données de
contrôle, puis tester la lecture d'un secret connu via une instance API isolée
munie des clés historiques correspondantes. La restauration SQL seule ne valide
pas le déchiffrement. Ne jamais pointer cette instance sur la base originale.
L'exercice complet avec données réelles et RPO/RTO reste à réaliser par
l'opérateur ; cette phase ne restaure pas le volume existant.
Après vérification du nom exact créé ci-dessus, nettoyer uniquement cet exercice :

```powershell
docker stop $restoreName
docker rm -v $restoreName
Remove-Item Env:POSTGRES_PASSWORD
```

`-v` concerne ici uniquement le conteneur de restauration neuf et son volume
anonyme ; ne pas transposer cette option aux commandes du projet normal.

## Rotation AES v1

1. Inventorier les versions utilisées en base et dans les sauvegardes à conserver.
   Sauvegarder la configuration et les clés historiques dans un coffre séparé.
2. Générer une nouvelle clé indépendante de 32 octets (`token_hex(32)`). Choisir
   une nouvelle version positive inutilisée, au maximum 2147483647.
3. Ajouter la paire au JSON `SECRETS_ENCRYPTION_KEYS` **en conservant les anciennes**.
   Ne jamais réassigner une version, ni dupliquer un matériau sous deux versions.
4. Distribuer le keyring complet à toutes les instances avant de faire écrire
   la nouvelle version ; définir `SECRETS_ACTIVE_KEY_VERSION`, recréer l'API et
   vérifier readiness, nouvelle écriture et lecture d'un ancien secret.
5. Les nouvelles créations et PATCH avec `content` chiffrent sous la clé active
   avec un nouveau nonce. Un PATCH title-only ne rechiffre pas. Les anciennes
   données restent lisibles tant que leur clé historique est disponible.

Il n'existe ni réchiffrement global automatique, ni KMS, ni rotation planifiée,
ni suppression cryptographique garantie. Ne jamais supprimer une ancienne clé
tant que des blobs, WAL, snapshots ou backups à restaurer en dépendent. La perte
d'une clé rend ces contenus illisibles ; une rotation après compromission
n'efface pas les copies déjà volées. Un rollback applicatif doit conserver la
capacité de lire toutes les versions déjà écrites.

## Diagnostic et logs

Redis indisponible : contrôler `/ready`, `docker compose ps`, puis
`docker compose exec -T redis redis-cli ping`. Vérifier connectivité et URL dans
un terminal privé ; ne pas publier la configuration résolue. Login/register
doivent rester en 503 tant que Redis ne répond pas. Ne pas contourner le quota
ni faire de FLUSHDB. Refresh/logout ne dépendent pas du quota Redis.

Pour corréler une réponse, relever son `X-Request-ID` serveur et rechercher cette
valeur dans `docker compose logs --no-log-prefix api`. Les lignes `app.http`
sont JSON ; les autres logs serveur peuvent être textuels. Lire method,
route-template, statut et durée ; jamais ajouter body, query, token ou clé pour
diagnostiquer. Un 500 non géré n'offre pas le même contrat de headers qu'une
erreur contrôlée. Protéger accès, collecte et rétention des logs.

## Security gates

Commandes Bandit/pip-audit dans le README ; Gitleaks et Trivy épinglés et commandes
exactes dans `.github/workflows/ci.yml`. Gitleaks historique ne couvre pas les
fichiers non committés : compléter par un scan `dir` de ces fichiers avant revue.
Trivy : archive de l'image finale, scan brut JSON HIGH/CRITICAL sans ignore,
`scripts/check_trivy_report.py`, puis gate avec `.trivyignore.yaml` et même DB.
La CI crée ce JSON dans le répertoire temporaire du runner et l'analyse ; elle
ne publie pas d'artifact de conservation du rapport brut. Conserver les rapports
locaux de validation si une traçabilité durable est nécessaire.
Huit exceptions exactes jusqu'au **2026-10-31**, aucune extension automatique.
Une nouvelle vulnérabilité exige arrêt et investigation, jamais un seuil abaissé.
