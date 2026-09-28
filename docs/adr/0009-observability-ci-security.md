# ADR 0009 — Observabilité minimisée et sécurité CI

Décision autorisée le 2026-09-27, validation finale lors de la reprise Phase 10.

## Menaces et frontières

Les URL concrètes, query strings, corps, credentials et exceptions de drivers
peuvent contenir des secrets. Le middleware ASGI dédié produit un log HTTP de
fin de requête sur `app.http`, sans logique métier ni persistance SQL.
Il génère `uuid4().hex`, ignore tout `X-Request-ID` entrant et expose cet ID via
un `ContextVar`, restauré avec son token dans un `finally`, même si une exception
remonte. La durée utilise `perf_counter`, jamais une horloge murale.

Le formatter JSON construit exactement ces champs : `timestamp` (UTC ISO-8601),
`level`, `logger`, `event`, `request_id`, `method`, `route`, `status_code`,
`duration_ms` (numérique). Il ne sérialise ni `LogRecord.__dict__`, ni message,
arguments, traceback ou extras arbitraires. L'événement est constant :
`http.request.completed`. Toutes les réponses contrôlées sont loggées à INFO,
y compris les 4xx et 5xx, selon le niveau configuré par `LOG_LEVEL`.

La route provient du template enregistré ; une route inconnue vaut
`<unmatched>`. Les méthodes non standard sont remplacées par `<other>` afin de
ne pas recopier une méthode arbitraire contenant une donnée client.
Ni query, body, header, email, IP, identifiant utilisateur/session/secret concret,
clé, hash de mot de passe ou token n'est ajouté. Le logger HTTP possède son
handler JSON et ne propage pas vers les handlers texte. Les logs serveur
Uvicorn restent disponibles ; `--no-access-log --no-proxy-headers` restent
obligatoires dans les commandes documentées et l'image.

Le middleware ajoute `Cache-Control: no-store`,
`X-Content-Type-Options: nosniff`, et `X-Request-ID` aux réponses qu'il traite,
sans modifier leurs bodies, `Retry-After`, `WWW-Authenticate` ou statuts.
Les 204 restent vides. Les bugs non gérés remontent toujours aux tests et au
serveur ; aucun catch-all ne les transforme en succès ou erreur silencieuse.
La réponse 500 produite par le middleware externe de Starlette pour un bug non
géré n'est pas assimilée à une réponse métier contrôlée.

Ce dispositif est une observabilité opérationnelle, pas un audit trail immuable
ou réglementaire. Aucun SIEM, OpenTelemetry, table d'audit, HSTS ou confiance
proxy n'est ajouté. Il ne contrôle pas de futurs handlers externes ni les
messages d'erreur du serveur ou des bibliothèques tierces.

## Image et exécution

Base autorisée :

```dockerfile
FROM python:3.13.15-slim-trixie@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b
```

L'investigation a mesuré Bookworm à 5 CRITICAL et Trixie à 0 CRITICAL,
avec Python 3.13 maintenu et smoke compatible. Debian 13.7 et amd64 ont été
vérifiés dans l'image. Les versions runtime de SecureVault restent inchangées.
Pas d'`apt-get upgrade` générique. Après installation, pip se désinstalle avec
`python -m pip uninstall --yes pip` ; aucune suppression arbitraire de fichiers
système. Les findings msgpack/setuptools associés à pip vendored ne sont pas
acceptés : le scan de l'image sans pip confirme leur disparition.

Le service API seul est `read_only: true`, `cap_drop: [ALL]`,
`security_opt: [no-new-privileges:true]`, sous UID/GID 10001.
Aucun répertoire `/app` writable et aucun tmpfs ajouté sans besoin constaté.
PostgreSQL conserve son volume ; Redis conserve son fonctionnement existant.
Les secrets restent exclusivement au runtime, jamais en ARG de build.

## Politique Trivy

Trivy 0.74.0 est exécuté via son image épinglée par digest, sur une archive de
l'image finale, sans exposer le socket Docker. Le scan brut HIGH/CRITICAL sans
ignore produit l'inventaire en CI. Un contrôle sur ce JSON refuse toute
CRITICAL, tout HIGH corrigible et tout finding non Debian, même si un ID
anciennement accepté change de gravité ou obtient un correctif.
Le gate natif suivant utilise `.trivyignore.yaml` et `--exit-code 1`.
`--skip-db-update` dans le second scan conserve la même base de vulnérabilités,
sans supprimer de finding ; aucun `--ignore-unfixed` n'est utilisé.

Après scan brut validé (44 HIGH OS, 0 CRITICAL, 0 corrigible), seules ces huit
CVE ont une acceptation temporaire autorisée :

| CVE | Source Debian | Situation vérifiée le 2026-09-27 |
|---|---|---|
| CVE-2026-76642 | util-linux | Trixie vulnérable, no-dsa |
| CVE-2026-78408 | util-linux | Trixie vulnérable, no-dsa |
| CVE-2026-78409 | util-linux | Trixie vulnérable, no-dsa |
| CVE-2026-78410 | util-linux | Trixie vulnérable, no-dsa |
| CVE-2026-54369 | acl | no-dsa, correction stable non publiée |
| CVE-2025-69720 | ncurses | no-dsa |
| CVE-2026-16742 | systemd | no-dsa |
| CVE-2026-9538 | perl | postponed, régressions amont à résoudre |

Sources : chaque ID est consultable dans le
[Debian Security Tracker](https://security-tracker.debian.org/tracker/).
L'investigation a vérifié les pages individuelles et les candidats apt : aucun
paquet corrigé dans les dépôts Trixie stables à cette date. Des correctifs
amont/unstable ne signifient pas qu'un paquet stable est disponible.
L'exploitabilité dans SecureVault n'est pas déduite de la seule présence d'un
paquet. Ces risques sont acceptés temporairement, pas déclarés inexistants.

Chaque entrée expire le **2026-10-31** (`expired_at` natif Trivy).
Réévaluation obligatoire avant expiration ; aucune nouvelle CVE acceptée
automatiquement. Aucune CRITICAL ni vulnérabilité corrigible n'est acceptée.
L'inventaire brut reste visible malgré les exceptions du gate.

La gestion native a été vérifiée avec le binaire 0.74.0 : fichier actif → exit 0 ;
copie temporaire avec les huit dates dans le passé → 44 findings, exit 1.
Pas de second mécanisme de calcul d'expiration. Reproduction en PowerShell,
sur une archive déjà scannée et les mêmes montages que le gate :

```powershell
$expired = Join-Path $env:TEMP 'securevault-trivy-expired.yaml'
(Get-Content .trivyignore.yaml -Raw).Replace('2026-10-31', '2000-01-01') |
    Set-Content -LiteralPath $expired
# Monter $expired en lecture seule et remplacer uniquement --ignorefile
# par son chemin conteneur. Le gate doit retourner 1 tant que ces CVE persistent.
```

## Autres scanners et CI

L'extra `security` contient Bandit 1.9.4 et pip-audit 2.10.1, versions réellement
installées et vérifiées. Ils servent à l'analyse statique et à l'audit des
dépendances, sans entrer dans l'image runtime. pip-audit audite strictement les
versions épinglées dans `constraints-runtime.txt`, sans ignore. Les contraintes
restent la référence runtime ; les dépendances conditionnelles peuvent rendre
cet inventaire conservateur par rapport à une plateforme donnée.

Bandit conserve un scan visible de tous les niveaux et bloque sur MEDIUM/HIGH.
Les trois LOW B105 connus sont deux messages publics de validation
(`app/api/errors.py:6-7`) et le PHC public anti-énumération
(`app/services/login.py:18`). Aucune exclusion B105 ni `nosec` ajouté.

Gitleaks 8.30.1 scanne l'historique complet (`fetch-depth: 0`, `--log-opts=--all`).
Le propriétaire a confirmé que la fixture JWT n'a servi qu'aux tests/CI
éphémères. `.gitleaksignore` contient uniquement ce fingerprint, sans valeur :

```text
b3101b54dc137f0f72c59c5b3fdd93dd9efcdad1:.github/workflows/ci.yml:generic-api-key:17
```

Le mécanisme est celui de Gitleaks 8.30.1 ; ni règle ni chemin global exclus.
Les actions checkout/setup-python sont épinglées sur les commits résolus depuis
les tags officiels v7/v6. Les scanners Docker sont épinglés par digest.
CI : permissions `contents: read`, timeouts, concurrency, credentials checkout
non persistés, triggers push/pull_request et aucun pull_request_target.
Seul le job de tests utilise PostgreSQL et Redis réels. Dependabot weekly
sur pip/docker/github-actions, cinq PR simultanées par écosystème, sans auto-merge.

Les scanners ne prouvent pas l'absence de vulnérabilité. Une nouvelle CRITICAL,
un HIGH corrigible, un nouvel ID non autorisé, un vrai secret suspect ou un
finding Bandit MEDIUM/HIGH réel exige investigation et décision, pas une
extension automatique des exceptions.
