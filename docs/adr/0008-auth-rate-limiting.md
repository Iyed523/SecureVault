# ADR 0008 — Limitation Redis des tentatives d'authentification

Statut : accepté pour la Phase 9.

## Contexte et décision

Redis est déjà partagé par le cycle de vie de l'application et contrôlé par
`/ready`. Il porte les quotas éphémères sans nouvelle dépendance, table,
migration ni compteur process-local. PostgreSQL conserve exclusivement la
vérité User/Session/RefreshToken/Secret. Aucun lockout persistant.

Chaque bucket est un ZSET évalué par un script Lua constant via EVAL. Redis
exécute atomiquement le retrait des scores expirés, le comptage et la décision.
`TIME` Redis fournit les millisecondes ; aucune horloge API n'est autoritaire.
La fenêtre est `(now_ms - window_ms, now_ms]`. À quota atteint, le script renvoie
le délai de la plus ancienne entrée, arrondi vers le haut en secondes, minimum
1. Il n'ajoute rien et ne renouvelle pas le TTL. Sinon il ajoute un membre
`secrets.token_hex(16)` et applique PEXPIRE pour une fenêtre. Les membres ne
contiennent aucun identifiant. KEYS reçoit la clé, ARGV la limite, la fenêtre
en millisecondes et le membre. Aucun assemblage de Lua depuis une entrée HTTP.

La borne supérieure de ZREMRANGEBYSCORE est inclusive : une entrée exactement
à `now_ms - window_ms` est expirée et supprimée. Un test Redis calcule le cutoff
et retire le score égal dans un seul script Lua de test, sans attente ni deux
lectures d'horloge ; une assertion structurelle le lie à la commande production.

Les limites sont bornées à 100000 et la fenêtre à 86400 s. Les paramètres sont
validés, booléens refusés. La concurrence de plusieurs instances utilisant
le même Redis, secret et configuration respecte le quota de chaque bucket.
Les deux buckets login sont vérifiés successivement, pas en une transaction
globale ; c'est volontaire pour compter l'IP même si account refuse.

Si login-ip est admis puis login-account échoue à cause de Redis, la requête
retourne 503 fail-closed et le service login n'est pas exécuté. L'admission IP
déjà persistée reste comptée : aucune compensation n'est effectuée. Ce choix
volontaire conserve la protection même lors d'une panne entre les deux checks.
Un test HTTP délègue le premier check au vrai Redis puis provoque une
ConnectionError sur le second ; il vérifie l'IP conservée, l'account absent,
l'absence d'Argon2, de nouvelle persistance auth et de fuite dans réponse/logs.

## Identifiants et politiques

Namespace : `securevault:ratelimit:v1:`. Format exact :
`securevault:ratelimit:v1:<bucket>:<hmac_sha256_hex>`.
Le HMAC porte sur `bucket.encode('ascii') + b'\0' + identifier.encode('utf-8')`.
Les buckets fixes sont `login-ip`, `login-account`, `register-ip`. Cette
séparation de domaines évite de réutiliser le même pseudonyme entre politiques.
`RATE_LIMIT_SECRET`, SecretStr non représenté, est obligatoire : 64 caractères
hexadécimaux décodés en 32 octets. Il est généré indépendamment des secrets
JWT/AES. Les clés ne contiennent ni IP ni email bruts ; aucun nouveau log de
refus, de clé complète, de secret, de mot de passe ou de token n'est ajouté.
La pseudonymisation permet encore la corrélation d'un bucket. Une rotation du
secret crée de nouveaux buckets et remet donc pratiquement les quotas à zéro.

Défauts : login 20/IP puis 5/account, inscription 10/IP, fenêtre commune 60 s.
Les quatre paramètres sont configurables. L'account est `LoginRequest.email`
déjà canonicalisé, sans accès DB ni distinction compte existant/inexistant.
Vérifier l'IP en premier borne la création de buckets account depuis une IP
envoyant des adresses aléatoires. Si l'IP refuse, account n'est pas évalué ; si
account refuse, l'IP reste consommée. Succès, mauvaises credentials, absence,
inactivité et doublons comptent dès qu'ils arrivent dans la route. Aucun reset
au succès ni décrément après erreur métier. La validation FastAPI précède le
comptage effectif ; une requête invalide ne consomme pas de quota.

## Refus et disponibilité

429 : `{"detail":"Too many requests."}`, Retry-After entier positif.
RedisError (notamment ConnectionError et TimeoutError, vérifiés dans redis-py
8.1.0) devient 503 `{"detail":"Service temporarily unavailable."}`. Le mode
fail closed protège Argon2, l'inscription et la création d'authentification
lors d'une panne Redis. Pas de capture générale Exception ni de parsing des
messages. Les délais réseau sont ceux du client partagé existant. Les erreurs
de programmation remontent. Redis reste indispensable pour login/register.

Refresh n'est pas limité : une réponse 429 avant la détection stricte du replay
pourrait retarder la révocation immédiate de la famille. Logout n'est pas limité
pour maintenir la révocation disponible même si Redis tombe ; son contrat 204
idempotent demeure. `/users/me`, `/secrets`, `/health` ne passent pas par ce
composant. La sonde `/ready` existante est réutilisée sans duplication.

## Limites et compromis

L'adresse vient uniquement de `request.client.host`, ou `unknown` si absent.
Tous les clients sans adresse partagent alors leur bucket. Les forwarded
headers ne sont pas interprétés. Uvicorn les traite par défaut pour certaines
origines : les commandes Docker/locales fournies ajoutent `--no-proxy-headers`
pour conserver l'adresse du pair. Aucun trusted-proxy parsing n'est développé.
Derrière un proxy, l'adresse de ce dernier peut limiter globalement ses usagers.
NAT/IP partagée peut pénaliser plusieurs comptes ; la seconde barrière account
ne supprime pas ce compromis. Une IP seule ne protège pas contre un botnet.
Le quota account aide contre les tentatives distribuées mais peut temporairement
bloquer un compte visé ; 60 s borne la fenêtre après l'arrêt des tentatives,
sans garantir la disponibilité face à un attaquant continu. Ni CAPTCHA ni
fingerprinting ni protection DDoS réseau dans cette phase.

Le TTL rend les buckets éphémères ; un redémarrage Redis sans persistance,
une éviction ou une rotation de secret peut perdre les quotas. Ce stockage
n'est jamais la source de vérité des sessions. Les refus n'étendent pas les
fenêtres. La validation Pydantic masque les représentations usuelles, sans
effacement mémoire ni garantie de nettoyage de ValidationError.errors()/json().

## Vérification

Tests réels Redis : ZSET, TIME, retrait des scores expirés, Retry-After, TTL non
renouvelé sur refus, suppression contrôlée, 20 appels concurrents pour exactement
5 admissions, clés et membres sans identifiants bruts. Tests HTTP avec PostgreSQL
réel : quotas IP/account/register, canonicalisation, compte connu/inconnu,
absence d'Argon2 et d'écriture User/Session/RefreshToken sur refus, panne Redis,
refresh/replay/logout inchangés. Chaque test nettoie ses seules clés, sans
FLUSHDB. Les anciens tests disposent de quotas élevés ; les tests ciblés ont
des configurations isolées. Reconstruction et smoke Docker valident les
429 login/register avec Retry-After en plus de `/health` et `/ready`.
