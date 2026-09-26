# ADR 0004 — Login, sessions serveur et access tokens

Statut : implémenté pour revue de la Phase 5.

- PyJWT 2.15.0 sans extra crypto. HS256 suffit au monolithe actuel, seul émetteur
  et vérificateur. L'algorithme est fixé en code ; le décodage utilise uniquement
  `algorithms=["HS256"]`, jamais une sélection depuis le header reçu.
- `JWT_SECRET` est obligatoire, sans défaut : `SecretStr`, exclu du repr,
  exactement 64 caractères hexadécimaux, convertis par `bytes.fromhex` en
  32 octets. Le format ne prouve pas l'aléa. Génération requise avec
  `python -c "import secrets; print(secrets.token_hex(32))"`. Aucune clé réelle
  versionnée ; Compose exige une valeur explicite. La CI et les tests utilisent
  une valeur fictive publique. Les objets internes d'erreur ne doivent pas être
  loggés intégralement (limite mémoire décrite dans l'ADR 0003).
- Access token de 15 minutes par défaut. Claims obligatoires : `sub` (UUID User),
  `sid` (UUID Session), `jti` (nouveau UUID v4), `type="access"`,
  `iss="securevault"`, `aud="securevault-api"`, `iat`, `nbf`, `exp`.
  La création utilise des datetimes UTC aware, encodés en NumericDate par PyJWT.
  Validation signature, issuer, audience unique (`strict_aud`), présence des neuf
  claims et temps sans leeway. Les dates décodées doivent être des entiers ; les
  identifiants sont convertis en UUID. Le résultat applicatif est structuré.
  Un JWT est signé mais non chiffré : aucune donnée sensible dans son payload.
- Le schéma login réutilise la canonicalisation email sans DNS et `SecretStr`
  strict, avec maximum 128 caractères mais sans minimum de création. Une chaîne
  courte ou vide passe à Argon2 ; un password incorrect produit 401. Les anciens
  passwords courts restent vérifiables. Une chaîne non encodable UTF-8 est
  refusée proprement par la vérification. Aucun changement au hashing des nouveaux
  passwords (15–128) ni à leur valeur.
- Dummy PHC Argon2id public, généré une fois avec l'implémentation du projet,
  paramètres 65536 KiB / 3 / 1. Seul le hash est conservé. La vérification réelle
  ou dummy est exécutée dans le pool de threads avant de distinguer absence,
  mauvais password ou inactivité. Même erreur 401 `Invalid credentials.` avec
  `WWW-Authenticate: Bearer`. Aucun test fragile de comparaison de durées.
- Le service login attend une session SQLAlchemy sans transaction active.
  Une courte transaction de lookup extrait un snapshot UUID/hash/is_active.
  Elle se termine et rend la connexion au pool avant Argon2, exécuté hors
  transaction pour ne pas monopoliser le pool PostgreSQL. La vérification dummy
  reste exécutée pour un email absent. Une nouvelle transaction courte relit User
  depuis PostgreSQL, sans réutiliser l'état du cache ORM : existence, is_active
  et hash identique au snapshot sont requis avant création Session, flush,
  construction JWT/réponse, puis commit. Une erreur de signature après flush
  rollbacke la Session. Aucun commit dans un repository. Le JWT n'est retourné
  qu'après succès du commit. La Session utilise le même `now` UTC pour
  `created_at` et `expires_at=now+30 jours`, avec champs d'audit initialement NULL.
- HTTPBearer avec `auto_error=False` laisse l'application imposer ses 401.
  Chaque accès protégé valide le JWT puis recherche Session par `sid` ET `sub` :
  existence, non-révocation, expiration future ; ensuite User existant et actif.
  La résolution est en lecture seule, sans modification de `last_used_at`.
  `/users/me` expose exclusivement `PublicUser`. Révocation ou désactivation
  rend inutilisable un JWT encore valide lors de la vérification suivante.

Limites : refresh tokens et rate limiting pas encore implémentés. Les comptes
peuvent créer plusieurs Sessions par logins successifs. Le dummy atténue le
retour rapide des emails inconnus sans garantir une égalité de temps globale.
Le coût Argon2 et l'accès PostgreSQL restent nécessaires. Une modification
concurrente après la lecture d'autorisation ne peut pas annuler cette lecture.
Une perte de réponse après commit peut laisser une Session inutilisée. Changer
la clé invalide tous les JWT existants ; aucune rotation de clé n'est implémentée.
Le contrôle accepte les UUID valides, tandis que les émissions créent des jti v4.
Les durées/issuer/audience ont des défauts centralisés ; leur modification relève
de la configuration de déploiement. Aucun changement de schéma SQL.
