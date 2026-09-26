# ADR 0005 — Refresh tokens, rotation et logout

Statut : implémenté pour revue de la Phase 6.

- Refresh token opaque de 256 bits : `secrets.token_hex(32)`, soit 64 caractères
  hexadécimaux minuscules. Aucun identifiant ni timestamp incorporé. Le brut
  reste en mémoire et dans la réponse HTTP ; seul `hashlib.sha256` de sa valeur
  exacte encodée UTF-8 est persisté, sous forme de digest binaire de 32 octets.
  SHA-256 convient à cette valeur aléatoire forte, contrairement à un password
  humain qui nécessite Argon2. Aucune normalisation, aucun sel de lookup.
- La Session est la famille. Le login crée Session et premier RefreshToken
  atomiquement, après Argon2 hors transaction. L'expiration du token initial
  et de chaque remplacement est exactement `Session.expires_at` (30 jours
  après login par défaut). La rotation ne prolonge jamais cette expiration.
- Ordre global : lookup du seul `session_id` par hash sans verrou, puis
  `SELECT Session FOR UPDATE`, puis `SELECT RefreshToken FOR UPDATE` pour la
  rotation, ou mise à jour de la famille pour logout. Les relectures sous verrou
  rafraîchissent le cache ORM. Toutes les mutations de famille se font sous le
  verrou Session ; aucun repository ne commit.
- La rotation vérifie Session/token actifs et non expirés, User existant et
  actif, et token non consommé. Elle crée un nouveau token de la même Session,
  marque l'ancien `consumed_at` et lie `replaced_by_id` au nouvel UUID. Flush,
  création JWT (même user/sid, nouveau jti), réponse, commit, puis retour. Les
  erreurs avant commit rollbackent normalement la transaction. Les tests couvrent
  signature, flush et `before_commit`, sans simuler une panne réseau du COMMIT.
- Replay : un token déjà consommé révoque Session et tous ses tokens non
  révoqués. Motif `refresh_token_reuse`, sans écraser un motif déjà enregistré.
  Un utilisateur inactif provoque la même révocation avec `user_inactive`.
  Le service sort normalement du bloc transactionnel, commit les révocations,
  puis lève l'erreur métier traduite en 401 `Invalid refresh token.`. Cette
  réponse ne distingue aucun motif de refus. `/users/me` vérifie PostgreSQL,
  donc les JWT encore valides cryptographiquement sont eux aussi refusés.
- Logout par possession d'un refresh token connu, même expiré ou consommé,
  sans dépendre d'un access token. Révocation Session puis famille, motif
  `logout` seulement si la Session n'était pas révoquée. Réponse idempotente
  204 vide, également pour un token inconnu. L'historique n'est jamais supprimé
  par logout/replay et conserve les liens de remplacement.
- Les champs de réponse secrets sont exclus du repr. Les requêtes utilisent
  SecretStr, borne 256 caractères, sans regex publique ni transformation.
  Les erreurs 422 de refresh_token sont expurgées comme celles de password.
  Aucun credential/hash n'est loggé. PostgreSQL seul détient la vérité
  d'authentification ; aucun état d'authentification dans Redis.

Limites et compromis : politique stricte, sans fenêtre de grâce. Deux refresh
concurrents du même token sont sérialisés par le verrou Session : le premier
peut réussir, le second constate le replay et révoque la famille. Perdre la
réponse d'une rotation laisse l'ancien token consommé ; le réessayer déclenche
également un replay. Les clients doivent éviter les refresh simultanés.
Une perte de connexion pendant ou juste après COMMIT peut laisser le résultat
transactionnel indéterminé côté client : celui-ci ne doit pas supposer que
l'opération n'a pas été persistée. La politique de replay strict reste applicable.
Les invariants de chaîne (même Session, absence de cycles) sont maintenus par
le service ; le schéma SQL ne garantit pas toutes ces propriétés multi-lignes.
Un changement utilisateur après la lecture d'autorisation reste une limite
concurrente, comme en Phase 5. Aucun changement de schéma, dépendance ou secret
de configuration ; les opérations réseau exigent un transport confidentiel.
