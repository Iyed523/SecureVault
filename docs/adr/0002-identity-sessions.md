# ADR 0002 — Persistance identité, sessions et refresh tokens

Statut : accepté pour la Phase 3.

- Chaque PK est un UUID v4 généré par `uuid.uuid4` lors de l'INSERT SQLAlchemy,
  sans génération côté PostgreSQL ni identifiant séquentiel public.
- Toutes les dates sont `TIMESTAMPTZ`, manipulées avec timezone et en UTC.
  `created_at` / `issued_at` utilisent `now()` PostgreSQL. `updated_at` est
  initialisé de même et mis à jour par SQLAlchemy (`onupdate=func.now()`). Ce
  n'est pas un trigger : les écritures SQL externes devront le gérer explicitement.
- Email : `VARCHAR(254)`, unicité exacte, aucune normalisation ni validation
  syntaxique SQL. Le futur service prendra en charge la normalisation.
  `password_hash` : `VARCHAR(512)` pour une future chaîne PHC ; aucun hashing
  n'est implémenté. Les raisons de révocation sont limitées à 255 caractères.
- `sessions` représente une session utilisateur ; `refresh_tokens` permet de
  conserver plusieurs empreintes successives sans stocker de token brut.
  Le hash prévu est un SHA-256 binaire (`BYTEA`), unique et contrôlé à 32 octets.
  Aucun calcul de hash ni génération de token n'est ajouté.
- Supprimer un utilisateur supprime ses sessions et leurs tokens ; supprimer
  une session supprime ses tokens. Les relations ORM utilisent des cascades
  explicites, `passive_deletes=True` et `lazy="raise"` pour éviter les I/O implicites.
- `replaced_by_id` pointe vers le successeur, avec unicité (plusieurs NULL restent
  possibles), interdiction de l'auto-référence et `ON DELETE SET NULL`. Supprimer
  un successeur préserve ainsi son prédécesseur sans bloquer les cascades. Ce lien
  prépare la rotation sans l'implémenter. L'absence de cycles plus longs et
  l'appartenance à la même session ne sont pas imposées par cette FK simple ;
  le futur service de rotation devra les garantir transactionnellement.
- Les contraintes temporelles imposent une expiration strictement postérieure
  à la création/émission et des dates d'utilisation, consommation ou révocation
  non antérieures à celle-ci. Une révocation après expiration reste possible.
- Noms déterministes des PK, FK, contraintes uniques/check et indexes. Seuls les
  FK de recherche `sessions.user_id` et `refresh_tokens.session_id` reçoivent
  un index supplémentaire ; les PK et UNIQUE disposent déjà de leurs indexes.
- Les repositories reçoivent une `AsyncSession`, ajoutent/flushent ou lisent ;
  aucun `commit`, décision d'autorisation ou traitement HTTP. Les tests utilisent
  PostgreSQL réel, une transaction externe rollbackée par test et des savepoints.
