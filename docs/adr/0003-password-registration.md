# ADR 0003 — Mots de passe et inscription

Statut : implémenté pour revue de la Phase 4.

- `pwdlib[argon2]==0.3.1` utilise Argon2id via argon2-cffi. Paramètres explicites :
  mémoire 65536 KiB, 3 itérations, parallélisme 1. Format PHC, salt automatique
  de 16 octets et empreinte de 32 octets avec la version installée. Aucun pepper
  faute de stratégie de gestion de ce secret. Aucun salt manuel.
- Mesure locale du 25 septembre 2026 : cinq hashings avec CPython 3.13.14 x64
  standard sous Windows, de 0,195 à 0,246 s, moyenne 0,222 s. Ce relevé vérifie
  l'ordre de grandeur ; ce n'est pas une assertion de performance en CI.
  Les paramètres restent fixes. Le service déporte le calcul dans le pool de
  threads Starlette pour ne pas bloquer la boucle asynchrone.
- Politique : 15 à 128 caractères Python, sans composition imposée. Espaces,
  Unicode et symboles acceptés, y compris 15 espaces. Aucune suppression
  d'espaces, conversion de casse, normalisation Unicode ou troncature. Les
  surrogates isolés, non encodables en UTF-8, sont rejetés explicitement.
  La longueur est contrôlée avant hashing, dans le schéma et la primitive.
- `SecretStr` masque le mot de passe dans les représentations et sérialisations
  Pydantic. Les erreurs HTTP 422 conservent `type`, `loc`, `msg`, mais excluent
  `input` et `ctx` : le gestionnaire FastAPI par défaut peut renvoyer le corps
  brut d'une requête invalide. Aucun log de corps, password ou hash n'est ajouté.
- Pour toute erreur dont `loc` contient `password`, le message HTTP est la
  constante `Invalid password.` ; le message interne n'est jamais recopié.
  `input`, `ctx` et `body` ne sont pas sérialisés. `SecretStr` protège les
  représentations usuelles mais n'efface pas la mémoire : Pydantic et
  `RequestValidationError` peuvent conserver l'entrée originale ou le body.
  Le code applicatif ne doit jamais logger intégralement ces exceptions,
  leur body ou `errors()` lorsqu'une entrée sensible peut être présente.
  Python ne garantit pas l'effacement immédiat des chaînes sensibles en mémoire.
- `email-validator==2.3.0` valide la syntaxe avec `check_deliverability=False`.
  La forme `normalized` subit ensuite `casefold()`, puis un contrôle de longueur
  à 254 caractères. SecureVault choisit une identité insensible à la casse,
  y compris dans la partie locale. Aucun retrait de points ou de `+tags`.
  `dnspython` reste une dépendance transitive de la bibliothèque mais aucun
  lookup DNS n'est effectué dans l'inscription.
- La route `POST /auth/register` valide la requête et appelle le service.
  Elle renvoie 201 avec seulement `id`, `email`, `is_active`, `created_at`.
  Elle traduit l'erreur métier de doublon en 409 avec un message générique.
- Le service reçoit une requête validée et une session sans transaction active.
  `session.begin()` contrôle commit au succès et rollback à l'échec, y compris
  après un flush. Le schéma public est construit avant le commit. Le repository
  conserve uniquement ses responsabilités d'ajout/flush et de lecture.
- Aucun pre-check SELECT : la contrainte PostgreSQL `uq_users_email` est
  autoritaire, même avec deux inscriptions concurrentes. Seule une
  `asyncpg.UniqueViolationError` portant ce nom, encapsulée par SQLAlchemy,
  devient l'erreur métier. Les autres erreurs d'intégrité sont propagées.
  Les tests vérifient ce chemin avec une violation PostgreSQL réelle et la
  réutilisation de la session après rollback ; aucun mock de la base.
- Aucun changement du schéma SQL, aucune session ni aucun token créés.
  Les tests réutilisent la transaction externe et les savepoints de la Phase 3,
  y compris lorsque le service valide sa transaction.

Limites : le code HTTP 409 révèle qu'une inscription est indisponible pour cet
email ; aucun dispositif anti-énumération ou de limitation de débit n'est ajouté.
Le coût mémoire d'Argon2 s'applique à chaque hashing concurrent, et devra être
pris en compte au déploiement. La validation syntaxique ne prouve pas la
possession de l'adresse. Les comptes préexistants non canoniques ne sont pas
convertis : les écritures applicatives d'inscription passent par ce service,
et la contrainte SQL conserve son unicité exacte. La détection de doublons
dépend du driver asyncpg validé par les tests. `password_needs_rehash` inspecte
un hash Argon2 valide sans effectuer de mise à jour automatique.
