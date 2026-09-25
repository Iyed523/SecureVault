# ADR 0001 — Infrastructure et sondes

Statut : accepté pour la Phase 2.

- PostgreSQL 17 est la source de vérité. SQLAlchemy 2.x async et asyncpg assurent
  les accès ; une session est créée par requête via une dépendance dédiée. Le cas
  d'usage sera responsable de ses transactions et commits explicites.
- Alembic utilise la metadata commune et une connexion async adaptée par
  `run_sync`. Aucun modèle métier, `create_all` ou migration vide n'est ajouté.
- Redis 8 et le client officiel `redis.asyncio` sont réservés aux usages
  transverses futurs. Redis n'a pas de persistance dans ce Compose local.
- Le lifespan crée les pools sans imposer de connexion au démarrage, puis les
  ferme. `/health` vérifie uniquement le processus. `/ready` effectue `SELECT 1`
  et `PING` en parallèle, avec une limite de trois secondes par sonde et un
  résultat 503 générique en cas d'échec.
- Compose fournit un environnement local avec ports limités à `127.0.0.1`,
  identifiants fictifs, volume PostgreSQL nommé et API non-root. Les images sont
  fixées par digest et les dépendances runtime par contraintes versionnées.
- Les tests d'intégration utilisent les services réels ; la CI les fournit par
  services GitHub Actions. Le marqueur `integration` permet une exécution locale
  séparée sans masquer des échecs de connexion.
