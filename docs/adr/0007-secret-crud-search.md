# ADR 0007 — CRUD et recherche des secrets du propriétaire

Statut : implémenté pour revue de la Phase 8.

## Collection et recherche

`GET /secrets` retourne des `SecretSummary` : id, title, created_at, updated_at.
La requête SQL ne charge que ces colonnes ; aucune clé, aucun blob ni contenu
n'est sérialisé. Aucun déchiffrement : un secret corrompu peut toujours figurer
dans la collection et la recherche de metadata, tandis que son GET détail
retourne le 500 contrôlé de Phase 7.

La recherche facultative `q` porte exclusivement sur le titre en clair, par
`ILIKE` substring. L'échappement remplace d'abord `\` par `\\`, puis `%` par
`\%` et `_` par `\_`. Le motif est entouré de `%` et passé comme paramètre lié
SQLAlchemy avec `escape="\\"`. Aucun fragment SQL fourni par l'utilisateur.
`q` partage la validation du titre : 1–200 caractères, non blanc, UTF-8 valide,
sans U+0000. Ni titre ni recherche ne sont stripés ou normalisés. La casse suit
ILIKE et la collation PostgreSQL configurée, sans promesse de normalisation
Unicode universelle. Le contenu chiffré n'est jamais recherché.

Toutes les requêtes contiennent le prédicat SQL `user_id == current_user.id`.
Le repository retourne des objets de persistance ; le service construit les
schémas publics pendant la transaction. Aucun filtrage propriétaire en Python.

## Pagination

Ordre fixe `created_at DESC, id DESC`. `limit` : défaut 20, intervalle 1–100 ;
`offset` : défaut 0, positif ou nul, limité uniquement au BIGINT PostgreSQL signé
(9223372036854775807). Le repository demande `limit + 1` lignes, le service
retourne au plus `limit` items et déduit `has_more` de l'existence du suivant.
Pas de COUNT ni de total. Les paramètres supplémentaires, notamment user_id,
sont refusés par le schéma query.

La pagination offset ne garantit pas un snapshot entre requêtes : insertions
et suppressions concurrentes peuvent déplacer les pages, créer des doublons ou
faire manquer un item. Les grands offsets et recherches substring peuvent être
coûteux ; aucune migration d'index ou pagination cursor n'est ajoutée ici.

## PATCH

La requête partielle est gelée, refuse les champs supplémentaires, `{}` et tout
`null` explicite. Création et PATCH partagent les validations title/content.
La réponse est un SecretSummary sans content.

La transaction de lecture d'authentification est fermée par la dépendance
existante avant le service. Si content est fourni, il est chiffré avant la
transaction de mutation avec l'UUID du path et l'utilisateur authentifié dans
l'AAD, un nouveau nonce, la clé active et le format crypto existant. Cela peut
effectuer un chiffrement inutile pour une ressource absente/étrangère, sans
lecture ou déchiffrement de cette ressource et sans écriture sur celle-ci.

La mutation commence par SELECT filtré par id et propriétaire, FOR UPDATE.
`populate_existing=True` évite d'utiliser un ancien état du cache ORM après
acquisition du verrou. Le verrou sérialise les mutations de la même ligne ;
deux modifications du même champ restent soumises à la dernière écriture.
Il ne remplace pas une détection de conflit côté client.

Seuls les champs fournis sont appliqués. Un title-only update ne touche aucun
champ crypto, même si une nouvelle clé est active. Fournir content le rechiffre
toujours, même si le texte est identique, sans déchiffrer l'ancien contenu.
Ainsi seule une mise à jour content effectue une rotation opportuniste de clé.

Après flush, updated_at est rafraîchi explicitement depuis PostgreSQL pour
construire la réponse avant commit. `onupdate=func.now()` est conservé. Un titre
identique peut ne déclencher aucun UPDATE. `now()` désigne le début de la
transaction PostgreSQL ; ce timestamp n'est pas un compteur de versions.

La reconnaissance structurée de `uq_secrets_key_version` est partagée avec la
création. Une collision entraîne rollback, conservation des anciennes valeurs,
SecretStorageError puis 500 `Secret could not be stored.`. Aucun retry ni nouveau
nonce après collision. Les autres IntegrityError ne sont pas masquées.

## DELETE et erreurs

DELETE filtre directement par id et propriétaire, avec RETURNING id. Le service
contrôle la transaction ; un résultat absent lève SecretNotFound. Le succès
retourne 204 réellement vide après commit. Absent, tiers et suppression répétée
retournent tous 404 `Secret not found.`, comme PATCH et GET détail. Aucun objet
étranger n'est chargé pour une comparaison propriétaire en Python.

Une exception avant commit rollbacke PATCH ou DELETE ; les tests distinguent
explicitement le scénario before_commit d'une panne réseau pendant COMMIT.
La suppression de la ligne ne garantit pas l'effacement physique immédiat :
MVCC, WAL, sauvegardes et snapshots peuvent conserver d'anciennes données.

Aucun changement de modèle, migration, format crypto, dépendance ou logique
Redis. Pas de cache ni d'index de recherche externe ; PostgreSQL reste la source
de vérité. Les captures de logs testent les chemins exécutés, sans garantie sur
de futurs handlers externes.
