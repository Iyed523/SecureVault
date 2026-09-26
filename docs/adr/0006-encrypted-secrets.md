# ADR 0006 — Secrets chiffrés et accès par propriétaire

Statut : implémenté pour revue de la Phase 7.

## Menaces et périmètre

Le chiffrement protège le contenu lors d'une lecture de la base sans accès aux
clés applicatives. Le contrôle SQL du propriétaire protège contre l'IDOR.
AES-GCM détecte une modification du contenu ou de son contexte authentifié.
Cette phase expose seulement création et lecture individuelle authentifiées.

`cryptography==50.0.1` fournit la primitive AESGCM éprouvée ; aucune primitive
cryptographique maison. Les dépendances transitives cffi et pycparser étaient
déjà présentes. Les clés AES sont indépendantes de la clé JWT.

## Format exact version 1

- Clé AES de 32 octets issue du keyring JSON validé au démarrage.
- Nonce neuf de 12 octets obtenu avec `secrets.token_bytes(12)`.
- Plaintext UTF-8 strict, de 1 à 65536 octets, sans transformation.
- `ciphertext` contient la sortie AESGCM, tag de 16 octets inclus.
- AAD : `b"SecureVault:secret" + encryption_version.to_bytes(2, "big")
  + key_version.to_bytes(4, "big") + user_id.bytes + secret_id.bytes`.
  Les entiers sont non signés, les UUID occupent chacun 16 octets. Le préfixe
  fixe et les champs de largeur fixe rendent cette concaténation non ambiguë.
  L'UUID v4 du secret est généré explicitement avant le chiffrement.
- Le titre est volontairement exclu de l'AAD et reste en clair ; il n'est pas
  protégé contre une modification directe en base. Les UUID, propriétaire,
  timestamps, versions, nonce et longueur du contenu restent également visibles.

La version du format et celle de la clé sont distinctes. Les versions de clé
sont positives, limitées à l'Integer PostgreSQL signé (2147483647), sans doublon
JSON ni alias numérique tel que `01` et `1`. La version active doit exister.
Le format courant est 1 ; les formats inconnus sont refusés. Une clé ancienne
peut rester disponible tandis qu'une nouvelle version devient active. Une
version doit toujours désigner le même matériau ; chaque nouvelle version doit
utiliser une clé fraîche. Aucun service de rotation ou réchiffrement n'est ajouté.

Chaque `key_version` identifie un matériau AES distinct dans le keyring.
La validation compare les 32 octets après décodage hexadécimal et refuse un
même matériau sous plusieurs versions, même si la casse hexadécimale diffère.
Cela maintient la cohérence de la barrière PostgreSQL `UNIQUE(key_version, nonce)`
avec l'exigence GCM d'unicité du nonce pour une même clé réelle.

L'unicité SQL `(key_version, nonce)` refuse une collision persistée, sans retry
automatique ni contournement. Elle complète l'aléa de 96 bits ; elle n'empêche
pas le calcul initial d'un chiffrement avec un nonce déjà utilisé. Elle ne
protège pas les réutilisations après restauration de base ou entre bases.
Le contrôle du keyring ne peut pas détecter la réaffectation historique d'une
clé retirée : conserver l'identité des versions reste une règle d'exploitation.

## Transactions et autorisation

Les routes délèguent aux services. Le propriétaire vient exclusivement de
`get_current_user`, qui vérifie JWT, Session et compte. `get_secret_session`
termine par rollback la transaction de lecture ouverte par cette authentification,
avant le use case Secret. Cette dépendance est réservée à ces routes ; elle ne
doit pas suivre une dépendance ayant des écritures à conserver.

Le service de création valide et chiffre avant sa transaction d'insertion.
Seuls les champs chiffrés sont transmis à l'ORM, avec titre et métadonnées.
Le repository fait un flush, jamais un commit. Le service retourne après commit.
Une erreur avant commit rollbacke l'insertion.

Le SELECT de lecture filtre simultanément `id` et `user_id`. Aucun chargement
global suivi d'un contrôle Python. Les valeurs nécessaires sont copiées pendant
la transaction ; le déchiffrement a lieu après sa fermeture, indépendamment
de l'expiration des objets ORM. Un secret absent ou tiers produit le même 404
sans déchiffrement. Un blob substitué à un autre identifiant ou propriétaire
échoue à l'authentification GCM. Un secret propriétaire corrompu produit un 500
générique, sans restitution de l'erreur cryptographique.

## Confidentialité et limites

Le keyring et le contenu entrant utilisent SecretStr ; leurs représentations
ne révèlent pas les valeurs. Le contenu de réponse et les octets chiffrés sont
exclus des repr dédiés. Les erreurs de validation du contenu sont génériques.
Aucune journalisation de contenu, clé, nonce ou ciphertext n'est ajoutée.

SecretStr et `hide_input_in_errors` protègent les représentations usuelles ;
les objets ValidationError peuvent conserver l'entrée originale en mémoire et
dans leurs API structurées. Les erreurs de configuration contenant des secrets
ne doivent jamais être sérialisées ou loggées via `.errors()` / `.json()`.

Les titres contenant U+0000 sont refusés avant PostgreSQL. Une violation de
`uq_secrets_key_version`, identifiée par la cause structurée asyncpg, rollbacke
l'insertion et devient un 500 contrôlé `Secret could not be stored.`, sans retry.
Les autres IntegrityError restent propagées.

Le contenu en clair existe en mémoire Python pendant le traitement et dans
la réponse HTTP autorisée. L'effacement fiable de cette mémoire n'est pas
garanti. Une compromission du processus ou du keyring permet le déchiffrement.
Il ne s'agit pas d'un chiffrement de bout en bout ni d'un coffre KMS/HSM.
TLS, gestion des clés et sauvegardes, protection des logs et des dumps mémoire
restent nécessaires en exploitation. Le chiffrement ne cache pas les métadonnées,
ne prévient pas suppression ou restauration d'un ancien blob valide au même
identifiant et ne constitue pas une garantie contre les canaux temporels.

Les tests vérifient crypto, AAD, limites UTF-8, contraintes PostgreSQL réelles,
requête SQL par propriétaire, absence de déchiffrement tiers, erreurs génériques,
absence de valeurs sensibles dans les logs capturés et rollback avant commit.
Les injections d'erreur ciblent les frontières du service ; elles ne remplacent
pas PostgreSQL et ne simulent pas une panne réseau au moment du COMMIT.
