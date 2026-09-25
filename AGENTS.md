# Règles de contribution

- Privilégier la simplicité, le typage Python et les fonctions courtes et lisibles.
- Utiliser CPython 3.13 standard 64 bits et l'environnement `.venv` existant.
- Ne pas placer la logique métier dans les routes.
- Respecter les frontières architecturales ; signaler et justifier toute décision
  architecturale importante avant de la modifier.
- Ne jamais ajouter de données sensibles dans Git ou les logs.
- Justifier chaque nouvelle dépendance.
- Accompagner les changements fonctionnels de tests.
- Ne jamais supprimer, ignorer ou affaiblir un test pour rendre la CI verte.
- Vérifier `python -m ruff check .`, `python -m ruff format --check .`
  et `python -m pytest` avec l'interpréteur de `.venv`.
