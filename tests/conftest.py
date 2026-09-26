import os

# Valeur publique fictive pour les tests, jamais une clé de déploiement.
# Avant la collecte : app.main construit Settings lors de son import.
os.environ["JWT_SECRET"] = "0123456789abcdef" * 4
