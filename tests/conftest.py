import json
import os

# Valeur publique fictive pour les tests, jamais une clé de déploiement.
# Avant la collecte : app.main construit Settings lors de son import.
os.environ["JWT_SECRET"] = "0123456789abcdef" * 4
os.environ["SECRETS_ENCRYPTION_KEYS"] = json.dumps({"1": "ab" * 32})
os.environ["SECRETS_ACTIVE_KEY_VERSION"] = "1"
os.environ["RATE_LIMIT_SECRET"] = "cd" * 32
os.environ["LOGIN_RATE_LIMIT_PER_IP"] = "100000"
os.environ["LOGIN_RATE_LIMIT_PER_ACCOUNT"] = "100000"
os.environ["REGISTER_RATE_LIMIT_PER_IP"] = "100000"
