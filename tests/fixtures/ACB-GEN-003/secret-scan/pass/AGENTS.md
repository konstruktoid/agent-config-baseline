# Agent instructions

Connect with: postgres://${DB_USER}:${DB_PASSWORD}@db.example.com/prod

Generate a new deploy key with `ssh-keygen -t ed25519` and store it outside
the repository. Never commit credentials to this artifact.
