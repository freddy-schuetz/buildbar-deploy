# buildbar-deploy

Eigenstaendiger, **isolierter** Desktop-Deploy-Dienst fuer buildbar. Laeuft als eigene
Coolify-App unter `deploy.buildbar.at`. **Faengt den mcp-hub (Web-Part) nicht an.**

Zweck: Claude-Code-**Desktop**-Teilnehmende veroeffentlichen ihr Frontend **account-frei**
auf der buildbar-EU-Infra, aus einem **privaten** GitHub-Repo.

## Ablauf (Client = Desktop-Claude, Event-Passwort noetig)
1. `gh repo create <user>/buildbar-frontend-<slug> --private --source=<dir> --push`
2. `POST /prepare {repo, password}` -> `{deployId, public_key}`
3. `gh api repos/<owner>/<name>/keys -f title=buildbar-deploy -f key="<public_key>" -F read_only=true`
4. `POST /publish {deployId, base_dir, env, password}` -> `{url: https://app-xxxx.buildbar.at}`

Der Dienst erzeugt das Deploy-Schluesselpaar selbst; der **Private Key bleibt server-seitig**
(nur in Coolify registriert), der Client haengt nur den Public Key ans Repo.

## ENV
`NRW_GATE_PASSWORD` (Gate), `COOLIFY_TOKEN`, `COOLIFY_API` (`http://coolify:8080/api/v1`),
`COOLIFY_PROJECT`, `COOLIFY_SERVER`, `DEPLOY_DOMAIN_BASE` (`buildbar.at`), optional `DATA_FILE`.

⚠️ **Keine Secrets ins Frontend-Repo** — nur `NEXT_PUBLIC_*` im Code, alles andere als Deploy-`env`.
