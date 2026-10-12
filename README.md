# Team Manager backend

## Runtime configuration

Configure these values in the backend hosting environment; do not commit secrets:

- `DATABASE_URL`: persistent database URL. The default is `sqlite:///./database.db` for local SQLite development. Render PostgreSQL URLs using `postgres://` or `postgresql://` are normalized to the Psycopg 3 SQLAlchemy driver.
- `JWT_SECRET_KEY`: use the current signing secret to preserve unexpired sessions; provide at least 32 characters.
- `SUPER_ADMIN_EMAIL`: owner email used only for the one-time bootstrap when no super-administrator account exists. Set it in hosting configuration; there is no source-code default.
- `SUPER_ADMIN_PASSWORD`: one-time bootstrap password used only when no super-administrator account exists. It is stored as a bcrypt hash and cannot reset an existing account at login.
- `CORS_ORIGINS`: comma-separated exact frontend origins, including the deployed Vercel URL.
- `SUPER_ADMIN_NAME`: optional display name used only if the configured owner account is missing during first bootstrap.
- `RESET_RATE_LIMIT_SECRET`: optional stable secret used to hash password-reset rate-limit keys; the JWT key is used when omitted.
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_USE_SSL`: outgoing email transport for password recovery and team invitations.
- `APP_BASE_URL`: deployed frontend origin used to build invitation and reset links.
- `STORAGE_S3_BUCKET`, `AWS_REGION`: optional private S3-compatible storage used only to serve legacy discussion attachments. New discussion photos and voice messages are stored as binary data in `DATABASE_URL` PostgreSQL and served through authenticated API requests.
- `AI_API_KEY`: optional server-only API key for the OpenAI-compatible chat endpoint. No key is configured in this repository, so the assistant returns an explicit unavailable response until configured.
- `AI_CHAT_COMPLETIONS_URL`: optional OpenAI-compatible `/chat/completions` endpoint; defaults to the OpenAI API.
- `AI_MODEL`: optional model name; defaults to `gpt-4o-mini`.
- `AI_DAILY_REQUEST_LIMIT`: optional per-user daily request limit, clamped to 1–50 (default 20).

The configured one-time bootstrap is disabled as soon as any super-administrator row exists. The environment password cannot promote or reset a second account after that point. Preserve the existing owner's database row and password hash.

### Owner account recovery

There is no public HTTP endpoint for owner recovery. A server operator with authorized database access can rotate the password using `python scripts/recover_super_admin.py`. First stop application writes and take a verified backup of the configured database. Run the script in the backend environment with the same `DATABASE_URL`; it prompts for the new password without echoing it, requires exactly one `SUPER_ADMIN` row, updates only that row's password hash, and increments its session version to revoke existing tokens. It does not create accounts or change roles. Never pass the password as an argument or place it in logs. Restart the service after confirming the backup and script result.

## Workspace migration

The initializer creates missing model tables, then applies explicit, repeatable legacy-column, workspace-backfill, and index steps; `create_all()` alone is not treated as an upgrade for existing schemas. SQLite and PostgreSQL are supported. Before applying it to an existing database, make and verify a restorable backup. From this directory, run one of the scripts:

```powershell
python migrations/001_workspaces.py
```

```powershell
python migrations/002_collaboration.py
```

```powershell
python migrations/003_single_super_admin.py
```

The scripts `001_workspaces.py`, `002_collaboration.py`, and `003_single_super_admin.py` all call the shared idempotent initializer. It records revisions `0001_workspaces`, `0002_collaboration`, `0003_single_super_admin`, and `0004_database_attachments`. The initializer preserves existing user IDs, password hashes, project IDs, messages, and S3 attachment metadata; legacy role labels and workspace ownership are normalized/backfilled as part of the existing migration behavior. It adds a nullable binary column for new database-backed attachments without moving or deleting existing S3 objects. It checks for multiple super-administrator candidates before schema or account changes and aborts without changing roles or accounts if duplicates exist. The final expression-based unique index is compiled for SQLite or PostgreSQL. No database reset is used.

Run the migration before deploying the new API code. The backend startup currently calls the same schema initializer, so starting the API also attempts this index creation. Do not start it against a production database until its backup is verified and the existing super-admin count has been checked.

## Current API constraints

Public registration creates a project lead and a private workspace. Workspace APIs filter users, projects, and discussions server-side. Only a workspace project lead can create or modify projects and manage member roles. A project lead may delegate task management to a sub-lead; the API enforces that permission. Assigned members can update the state of their own tasks. Super administrators have global read access.

Global administration is restricted to the super-admin role: `/admin/overview`, `/admin/users`, `/admin/workspaces`, and `/admin/projects` provide global read access; workspace rename/owner transfer and project create/update are privileged operations. Owner transfer only accepts an existing member of that workspace. These APIs intentionally provide no global delete operation.

The current hosted database configuration must use persistent storage. SQLite on an ephemeral hosting filesystem will not survive instance replacement; configure a persistent volume or a managed database before production use.

Password recovery and invitations remain unavailable until the email variables and frontend base URL are configured and SMTP delivery is verified. The API returns a neutral password-recovery response either way. Team-member accounts are created only after the invitation email can be sent; recipients set their own password through the single-use, 48-hour activation link.

Discussion photos are validated server-side (magic bytes and 5 MiB limit) and stored in PostgreSQL. Voice messages accept validated WebM or Ogg audio containers up to 20 MiB and are stored in PostgreSQL as well. Playback uses an authenticated, workspace-scoped endpoint; pre-existing S3-backed attachments continue to use private signed links. Back up PostgreSQL before deploying the additive attachment migration. The new upload path does not require an S3 bucket.

The AI endpoint makes real requests to the configured provider and can incur API charges. A ChatGPT subscription does not include API usage. No request is made while `AI_API_KEY` is absent. Set a provider-side spending limit as well as the per-user request limit before enabling a paid API. Conversation history is stored in the user's browser; project context sent to the provider is limited to the selected project, and is subject to that provider's data policy.


## Local development and tests

Use standard CPython 3.12 in an isolated virtual environment. On Windows with `uv`, these commands install the interpreter under the current user's local application data directory, create the venv, and install only the locked requirements:

```powershell
uv python install 3.12 --install-dir "$env:LOCALAPPDATA\team-manager-python" --no-registry --no-bin
$tmPythonExe = "$env:LOCALAPPDATA\team-manager-python\cpython-3.12.13-windows-x86_64-none\python.exe"
& $tmPythonExe -m venv .venv
uv pip install --python .venv\Scripts\python.exe -r requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The test suite uses an in-memory SQLite database. It does not need a production database or external API credentials. The repository's `main.py` startup event initializes the schema and attempts migration 003; do not start the server against a real database until that database has a verified backup and its super-administrator count has been checked. Configure runtime secrets only in the local environment or hosting secret manager, never in tracked source files.
