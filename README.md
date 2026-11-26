# Local Agent Harness v1.1 (Stage 9 development branch)

Personal local CLI coding agent using `mlx-code==0.0.42` and a local OpenAI-compatible inference endpoint.

## Requirements

- macOS Apple Silicon
- Python 3.12.8+
- `uv`
- Docker Desktop running
- `mlx-code==0.0.42` in the project environment
- Model server listening at `http://127.0.0.1:8001` by default

## Install / upgrade

For a new checkout:

```bash
uv sync
```

For the Stage 6–8 one-shot upgrade, use the supplied `upgrade-to-v1.sh` bundle script. It creates a source backup, installs the overlay, runs tests and diagnostics, and restores the previous source files if validation fails.

## Configuration

The default user configuration is:

`~/.config/local-agent-harness/config.toml`

See `config.example.toml`. Environment variables override TOML values:

| Setting | Environment variable | Default |
|---|---|---|
| endpoint | `LAH_ENDPOINT` | `http://127.0.0.1:8001` |
| Docker image | `LAH_DOCKER_IMAGE` | pinned Python 3.12 slim digest |
| timeout | `LAH_SANDBOX_TIMEOUT` | `60` |
| memory | `LAH_DOCKER_MEMORY` | `512m` |
| CPUs | `LAH_DOCKER_CPUS` | `1` |
| PID limit | `LAH_DOCKER_PIDS_LIMIT` | `64` |
| retained output | `LAH_MAX_OUTPUT_BYTES` | `1048576` |

Example:

```bash
mkdir -p ~/.config/local-agent-harness
cp config.example.toml ~/.config/local-agent-harness/config.toml
```

Or specify a configuration file:

```bash
lah --config ./my-local-agent.toml
```

## Diagnostics

```bash
lah --doctor --project .
```

The doctor checks Python, Docker CLI/daemon, sandbox image presence, project root, and local inference endpoint reachability. An unavailable inference endpoint is a warning; Docker daemon and image availability are required.

## Run

Start the model server in terminal 1:

```bash
mlc --model mlx-community/Qwen3.5-4B-OptiQ-4bit --leash none
```

Start the harness in terminal 2:

```bash
uv run lah --project .
```

Enable write tools:

```bash
uv run lah --project . --write
```

## Commands

| Command | Purpose |
|---|---|
| `/help` | Show help |
| `/new` | New session |
| `/sessions` | List sessions |
| `/resume ID` | Resume session |
| `/memory` | List saved memories |
| `/remember TEXT` | Save memory |
| `/search TEXT` | Search memory |
| `/audit` | Show security audit events |
| `/sources` | List fetched web sources and citation URLs |
| `/backup` | Create consistent SQLite backup |
| `/restore PATH` | Restore backup after explicit `RESTORE` confirmation |
| `/write on` | Enable Write/Edit/Bash |
| `/write off` | Disable Write/Edit/Bash |
| `/quit` | Save and exit |

A restore creates a pre-restore database copy and requires restarting the harness afterward.

## Security model

- Read, Write, Edit, Grep, Find, Ls, and Bash execute against a filtered Docker workspace snapshot.
- Docker uses `--network none`, read-only container rootfs, dropped Linux capabilities, no-new-privileges, non-root UID/GID, PID/memory/CPU limits, tmpfs `/tmp`, and bounded retained output.
- The sandbox image is pinned by digest by default.
- Filesystem gateway installation fails closed if a required tool is missing.
- Approval is one-time per tool call. Bash always requires approval; Edit and overwrite operations require approval.
- Tool-call journal IDs cannot be reused to reset a previous execution.
- SQLite backup/restore uses SQLite's online backup API and integrity checks.

**Limitations:** Docker Desktop is a VM-backed isolation boundary, not a formal guarantee against every host or hypervisor vulnerability. Snapshot synchronization is conservative but cannot provide a universal atomic compare-and-swap guarantee against a concurrently malicious host process. Do not mount secrets into the workspace or treat this as a multi-tenant hostile-code execution service.

## Stage 9 — Web Intelligence (development)

This branch introduces the first host-side web gateway components:

- SearXNG deployment overlay: `docker-compose.web.yml` (loopback-only port binding).
- SearXNG JSON search client.
- HTTP(S) fetcher with public-address DNS validation, pinned resolution, redirect revalidation, decompressed response-size limit, and HTML extraction through Trafilatura.
- Source metadata-only citation store; page bodies are not persisted.
- Web gateway remains a host-process component. The Docker Bash/filesystem sandbox is still network-disabled.

Set a runtime secret (do not commit it) and start SearXNG:

```bash
export SEARXNG_SECRET="$(openssl rand -hex 32)"
docker compose -f docker-compose.web.yml up -d
```

The compose file requires `SEARXNG_SECRET` and binds port 8888 to loopback only. The SearXNG image currently uses the mutable `latest` tag; pin a verified image digest before production use.

Check the JSON endpoint from the host:

```bash
curl 'http://127.0.0.1:8888/search?q=python&format=json'
```

Enable the web tools in `~/.config/local-agent-harness/config.toml` after SearXNG is healthy:

```toml
[web]
enabled = true
provider = "searxng"
```

The remaining web settings can be copied from `config.example.toml`. Then run:

```bash
uv sync
uv run lah --doctor --project .
uv run lah --project .
```

When enabled, the agent receives `WebSearch` and `WebFetch`. Both outbound operations require one-time approval and are recorded in the existing tool journal/security audit. Fetched pages receive session-scoped citation IDs such as `[W1]`; use `/sources` to list their URLs and metadata. Search and fetch caches are in-memory only, with a gateway limit of 30 uncached requests per minute.

The initial integration is implemented on this branch, but has not yet been run against the user's local environment. Run the test suite before enabling it for normal work. The Docker Bash/filesystem sandbox remains network-disabled; do not add the web gateway or Docker socket to that container.

## Tests

```bash
uv run python -m compileall -q harness tests
uv run python -m pytest -q
```

The integration test requires Docker Desktop and the configured sandbox image to be available locally.

## Data locations

SQLite and logs are stored outside the repository under:

`~/Library/Application Support/LocalAgentHarness/<project-key>/`

- `state.sqlite3`
- `backups/`
- `logs/harness.jsonl`

## Version

`1.0.0`
