# AgentsServer

![AgentsDock in action](assets/agentsdock-preview.png)

**AgentsServer is the self-hosted execution backend for
[AgentsDock](https://agentsdock.net).** AgentsDock provides
the polished desktop and mobile chat experience; AgentsServer runs on the
machine that owns your workspaces, Claude Code installation, and Codex CLI.
Together they provide persistent agent chats without routing private project
files through a third-party chat service.

AgentsServer exposes an authenticated HTTP/WebSocket API and streams normalized
Claude/Codex events, files, videos, uploads, scheduled jobs, process inspection,
and persistent tmux terminals to AgentsDock clients.

```text
AgentsDock (Mac, iPhone, iPad, Linux)
        |
        | private HTTP/WebSocket connection
        v
AgentsServer (your workstation or server)
        |
        +-- Claude Code CLI
        +-- Codex CLI
        +-- local workspaces, files, jobs, and tmux sessions
```

This repository is intentionally server-only. It should not contain local chat
state, uploaded files, tokens, compiled caches, private hostnames, or personal
machine paths.

## What It Gives AgentsDock

- Creates and resumes chat sessions for Claude and Codex CLI backends.
- Streams live agent events over WebSocket while preserving a JSONL event
  history on disk.
- Accepts file uploads and serves generated artifacts, including videos.
- Supports queued turns, stop requests, chat forking, context digests, and rough
  history import from provider sessions.
- Recovers oversized Codex provider threads by rolling the same chat onto a
  fresh thread with bounded recent memory when remote compaction fails.
- Creates handoff digests with an actual LLM summarizer; the raw transcript/file
  pack is only internal source material.
- Runs recurring/loop jobs per chat with host load/memory guardrails.
  Archiving a chat pauses every interval, cron, and RRULE job attached to it;
  unarchiving leaves those jobs paused until the user explicitly enables them.
- Gives each live provider turn a private, chat-scoped Jobs/Publish authority
  and rotates it with the logical run during native steering. Failed steering
  restores the predecessor only when rejection is proven safe; stopped,
  uncertain, and restarted runs fail closed.
- Provides optional live process and tmux-pane inspection for active work.
- Hosts one persistent interactive tmux terminal per chat. Clients attach over
  an authenticated PTY WebSocket; disconnecting a client does not stop the
  tmux session, its panes, or processes. Structured actions create, select,
  split, and close individual windows while guarding the final persistent
  window from accidental destruction. Archiving a chat kills this owned tmux
  session and prevents it from being recreated until the chat is unarchived.
- Gives every Claude and Codex turn the owning chat's tmux session name through
  `AGENTSDOCK_TMUX_SESSION` and prompt context. Agents can inspect the current
  pane with `tmux capture-pane` when it is relevant, but are instructed not to
  type into, resize, or destroy the interactive terminal without an explicit
  user request.
- Discovers available runtime models/efforts from the installed CLI tools when
  possible.
- Reports Claude Code and Codex installation, authentication, version, and
  latest-run health separately from basic server connectivity. New turns are
  rejected with an actionable error before timeline activity when their
  selected runtime is unavailable.

## Requirements

- Linux or Apple silicon (arm64) macOS host. The trusted `uv` runtime below
  provisions the release's isolated Python 3.10+ environment. Intel macOS is
  unsupported because the patched cryptography runtime no longer publishes or
  supports x86_64 macOS wheels; `install.sh` rejects that architecture before
  changing state, releases, configuration, or services.
- A trusted, preinstalled `uv` on `PATH` is required for the isolated runtime.
  On macOS, install it with `brew install uv`; on Linux, use your trusted OS or
  package-management environment. The installer never downloads and executes
  a mutable bootstrap script.
- Claude CLI and/or Codex CLI installed and authenticated on the agent host.
- Optional: `tmux`, for the persistent chat terminal, tmux-pane inspection,
  and in-app managed updates. Everything else (chats, turns, jobs, files)
  works without it. `install.sh` offers to install it with Homebrew on macOS;
  elsewhere, install it yourself and rerun `install.sh` any time to enable
  these features.
- Tailscale on the agent host and each client device if you want to use the
  server from another Mac, iPhone, or iPad.
- Optional: a user-level `systemd` service on Linux.

### Optional: tmux

tmux is not required to run AgentsServer, chat with agents, or use jobs,
files, or search. It only backs three features: the persistent interactive
chat terminal, live tmux-pane inspection, and in-app managed updates
(Settings > Install or update AgentsServer in AgentsDock), which needs tmux to
survive the server restarting itself mid-update. `GET /api/health` reports
`capabilities.tmux.available` so clients can grey those features out without
tmux rather than failing.

If tmux is missing, `install.sh` proceeds anyway and prints the install
command for your platform. On macOS with Homebrew installed and an
interactive terminal, it asks first whether to run `brew install tmux` for
you. Install tmux at any time and rerun `install.sh` to pick it up; no state,
release, or service is affected.

## AgentsDock

AgentsDock is the companion client for this server. It provides multiple chats
and folders, queues and scheduled jobs, rich Markdown/code rendering, inline
media, downloads and drag-out, code review, search, notifications, and
persistent per-chat terminals.

Get the client and current installation instructions from
[agentsdock.net](https://agentsdock.net). The macOS desktop app is available
as a Developer ID-signed and Apple-notarized build; Apple-platform test
builds are also distributed through TestFlight.

## Guided Setup

The recommended first install is **AgentsDock > Set up AgentsServer**. The
direct desktop app downloads a pinned release archive, verifies its SHA-256,
and runs the same idempotent installer locally or over an existing SSH key.
The app shows live progress, a finite deadline, cancellation, and a persistent
diagnostic log instead of leaving a setup spinner running indefinitely.

For a manual fallback, clone the repository and run the installer as the user
who will run Claude Code or Codex:

```bash
git clone https://github.com/ZhengyiLuo/AgentsServer.git
cd AgentsServer
./install.sh
```

Before changing state, releases, configuration, or services, the installer
checks for a working, preinstalled `uv` and the platform service command
(`launchctl` on macOS or `systemctl` on Linux), and verifies that the current
user's service domain responds. Missing tools or an unavailable user service
session produce platform-specific guidance and stop the install. The preflight
never invokes a package manager or `sudo` itself, with one opt-in exception:
on macOS with Homebrew present and an interactive terminal, it offers to run
`brew install tmux` if tmux is missing. Declining, running unattended
(`--non-interactive` or no TTY, as with the SSH-driven app flow), or being on
a host without Homebrew all just print the manual `tmux` install command and
continue — tmux is optional, so its absence never blocks setup. See
[Optional: tmux](#optional-tmux) below for what it enables.

After that preflight, the installer uses the trusted `uv`, installs a user-level service,
creates a private access token, verifies authenticated health, and preserves
existing `~/.agentsdock` chat state on every update. Network downloads retry
with bounded timeouts, and the longer runtime/dependency stages print output
and periodic heartbeats with hard deadlines. A failure leaves the active
release unchanged and prints recovery guidance. An install lock prevents a
cancelled or disconnected SSH attempt from racing a retry, and timeout cleanup
terminates the complete dependency-worker process group. Existing
`~/.zenithbot-agent` state is migrated automatically and left behind as a
compatibility link. The installer does not use `sudo`.

If the default port is already held by something other than the AgentsServer
release being replaced, the installer detects that listener before restarting
the user service, reports what it found (with `lsof`, when available), and
selects one of up to 5 higher free ports. It never treats a newly started but
unhealthy AgentsServer as a port conflict; that path still rolls back. A port
chosen this way is called out at the end of the run and reflected in
`AGENTSDOCK_SETUP_RESULT`. Passing `--port` pins an exact port by default;
combine it with `--allow-port-fallback` to opt an explicit port into nearby
selection, or use `--no-port-fallback` to disable selection explicitly.

AgentsDock desktop can run this same installer locally or over an existing SSH
key connection from its first-run setup window. Remote clients should use the
Tailscale URL printed by the installer.

The same guided flow is available later from **Settings > Install or update
AgentsServer**. Rerunning it is the supported app-managed update path: it
replaces the server runtime and restarts the user service while preserving the
access token, configuration roots, chat history, jobs, files, and terminals.
Direct desktop builds can perform local/SSH setup; App Store-sandboxed builds
can configure the server URL and token but cannot launch service installers.

Once a versioned installation is present, AgentsDock can also check and apply
signed releases directly from Settings. The server downloads a release only
from this repository's GitHub Releases page, verifies an Ed25519-signed
manifest and the archive SHA-256, installs into a versioned directory, restarts
the user service, and accepts the release only after authenticated health
passes. The previous healthy release remains available for automatic rollback.

### Team Hub preview

AgentsServer `0.1.25-beta.3` and later can designate one installed server as the
Team Hub host. Team Hub runs inside that AgentsServer process and listener;
there is no second service or separate `uv` command to keep running. For
same-machine use, enable it on exactly one development server with:

```bash
./install.sh --team-hub-host
```

For private remote access, expose only the existing listener through a
tailnet-only Tailscale Serve HTTPS port that Tailscale Funnel cannot use, then
bind the exact canonical URL during the host install. For example:

```bash
tailscale serve --bg --https=8444 http://127.0.0.1:7850

./install.sh --non-interactive \
  --team-hub-tailscale-serve-url \
  https://my-server.my-tailnet.ts.net:8444/api/team-hub
```

The installer persists and verifies the exact Team Hub transport and URL but
does not alter Tailscale configuration. Confirm separately that the exact 8444
mapping appears under `Web` in `tailscale serve status --json`, and run
`tailscale funnel status` to confirm Team Hub's `:8444` mapping is not public;
unrelated mappings may remain untouched. Do not use Funnel, a generic reverse
proxy, or one of Funnel's supported ports
(`443`, `8443`, or `10000`).
The ordinary AgentsServer endpoint and any unrelated Serve/Funnel mappings are
unchanged.

AgentsServer `0.1.25-beta.5` adds an optional bare-IP route. For a fresh host,
the operator may additionally advertise the exact route used by its
authenticated AgentsServer profile:

```bash
./install.sh --non-interactive \
  --team-hub-tailscale-serve-url \
  https://my-server.my-tailnet.ts.net:8444/api/team-hub \
  --team-hub-direct-ip-url \
  http://100.73.184.23:7850/api/team-hub
```

If Serve is not configured on a fresh/disabled host,
`--team-hub-direct-ip-url` selects Direct IP as the primary route. Direct IP is
advanced and unencrypted: the AgentsServer bearer, Teamspace credentials and
messages are plaintext in transit. Literal IP shape is not proof of Tailscale
or identity. The route must be canonical
`http://<literal-ip>:<AgentsServer-port>/api/team-hub`; it cannot use a
hostname, loopback, another port/path, credentials, query or fragment. The
AgentsServer retains this legacy transport for manual host configuration and
rollback continuity. The current desktop filters and refuses Direct-IP routes
instead of offering them for selection; use secure pairing or private Tailscale
Serve. Automatic selection continues to use the advertised Serve primary.

If the host install fails or you abandon this setup, remove only that listener:

```bash
tailscale serve --https=8444 off
```

The host choice and exact primary/Direct-IP routes are preserved by managed
updates and rollback. A fresh server with no Hub database may be designated
directly.
`--no-team-hub-host` stops serving an existing Hub but preserves its data and
managed host binding. It is never silently reactivated. To bring that exact
preserved host back on the same AgentsServer, request the guarded transition:

```bash
./install.sh --non-interactive --reactivate-team-hub-host
```

The installer requires disabled mode, verifies the stored Hub binding against
this server's durable identity without migrating the source database, and
writes and re-verifies a complete pre-reactivation snapshot before changing
configuration or service state. A candidate failure restores that snapshot.
Foreign, unbound, fenced, missing, or concurrently changed state is refused.
The Tailscale Serve or Direct-IP options may be supplied with the explicit
reactivation flag when retaining the corresponding supported origin; ordinary
`--team-hub-host` remains the fresh-state path.

Adding or changing Direct IP on an existing live Hub is intentionally rejected
by the ordinary installer, including a same-version reinstall. That change
needs an authenticated transaction that closes admission and journals the
exact route before restart; do not edit the environment behind a running Hub
and assume update continuity will adopt it.

An existing beta.2 host remains loopback-only during a normal managed update;
an origin change is never inferred from mutable environment state. The remote
command above is for a fresh, disabled server with no Hub database. Do not use
it to re-home existing Team Hub state: changing the origin of an existing Hub
requires a separate signed, snapshot-protected migration. Leave every other
server disabled.

The desktop discovers the separate Hub URL through authenticated AgentsServer
health. `Start Teamspace` asks the active AgentsServer for a short-lived,
one-time enrollment grant and redeems it directly with Team Hub over the
verified Serve origin. The AgentsServer bearer authorizes that one narrow
parent bootstrap-grant endpoint, but it is never accepted as a Team Hub
credential; Team Hub credentials likewise never authorize ordinary
AgentsServer routes. Grant issuance additionally requires the exact configured
private Serve origin and its verified Tailnet identity. Remote clients must
select the designated host's server profile; switching profiles closes
Teamspace instead of carrying its state to another server.

For a loopback host, the equivalent installed command is:

```bash
~/.local/share/agents-server/current/install.sh \
  --non-interactive --team-hub-host
```

The installed release also provides host operator controls; no repository
checkout or separate service is needed. These commands print the path to an
owner-only proof file, never the proof secret itself:

```bash
PYTHONPATH=~/.local/share/agents-server/current \
  ~/.local/share/agents-server/current/.venv/bin/python -m agentsdock_team_hub.cli \
  bootstrap-proof --data-dir ~/.agentsdock/team-hub

PYTHONPATH=~/.local/share/agents-server/current \
  ~/.local/share/agents-server/current/.venv/bin/python -m agentsdock_team_hub.cli \
  device-recovery --data-dir ~/.agentsdock/team-hub \
  --email member@example.com --device-label "Member Mac"
```

Issuing a device-recovery proof immediately revokes every existing device
session and live refresh token for that person. Deliver and redeem the printed
proof path on the replacement device within ten minutes.

Authenticated human owners can list and revoke pending invitations and can
change, suspend, reactivate, or permanently revoke non-owner human memberships;
owner, automation, and self rows are not mutable through this API. Human users
can list and revoke only their own device sessions. Device revocation takes
effect on the next authenticated request and revokes every still-live refresh
token for that device. These controls keep invitation, membership, session, and
audit ledger rows rather than deleting security history. The member,
pending-invitation, and device-session inventory endpoints use opaque,
authenticated keyset cursors with a default page size of 50 and a maximum of
100; callers follow `next_cursor` only while `has_more` is true.

If you override the install or state directory, use the exact operator commands
printed by `install.sh` at the end of a host-mode install.

Team Hub keeps its own credentials and authorization boundary even though it
shares the AgentsServer process. AgentsServer bearer tokens and Team Hub
credentials are mutually non-interchangeable. Team posts and messages are
passive in this preview: agent dispatch and wake-up are not available. Managed
updates snapshot and verify the Hub database, signing key, and local enrollment
proofs before replacement; if the candidate cannot prove the same server and
Hub identities, the installer restores that snapshot before starting the
previous server release.

### Agent Team Network mail

API contract v24 advertises `capabilities.agent_team_mail_v1`. Agent mail is
default-deny: only an ordinary user prompt whose first token is exactly
`/mail` receives a short-lived provider capability. The helper freezes at most
512 currently visible destinations as opaque run-local routes, accepts at most
four sends, and reads the UTF-8 body from stdin so message content does not
appear in process arguments. It creates a passive Team Network Inbox item; it
never starts or steers a chat or agent. Scheduled jobs, synthetic handoffs, and
near-matches such as `/mailbox` do not receive this authority. The provider
mail harness creates message items only; it cannot create new Team Network
requests. Existing request records and the separate Team Hub request lifecycle
remain readable for backward data compatibility.

The additive strict form `/mail server NAME MESSAGE` treats `NAME` as one
case-sensitive token and the remainder as the exact normalized message body.
AgentsServer filters the private route snapshot to active server destinations
whose raw display name exactly equals `NAME`. Zero matches fail as not found;
multiple matches, including equal names on different Team Networks, fail as
ambiguous. A successful strict command exposes only that one opaque route and
permits exactly one idempotent `kind=message` effect with the exact body. It
cannot fall back to an agent destination, a case-insensitive name, a request,
rewritten content, or a second send. Legacy `/mail` remains available for
older clients. Health advertises the strict syntax and feature flags inside
`agent_team_mail_v1`, so clients can discover it without a global API-contract
revision.

## Manual Onboarding

1. Clone this repo on the machine that will run the agents.

```bash
git clone https://github.com/ZhengyiLuo/AgentsServer.git
cd AgentsServer
```

2. Create a Python environment.

```bash
uv venv
uv sync --frozen
```

3. Install and authenticate the backend CLI tools you want to use.

AgentsServer does not bundle Claude or Codex. It shells out to the CLI tools
that are already installed on the agent host. Install the official Claude CLI
and/or Codex CLI, sign in or configure credentials for each, then verify the
commands work in the same shell/user that will run the server:

```bash
command -v claude
claude --version

command -v codex
codex --version
```

If you only want one backend, install only that backend and set
`AGENTSDOCK_BACKEND` accordingly.

4. Start the server locally.

```bash
uv run python agent_server.py serve --bind 0.0.0.0 --port 7850
```

5. Check health from the server machine.

```bash
curl http://127.0.0.1:7850/api/health
```

6. Connect AgentsDock.

Open AgentsDock, enter the server URL printed by the installer, and paste its
access token. The desktop app can also run the installer for you during
first-run setup.

For a client on the same machine, use:

```text
http://127.0.0.1:7850
```

For another Mac, iPhone, or iPad, use Tailscale. Install Tailscale on the agent
host and client device, confirm both devices are in the same tailnet, then use
the server's Tailscale IP:

```text
http://<tailscale-ip>:7850
```

Do not expose port `7850` directly to the public internet. Use Tailscale or
another private network, and set `AGENTSDOCK_AGENT_TOKEN` for shared-token
access control.

## Run Locally

```bash
uv run python agent_server.py serve --bind 0.0.0.0 --port 7850
```

Health check:

```bash
curl http://127.0.0.1:7850/api/health
```

The default state directory is `~/.agentsdock`. Override it when you want
state somewhere else:

```bash
AGENTSDOCK_STATE_DIR=/path/to/state \
uv run python agent_server.py serve --bind 0.0.0.0 --port 7850
```

## Security

Set `AGENTSDOCK_AGENT_TOKEN` to require a shared bearer token for HTTP calls,
uploads, file/video fetches, and WebSocket streams.

```bash
export AGENTSDOCK_AGENT_TOKEN='replace-with-a-long-random-token'
uv run python agent_server.py serve --bind 0.0.0.0 --port 7850
```

Clients should send either:

```http
Authorization: Bearer replace-with-a-long-random-token
```

or `X-AgentsDock-Token`. The legacy `X-ZenithDock-Token` header remains
accepted for existing clients.
Leave the variable unset only for trusted local development.

`install.sh` prints the generated token once, at the end of setup. To see it
again later without reinstalling anything:

```bash
./install.sh --show-token
```

This only reads the existing configuration and exits; it makes no changes.

## Managed server restart

Authenticated clients can discover restart support through the additive
`capabilities.server_restart` v1 health capability and the top-level
`server_instance_id`. Restart is available only when AgentsServer proves that
the running process belongs to the supported launchd or systemd user service
and is executing from the installer's resolved `current` release.

```text
GET  /api/admin/restart
POST /api/admin/restart
```

Both endpoints require the access token in an authorization header; URL token
parameters and browser-originated requests are rejected. POST accepts a small
JSON body containing a UUID `request_id`, the exact
`expected_server_identity`, the exact `expected_server_instance_id`, and
`confirmed: true`. It returns `202` before signaling the managed process.
Replaying the same request ID is idempotent; another pending or recently
completed request is rejected.

A cooperative restart is fail-closed while an active update, active turn,
provisional queue write, provider background task, lifecycle operation, or
HTTP mutation is in flight. Durable queued turns remain queued for recovery
after relaunch. Unmanaged processes cannot use this control.

### Forced (emergency) restart

Adding `force: true` and `force_confirmed: true` to the POST body requests an
emergency restart. It exists for the case where the server is wedged, so it
never refuses or waits on server state beyond authentication, the managed
service proof, and the exact `expected_server_identity` /
`expected_server_instance_id` pair:

- Cooldowns, a pending or stale restart record, an active managed update,
  safety-critical work (Codex maintenance, session deletions, in-flight HTTP
  mutations, goal reconfiguration), and Team Hub snapshot failures are
  overridden and recorded in `forced_audit` instead of rejected.
- `expected_blocker_revision` is optional. A stale or omitted revision is
  audited (`blockers_changed_after_confirmation`, `blocker_revision_omitted`)
  rather than refused, because a wedged server may be unable to serve a fresh
  blocker snapshot at all.
- Every admission lock and probe on the forced path is bounded by a short
  timeout. If one cannot be obtained the audit snapshot is marked
  `snapshot_degraded` and the restart still proceeds. `GET /api/admin/restart`
  and `/api/health` use the same bounded snapshot so they cannot hang.
- The restart journal is best effort: if it cannot be written the restart
  still proceeds.
- SIGTERM is sent from a dedicated thread after the `202` response, and a
  hard-kill watchdog sends SIGKILL a few seconds later if graceful shutdown
  has not finished, so the user service always relaunches the server.

Forced restarts interrupt active agent turns and can leave provider children
to be reaped by the relaunched server; use the cooperative restart when the
server is healthy.

## Remote Access With Tailscale

Remote access is expected to go through Tailscale. This keeps the server
reachable from phones, tablets, and laptops without publishing the raw agent
port on the internet. It's optional: everything else in this README works
without it, so `install.sh` only prints a reminder with the download link
at the end of a successful run when Tailscale isn't already on the host —
it never blocks setup or is installed automatically.

On the agent host:

```bash
tailscale status
tailscale ip -4
```

On the client device, make sure Tailscale is connected to the same account or
tailnet, then set the AgentsDock server URL to:

```text
http://<tailscale-ip>:7850
```

If the browser can open `/api/health` but the app cannot connect, check:

- the client is also connected to Tailscale
- the URL includes the correct port
- the same `AGENTSDOCK_AGENT_TOKEN` is configured in the app
- the server is bound to `0.0.0.0` or the Tailscale interface, not only
  `127.0.0.1`

## Updating AgentsServer

Pull the newest version and rerun the installer. It updates the runtime and
service while preserving the access token and all chat state:

```bash
git pull --ff-only
./install.sh
```

On Linux, inspect the installed service with:

```bash
systemctl --user status agents-server.service --no-pager -l
journalctl --user -u agents-server.service -f
```

On macOS, the installer creates the LaunchAgent
`com.agentsdock.server` and writes logs under
`~/Library/Logs/AgentsServer/`.

### Managed updates from AgentsDock

Managed update endpoints use the same access token as the rest of the API.
Release manifests and archives are also verified with the public Ed25519 key
bundled by the installer, so the endpoint can install only an official signed
AgentsServer release:

```text
GET  /api/admin/update
POST /api/admin/update/check
POST /api/admin/update/start
```

The update runs in a detached tmux session so restarting AgentsServer cannot
terminate its own installer. Progress is written to
`~/.agentsdock/admin/server-update.json`, and installer output is kept in
`server-update.log` beside it. Chat history, files, jobs, tokens, and tmux
sessions remain under the persistent state/configuration roots and are never
placed inside a release directory.

`capabilities.server_updates` v7 defines install-when-idle as a passive,
durable reservation. Chats, messages, terminal connections, settings changes,
and manual restart remain available while the reservation is pending. The
server begins maintenance only when one shared-lock snapshot proves it is
actually idle; that same atomic transition closes new-work admission. A
pending reservation survives a manual restart and is re-armed after startup.
While it is pending it fences nothing: new turns, Force Send, scheduled jobs,
and provider controls are all admitted, and the update simply waits for the
next moment nothing is running. (Releases before 0.1.26-beta.31 parked new
turns behind the reservation; that behavior is gone.)

## Uninstalling AgentsServer

```bash
./uninstall.sh
```

This stops and removes the user service, the versioned release runtime, and
generated configuration (including the access token). It prompts before
making changes unless `--yes` is passed. Chat history, jobs, files, and
terminals under the state directory (`~/.agentsdock` by default) are kept by
default, so a later `./install.sh` picks the same ordinary AgentsServer history
back up. Preserved Team Hub state is intentionally not auto-reactivated in this
beta; re-enable an exact same-server preserved host explicitly with
`./install.sh --reactivate-team-hub-host`, which verifies its durable binding
and takes a rollback snapshot first.
Passing `--purge-state` permanently deletes that too, but always requires an
interactive exact-path confirmation that `--yes` cannot bypass. Before any
change, the uninstaller rejects root, home, broad system/user directories,
path traversal, and overlapping install/configuration/state roots. Like
`install.sh`, it never invokes a package manager or `sudo`. Persistent chat
terminal tmux sessions (named `zd_*`) are left running; list them with `tmux
ls` and remove them yourself if you no longer need them.

## Development Deployment Helper

New installations should use `install.sh`. For a managed installation,
`deploy.sh` copies the complete server runtime into the active release,
compiles it, restarts the configured user service, and checks local health on
the remote host. It is intended for development, not end-user upgrades. It
refuses a designated Teamspace host or a paired secure-peer Teamspace client;
use the signed managed updater for those servers so exact continuity and
versioned rollback remain available.

```bash
./deploy.sh <ssh-host>
```

Optional variables:

```bash
AGENTSDOCK_REMOTE_APP_DIR='.local/share/agents-server/current' \
AGENTSDOCK_SERVER_SERVICE='agents-server.service' \
AGENTSDOCK_AGENT_TOKEN='replace-with-a-long-random-token' \
./deploy.sh <ssh-host>
```

The deploy helper writes to:

```text
<remote-app-dir>/agent_server.py
```

Run `install.sh` before the first deploy so the versioned runtime, environment,
token, and service are present. A reference Linux unit lives at
`systemd/agents-server.service.example`.

## Systemd Template

New installations do not need to copy the template because `install.sh`
creates and manages `agents-server.service` automatically. The template is
provided for inspection and custom deployments.

Manual install flow:

```bash
mkdir -p ~/.config/systemd/user
cp systemd/agents-server.service.example ~/.config/systemd/user/agents-server.service
systemctl --user daemon-reload
systemctl --user enable --now agents-server.service
```

Then check it:

```bash
systemctl --user status agents-server.service --no-pager -l
curl -H 'Authorization: Bearer replace-with-a-long-random-token' \
  http://127.0.0.1:7850/api/health
```

## Useful Configuration

Most settings are environment variables. New configurations should use
`AGENTSDOCK_*`. Historical `ZENITHBOT_*` and `ZENITHDOCK_AGENT_TOKEN` names are
accepted only as compatibility aliases so existing installations can migrate
without losing chat state:

| Variable | Purpose | Default |
|---|---|---|
| `AGENTSDOCK_STATE_DIR` | Persistent session/job/file state directory | `~/.agentsdock` |
| `AGENTSDOCK_AGENT_CWD` | Default working directory for new sessions | user home |
| `AGENTSDOCK_AGENT_BIND` | Bind address | `0.0.0.0` |
| `AGENTSDOCK_AGENT_PORT` | Port | `7850` |
| `AGENTSDOCK_AGENT_TOKEN` | Shared bearer token | unset |
| `AGENTS_SERVER_INSTALL_DIR` | Versioned server runtime root | `~/.local/share/agents-server` |
| `AGENTSDOCK_BACKEND` | Default backend, `claude` or `codex` | `claude` |
| `CLAUDE_BIN` | Claude Code executable name/path | `claude` |
| `AGENTSDOCK_CLAUDE_TRANSPORT` | Interactive Claude transport: `auto`, `agent-sdk`, or `print` | `auto` |
| `AGENTSDOCK_CLAUDE_SDK_IDLE_TTL_SECONDS` | Idle per-chat SDK client retention | `300` |
| `AGENTSDOCK_CLAUDE_SDK_MAX_LOADED_CHATS` | Maximum retained per-chat SDK clients | `4` |
| `CODEX_BIN` | Codex executable name/path | `codex` |
| `AGENTSDOCK_RUNTIME_DIAGNOSTIC_TTL_SECONDS` | Cache lifetime for safe CLI version/auth probes | `60` |
| `CLAUDE_PROJECTS_ROOT` | Claude history search root | `~/.claude/projects` |
| `CODEX_SESSIONS_ROOT` | Codex history search root | `~/.codex/sessions` |
| `AGENTSDOCK_JOB_MAX_ACTIVE_RUNS` | Scheduled-job concurrency cap (`0` disables this dedicated cap) | `0` |
| `AGENTSDOCK_MAX_ACTIVE_AGENT_RUNS` | Interactive agent concurrency cap | `10` |
| `AGENTSDOCK_JOB_MIN_AVAILABLE_MEM_MB` | Job launch memory guardrail | `4096` |
| `AGENTSDOCK_MIN_START_AVAILABLE_MEM_MB` | Interactive launch memory guardrail | `2048` |
| `AGENTSDOCK_HANDOFF_DIGEST_BACKEND` | LLM backend for context digests, `claude` or `codex` | `claude` |
| `AGENTSDOCK_HANDOFF_DIGEST_MODEL` | LLM model for context digests | `sonnet` |
| `AGENTSDOCK_HANDOFF_DIGEST_EFFORT` | Optional digest reasoning/effort setting | unset |
| `AGENTSDOCK_HANDOFF_DIGEST_TIMEOUT_SECONDS` | Digest summarizer timeout | `180` |
| `AGENTSDOCK_HANDOFF_DIGEST_CHARS` | Final digest character cap | `56000` |
| `AGENTSDOCK_CODE_DIFF_SNAPSHOT_TIMEOUT_SECONDS` | Maximum time for each isolated Git worktree snapshot | `120` |

## Context Digests

`POST /api/sessions/{session_id}/digest` creates a real LLM-summarized handoff
for another chat. The server first builds a bounded source packet from recent
events and files, then asks the configured digest backend to summarize it into
a clean Markdown handoff. If the LLM summarizer fails, the endpoint fails
visibly instead of returning the raw source packet as if it were a digest.

By default, the digest summarizer uses Claude Sonnet:

```bash
AGENTSDOCK_HANDOFF_DIGEST_BACKEND=claude
AGENTSDOCK_HANDOFF_DIGEST_MODEL=sonnet
```

You can switch it to Codex or another installed CLI model, but the relevant CLI
must already be authenticated for the same Unix user that runs the service.

## Claude Agent SDK Transport

Interactive desktop clients can opt individual Claude chats into a persistent,
per-chat `ClaudeSDKClient`. This enables native steering plus approval and
question cards without sharing one Claude process across chats. The server
advertises the exact `claude_sdk_interactive_v1` capability before the desktop
app opts in.

Set `AGENTSDOCK_CLAUDE_TRANSPORT` to `auto` (default), `agent-sdk`, or `print`.
`print` always uses the compatible `claude -p` path. Clients that do not send
the exact capability—including older iOS builds and scheduled jobs—also remain
on `claude -p`, regardless of the server's interactive transport setting.

Idle SDK clients are retained for at most five minutes by default, with up to
four chat processes loaded. Active chats are never evicted to enforce the idle
limit.

Claude-controls capability v3 adds authenticated MCP management without
changing global API contract v13. Clients gate on
`capabilities.claude_controls.features.mcp_management` and use the additive
v1 endpoints:

```text
GET  /api/sessions/{session_id}/claude/mcp
POST /api/sessions/{session_id}/claude/mcp
```

GET lazily connects an idle chat's Agent SDK client and returns an opaque
generation string plus at most 100 exact-name-deduplicated, sorted, allowlisted
server rows; `truncated` marks an incomplete list. POST requires that exact
generation and supports `reconnect`, `reconnect_all`, `enable`, and `disable`.
Both operations reject active/provider-starting turns, are lifecycle-serialized
with managed-update admission, and have a bounded native-control timeout.
Responses never expose MCP commands, environment, headers, configuration URLs,
raw provider errors, or tool metadata. Print transport and SDK-unavailable
hosts return an explicit unavailable snapshot; older servers continue to
return 404. Tune the default 15-second bound with
`AGENTSDOCK_CLAUDE_MCP_CONTROL_TIMEOUT_SECONDS`.

## Backend CLI Notes

The backend selection in AgentsDock only chooses which CLI the server invokes.
The model, effort, authentication, provider-side session storage, and available
commands still come from the installed CLI tools and their local configuration.

Recommended checks before connecting clients:

```bash
# Claude backend
command -v claude
claude --version

# Codex backend
command -v codex
codex --version

# Cursor backend
command -v cursor-agent || command -v agent
cursor-agent --version || agent --version
```

Run these as the same Unix user that owns the systemd service. If the CLI works
in your login shell but fails under systemd, check the service `PATH`, virtual
environment, and any provider-specific auth/config files.

### Runtime diagnostics

API contract v9 exposes privacy-safe runtime status in two places:

```text
GET /api/health
GET /api/runtime/catalog?refresh=true
```

The health response includes cached `runtimes` entries. The catalog endpoint's
`refresh=true` query forces a fresh version/authentication probe. Each backend
reports `ready`, `missing`, `unauthenticated`, or probe `error`, plus an
actionable recovery instruction. It never returns account identity, auth
output, or tokens.

Cursor capability contract v2 advertises the hardened process guard, bounded
idle warning/timeout lifecycle, and explicit permission-mode semantics.

A new prompt performs the same preflight before reserving real agent work. If
the selected CLI is unavailable, the endpoint returns a structured
`503 runtime_unavailable` response. Failures after a healthy launch remain a
`last_error` on a ready runtime so model overloads, bad thread IDs, and ordinary
provider failures are not mislabeled as missing installations.

## Agent-managed scheduled jobs

Every Claude and Codex turn receives a compact snapshot of up to 25 jobs
belonging to that chat. The snapshot contains only job ID, title, enabled
state, schedule, IANA timezone, and next-run time; job prompts are omitted.
The helper's `list` command returns the complete current set. Agents are
instructed to change jobs only after an explicit scheduling request.

The installed `agentsdock_jobs.py` helper is the authoritative interface from
an agent turn. Every live turn receives a private, run-scoped authority file
and exact helper command in its provider-authority block. The helper accepts
that file and the bound chat ID explicitly, then uses server-enforced
agent-only routes for `list`, `get`, `runs`, `create`, `update`, and `delete`.
It deliberately provides no run-now command. The main server bearer is never
inherited by a provider process. For example, using the literal authority path
and chat ID shown in the current turn:

```bash
"$AGENTSDOCK_JOBS_CLI" --authority-file /path/from/turn.json --chat-id sess_from_turn list
"$AGENTSDOCK_JOBS_CLI" --authority-file /path/from/turn.json --chat-id sess_from_turn get JOB_ID
"$AGENTSDOCK_JOBS_CLI" --authority-file /path/from/turn.json --chat-id sess_from_turn runs JOB_ID --limit 20
"$AGENTSDOCK_JOBS_CLI" --authority-file /path/from/turn.json --chat-id sess_from_turn create --title "Daily status" \
  --prompt "Summarize the current project status." \
  --interval-seconds 86400 --loop
"$AGENTSDOCK_JOBS_CLI" --authority-file /path/from/turn.json --chat-id sess_from_turn create --title "Weekday status" \
  --prompt "Summarize the current project status." \
  --cron "0 9 * * MON-FRI" --timezone America/Los_Angeles
"$AGENTSDOCK_JOBS_CLI" --authority-file /path/from/turn.json --chat-id sess_from_turn update JOB_ID \
  --rrule "FREQ=WEEKLY;BYDAY=MO,WE,FR;BYHOUR=8;BYMINUTE=0;BYSECOND=0" \
  --timezone Europe/London
"$AGENTSDOCK_JOBS_CLI" --authority-file /path/from/turn.json --chat-id sess_from_turn delete JOB_ID
```

API contract v13 includes the durable per-chat `provider_jobs_access` setting.
Its default `full` mode exposes the existing helper surface, `read_only`
permits only `list`, `get`, and `runs`, and `blocked` permits no agent Jobs
calls. Capability issuance records the mode at turn start and every agent Jobs
route also checks the live session setting, so a human can tighten access while
a provider turn is running. Restoring broader access beyond the turn's issued
ceiling takes effect on the next turn. Authenticated app/human Jobs endpoints
are unaffected. Clients can detect the contract through
`capabilities.provider_jobs_access_control_v1` in `/api/health`.

Cron accepts Vixie five-field expressions, aliases such as `@daily`, and
seconds-first six- or seven-field expressions (the seventh field is year).
Hashed `H` fields are stable per job; nondeterministic `R` fields are rejected.
RRULE accepts one RFC 5545 recurrence-rule property with an optional `RRULE:`
prefix. Explicit first-run timestamps run exactly once even when off-rule;
subsequent runs return to the calendar schedule. Missed occurrences are
skipped, retries do not move the canonical schedule, nonexistent DST times are
skipped, and ambiguous fall-back times run once.

Interval schedules are capped at ten years. RRULE `COUNT` is capped at 10,000,
and leap-second `BYSECOND=60` is rejected because the runtime clock cannot
represent second 60.

## Cross-chat handoffs

### Current route-hint contract (API contract 27, capability v10)

An inline structured `@Chat` is an optional target hint. It never forwards the
raw user prompt. On successful ordinary-turn admission, an exact local
single-`@Chat` reference authored by a v2 client with `grant_intent: true`
idempotently creates or refreshes a durable directional source-to-target
grant. Subsequent turns receive only that source chat's current grants; there
is no ambient all-chat authority. An explicit user request to send, ask, tell,
or contact a named chat requires the agent to use the matching helper; passive
mentions remain optional. Every accepted configured-route Send carries one optional terminal
reply path back to its immutable source; it creates no reply obligation, never
automatically relays the target's ordinary final answer, cannot request a
follow-up, and grants no durable reverse route. Ask explicitly requests one
terminal answer over the same exchange-scoped return mechanism: it waits
briefly for a direct response, then atomically falls back to durable
asynchronous delivery without cancelling the recipient's work.
`/chat` is a composer alias for selecting the same structured hint.

Scheduled runs never inherit the source chat's grants. Each job stores its own
exact route selection, authorized by route ID in the job editor/helper flow,
and revalidates its target, revision, and action on every firing. Its prompt
contains the corresponding exact single `@Chat` marker for display and
binding; no `@@` authoring syntax is required. The health surface advertises
cross-chat version 10, `durable_route_grants`, configured-route
`instruction_reply_once`, `live_wait_async_fallback`,
`agent_ambient_local_handoffs: false`, scheduled Jobs version 5, and global
API contract 27.

Capability v10 retains this reply-once behavior for existing
configured `instruction` grants as well as newly created ones. The return path
is a property of each accepted delivery, not a new durable target grant: it is
bound to the original source, delivery run, exchange generation, two-leg
budget, and expiry. Revoking or revising the source route still blocks future
deliveries immediately.

Beta-era local `direct_message` and `@@` references remain readable only for
safe migration/recovery. They are quarantined from ordinary authority and can
never mint a durable grant; queued v6 snapshots are narrowed against current
persisted grants and cannot recreate a revoked route. Nonterminal legacy UI
envelopes are failed/cancelled during upgrade before they can be resubmitted.
Existing configured-route Send/Ask effects, action-specific secure-peer hints,
and final-result obligations retain their separate exact authorization and
lifecycle fences.

For a current ordinary turn, the provider-authority block exposes only opaque
route IDs. The agent lists the available routes, then sends or asks when the
user explicitly requests contact (and may otherwise decide no contact is
warranted):

```bash
"$AGENTSDOCK_CHATS_CLI" --authority-file /path/from/turn.json list
"$AGENTSDOCK_CHATS_CLI" --authority-file /path/from/turn.json \
  send --route route_opaque --message "Verify the API contract."
"$AGENTSDOCK_CHATS_CLI" --authority-file /path/from/turn.json \
  ask --route route_opaque --message "Which rollout is blocked?"
```

The helper never exposes or accepts an inferred chat ID. It accepts only the
opaque IDs in that run's authority snapshot, uses loopback AgentsServer URLs,
disables redirects and proxies, and submits one bounded agent-authored
message. Send creates a correlated two-leg exchange with one optional terminal
reply capability available only to its exact delivery run. If the target does
not deliberately use that capability, its ordinary final stays local and the
exchange closes without sending anything back. Ask creates the same bounded
exchange, initially returns the answer directly when it is ready within the
wait window, retains that exact result briefly for safe GET replay, and
otherwise returns an accepted/deferred receipt while the answer or failure
status is delivered asynchronously to the source chat.

### Historical action-specific grants (v1-v2)

API contract v11 added durable, same-server handoffs selected by the user in
the AgentsDock composer. API contract v13 upgraded
`capabilities.cross_chat_handoffs_v1` to version 2 and added bounded
request/reply exchanges. These historical structured references authorized
one exact exchange, instruction, or automatic final-result delivery. They are
retained for readable stored records and secure action-specific compatibility;
they are not the current `@Chat` authoring model. Self, archived, deleted,
legacy-transport, and unpaired foreign-server targets fail closed.

When such an action-specific grant is replayed, the provider-authority block
may print a one-use opaque target handle:

```bash
"$AGENTSDOCK_CHATS_CLI" --authority-file /path/from/turn.json \
  send --target OPAQUE_HANDLE --message "Verify the API contract."
```

`OPAQUE_HANDLE` is capability data, never a session ID. Delivery is a normal
durable target turn using the target chat's own provider, permission policy,
queue, and timeline. A server restart reconciles the ledger and lifecycle
outbox without silently duplicating a handoff. The desktop bearer remains
required to inspect or cancel handoffs.

Request/reply grants use the exact exchange ID reserved when the source turn
is admitted. The source agent starts it with `ask`; a recipient may answer or
ask a clarification with the exact `respond` command printed in that delivery
turn's provider-authority block:

```bash
"$AGENTSDOCK_CHATS_CLI" --authority-file /path/from/turn.json \
  ask --target OPAQUE_HANDLE --message "Which rollout is blocked?"
"$AGENTSDOCK_CHATS_CLI" --authority-file /path/from/turn.json \
  respond --exchange exchange_exact --inbound-leg leg_exact \
  --message "Do you mean the desktop or server rollout?" --request-response
```

An exchange is limited to six directed conversational legs (three rounds) and
expires after 72 hours. A successful non-empty recipient final automatically
returns one terminal answer when the inbound leg expects a reply and no
explicit response won the one-use CAS.
Failures, stops, expiry, participant deletion/archive, and queue-owner loss are
durable visible outcomes; non-user failures also create one bounded native
status wake for the waiting sender. Exchange turns reuse the existing hidden
`cross_chat_handoff_delivery` purpose so older clients do not expose synthetic
prompts or queue controls.

### Durable directional route management (v8)

The default-empty per-source-chat grant list is the sole ordinary cross-chat
authority ceiling. Inline `@Chat` admission manages it automatically, while
these authenticated endpoints support inspection and explicit administration:

```text
GET    /api/sessions/{source_session_id}/agent-handoff-routes
POST   /api/sessions/{source_session_id}/agent-handoff-routes
PATCH  /api/sessions/{source_session_id}/agent-handoff-routes/{route_id}
DELETE /api/sessions/{source_session_id}/agent-handoff-routes/{route_id}?expected_revision={revision}
```

`PATCH` and `DELETE` use the route revision as a compare-and-swap precondition;
a stale or missing valid route returns HTTP 409 with
`code: route_revision_conflict`, a safe message, and the current route or
`null`. A chat can hold at most 16 routes, aliases and targets are unique,
routes cannot point to their source chat, and forks inherit neither routes nor
their private mutation journal. Only v2 `agent_cross_chat_routes_v2`
submissions carrying exact `grant_intent` provenance may persist an inline
grant. Older v1/v6 turns and recovered queue hints remain one-run legacy data
and never become durable policy.

Grant mutation and turn admission cross two durable files. AgentsServer first
stores a hidden pending route journal, then fsyncs the exact `turn_started` or
`turn_queued` admission ID, and only then exposes the grant. Startup rolls the
exact route revisions back when no matching event exists, or finalizes them
when it does; later edits and revocations are never recreated. Scheduled,
internal, digest, standalone, and cross-chat delivery turns receive no source
grant snapshot. Every helper call intersects its issued snapshot with the
exact live route revision and allowed actions, so removal or policy edits
block future acceptance immediately; an already accepted ledger item remains
visible and cancelable through authenticated desktop APIs.

The turn-scoped helper surface accepts only opaque issued route IDs:

```bash
"$AGENTSDOCK_CHATS_CLI" --authority-file /path/from/turn.json list
"$AGENTSDOCK_CHATS_CLI" --authority-file /path/from/turn.json \
  send --route route_opaque --message "Apply the corresponding mobile change."
"$AGENTSDOCK_CHATS_CLI" --authority-file /path/from/turn.json \
  ask --route route_opaque --message "Which mobile behavior must match?"
```

`list` is capability-scoped; there is no provider chat search or arbitrary
target parameter. `Ask` is not transcript access: it creates a normal target
turn containing only the bounded relayed message, then returns one asynchronous
terminal answer to the source chat. Configured-route Send and Ask are limited
to two legs and 24 hours. A Send reply is always terminal; Ask also has no
follow-up under the configured-route contract. Route bodies and answers are
limited to 16,000 characters and 64 KiB UTF-8. A live run can accept at most
one effect per route and four route handoffs total; durable source and target
limits are 12 accepted route effects per rolling hour.

Provider projections contain only the opaque route ID, safe alias, sanitized
bounded title, backend, allowed actions, and generic availability. They never
expose target/session IDs, folders, working directories, models, provider IDs,
transcripts, rate counts, or route mutation history. Configured delivery
prompts likewise omit route and ledger identifiers; a returning answer may
include only the target's sanitized, explicitly untrusted display label.

Agent-created jobs use the same job store as the desktop and mobile clients,
so they immediately appear in the Jobs panel. The scoped helper routes are:

- `GET/POST /api/sessions/{session_id}/jobs`
- `PATCH/DELETE /api/sessions/{session_id}/jobs/{job_id}`

## Working-directory completion

AgentsDock can complete New Chat working-directory paths against the active
AgentsServer host (including remote hosts) when
`capabilities.working_directory_completion` is advertised:

```text
GET /api/working-directories/complete?path=/srv/pro&limit=24
```

The authenticated endpoint performs one bounded, shallow scan and returns
directories only. Older clients and servers continue to use the ordinary path
field without a global API compatibility failure.

## Workspace Files

The optional `workspace_files` health capability exposes a chat-scoped text
workspace rooted at that chat's exact `cwd`. It is additive to API contract v9,
so older clients continue to work without a global compatibility failure.

```text
GET /api/sessions/{session_id}/workspace
GET /api/sessions/{session_id}/workspace/entries?path=&offset=0&limit=500
GET /api/sessions/{session_id}/workspace/search?q=app&limit=100
GET /api/sessions/{session_id}/workspace/file?path=src/App.tsx
PUT /api/sessions/{session_id}/workspace/file
POST /api/sessions/{session_id}/workspace/entry
PATCH /api/sessions/{session_id}/workspace/entry
DELETE /api/sessions/{session_id}/workspace/entry?path=src/old.ts&expected_revision=...&recursive=false
```

Reads accept complete UTF-8 regular files up to 32 MiB by default, replacing
the legacy 2 MiB editor ceiling. Writes are atomic,
require the SHA-256 revision returned by the read endpoint, and reject stale
revisions, symlinks, special files, hard links, archived chats, and read-only
targets. Directory traversal is descriptor-relative and fails closed when the
host lacks secure no-follow file APIs. Configure the text limit with
`AGENTSDOCK_WORKSPACE_TEXT_MAX_BYTES`; a positive value selects a bounded
transport ceiling, while an explicit zero disables the AgentsServer ceiling.

Workspace-files capability v2 adds an opaque `revision` to every explorer and
search entry. Rename accepts `{path, new_name, expected_revision}`, is limited
to the same parent directory, and uses the host's atomic no-replace primitive,
so it never overwrites another entry. Delete requires the current entry
revision. A non-recursive delete removes files, symlinks, or empty
directories; `recursive=true` confirms deletion of a non-empty directory.
Recursive traversal remains descriptor-relative, never follows symlinks, and
rejects mounted filesystems rather than crossing them.

Workspace-files capability v4 adds no-overwrite creation. Post
`{path, kind: "file"}` to create an empty UTF-8 file or
`{path, kind: "directory"}` to create one directory. Creation is
descriptor-relative, rejects symlinked parents and existing destinations, and
is unavailable for archived chats.

## Imported provider history

Opening a chat catches its timeline up with messages added to the provider
transcript outside AgentsDock. The sync anchors on the newest timeline
messages, skips the parse when the transcript file is unchanged, refuses to
import a transcript that matches nothing on a populated timeline, and closes
every import batch with a `turn_finished` marked `imported: true`. Imported
turns never set a chat's active run, so replayed history can never make a
stopped chat look busy.

Servers before 0.1.26-beta.30 could append the same transcript tail on every
open. To remove those duplicates from a chat's event log:

```text
POST /api/sessions/{session_id}/history/prune-duplicates
{"dry_run": true}
```

The default dry run reports how many events and import runs would be
removed; `{"dry_run": false}` rewrites the log atomically while the chat is
idle, keeping the first occurrence of every message.

## Whole-History Search

`GET /api/search?q=<query>&limit=<chat-count>` searches user, assistant, error,
job, reasoning-summary, and file text across every chat. Quoted phrases remain
phrases; unquoted terms use prefix matching for responsive type-ahead search.

The first request incrementally builds `history_search.sqlite3` inside the
agent state directory. Each transcript stores its indexed byte offset, so later
requests ingest only newly appended JSONL records. The index is persistent and
safe across server restarts; a replaced or truncated transcript is rebuilt
automatically. Indexing runs in a worker thread and does not block agent turns.

## Per-Turn Code Review

For Git worktrees, the server snapshots the repository immediately before and
after each agent turn through an isolated temporary index. This captures the
complete turn-specific textual patch without modifying the user's real index
or folding pre-existing dirty changes into the review.

The append-only timeline stores only a compact `code_diff` event with file and
line-count metadata. Clients fetch the complete patch on demand:

```text
GET /api/sessions/{session_id}/diffs/{run_id}
```

The endpoint uses the same bearer-token authentication as the rest of the API.
Binary changes remain compact Git binary markers rather than being copied into
the event log.

## Public API Sketch

The server exposes JSON endpoints under `/api`.

- `GET /api/health`
- `GET /api/sessions`
- `GET /api/search`
- `POST /api/sessions`
- `PATCH /api/sessions/{session_id}`
- `GET /api/sessions/{session_id}/events`
- `GET /api/sessions/{session_id}/subagents`
- `POST /api/sessions/{session_id}/prompt`
- `POST /api/sessions/{session_id}/stop`
- `POST /api/sessions/{session_id}/fork`
- `POST /api/sessions/{session_id}/digest`
- `GET /api/sessions/{session_id}/files`
- `GET /api/sessions/{session_id}/diffs/{run_id}`
- `POST /api/sessions/{session_id}/upload`
- `GET /api/jobs`
- `POST /api/jobs`
- `PATCH /api/jobs/{job_id}`
- `DELETE /api/jobs/{job_id}`
- `GET /api/sessions/{session_id}/jobs`
- `POST /api/sessions/{session_id}/jobs`
- `PATCH /api/sessions/{session_id}/jobs/{job_id}`
- `DELETE /api/sessions/{session_id}/jobs/{job_id}`
- `GET /api/cross-chat/handoffs/{envelope_id}`
- `POST /api/cross-chat/handoffs/{envelope_id}/cancel`
- `GET /api/sessions/{session_id}/processes`
- `GET /api/sessions/{session_id}/tmux`
- `GET /api/runtime/catalog`
- `GET /api/admin/update`
- `POST /api/admin/update/check`
- `POST /api/admin/update/start`
- `GET /ws/sessions/{session_id}`

The event stream is append-only JSONL on disk and paged through the events API.
Large clients should page history instead of loading every event at once.
The subagents endpoint folds Claude local-agent lifecycle records into bounded
`subagent_state` snapshots without returning provider prompts, raw events,
tool-result output, commands, or output-file paths.

## Repository Hygiene

Before publishing:

```bash
python3 -m py_compile agent_server.py agentsdock_jobs.py agentsdock_chats.py agentsdock_emergency.py agentsdock_publish.py claude_sdk_client.py codex_app_server.py cursor_agent_client.py update_runner.py
rg -n 'private-host|/home/<name>|/Users/<name>|token-value' .
```

Do not commit:

- `~/.agentsdock` state (and the legacy `~/.zenithbot-agent` compatibility link)
- uploads or generated artifacts
- `.env` files or access tokens
- machine-specific hostnames, IP addresses, or user home paths
- compiled Python caches
