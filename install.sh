#!/usr/bin/env bash
set -euo pipefail

PORT="7850"
BIND_ADDRESS="0.0.0.0"
RELEASE_VERSION=""
DEPENDENCY_SYNC_TIMEOUT_SECONDS="${AGENTS_SERVER_DEPENDENCY_TIMEOUT_SECONDS:-1200}"
INSTALL_HEARTBEAT_SECONDS="${AGENTS_SERVER_INSTALL_HEARTBEAT_SECONDS:-15}"
HEALTH_CHECK_ATTEMPTS="${AGENTS_SERVER_HEALTH_CHECK_ATTEMPTS:-45}"
ROLLBACK_HEALTH_CHECK_MAX_ATTEMPTS=45
INSTALL_ROOT="${AGENTS_SERVER_INSTALL_DIR:-$HOME/.local/share/agents-server}"
CONFIG_ROOT="${AGENTS_SERVER_CONFIG_DIR:-$HOME/.config/agents-server}"
LEGACY_STATE_ROOT="$HOME/.zenithbot-agent"
if [[ -n "${AGENTSDOCK_STATE_DIR:-}" ]]; then
  STATE_ROOT="$AGENTSDOCK_STATE_DIR"
elif [[ -n "${AGENTS_SERVER_STATE_DIR:-}" ]]; then
  STATE_ROOT="$AGENTS_SERVER_STATE_DIR"
elif [[ -n "${ZENITHBOT_AGENT_DIR:-}" ]]; then
  STATE_ROOT="$ZENITHBOT_AGENT_DIR"
else
  STATE_ROOT="$HOME/.agentsdock"
fi
SERVICE_NAME="agents-server"
LEGACY_SERVICE_NAME="zenithbot-agent"
# AgentsServer's cooperative shutdown has 17 independently bounded cleanup
# phases in addition to uvicorn's graceful window.  Five seconds was shorter
# than even an ordinary slow shutdown: launchctl had already accepted bootout,
# then the installer abandoned activation/rollback and could leave the service
# unloaded.  Keep this wait bounded, but long enough for the server's complete
# worst-case graceful budget before declaring the exact launchd job wedged.
# AgentsServer caps the configurable uvicorn window at 60 seconds; 180 seconds
# covers that window, all 17 five-second teardown phases, the watchdog margin,
# and another 30 seconds for launchd to reap the terminated process.
LAUNCHCTL_STOP_ATTEMPTS=1800
LAUNCHCTL_STOP_DELAY=0.1
LAUNCHCTL_BOOTSTRAP_ATTEMPTS=3
NON_INTERACTIVE="false"
PORT_EXPLICIT="false"
BIND_EXPLICIT="false"
PORT_FALLBACK="auto"
PORT_FALLBACK_ATTEMPTS=5
TEAM_HUB_MODE_OVERRIDE=""
TEAM_HUB_MODE="disabled"
TEAM_HUB_REACTIVATION_REQUESTED="false"
TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED="false"
TEAM_HUB_REACTIVATION_SNAPSHOT=""
TEAM_HUB_REACTIVATION_HUB_ID=""
TEAM_HUB_REACTIVATION_OPERATION_ID=""
TEAM_HUB_REACTIVATION_FENCE_PENDING="false"
TEAM_HUB_REACTIVATION_FINALIZED="false"
TEAM_HUB_TRANSPORT_OVERRIDE=""
TEAM_HUB_TRANSPORT="loopback"
TEAM_HUB_URL_OVERRIDE=""
TEAM_HUB_URL=""
TEAM_HUB_DIRECT_IP_URL_OVERRIDE=""
TEAM_HUB_DIRECT_IP_URL=""
EXPECTED_SERVER_IDENTITY=""
EXPECTED_TEAM_HUB_ID=""
EXPECTED_TEAM_HUB_TRANSPORT=""
EXPECTED_TEAM_HUB_TRANSPORT_SET="false"
EXPECTED_TEAM_HUB_URL=""
EXPECTED_TEAM_HUB_URL_SET="false"
EXPECTED_TEAM_HUB_DIRECT_IP_URL=""
EXPECTED_TEAM_HUB_DIRECT_IP_URL_SET="false"
TEAM_HUB_SNAPSHOT=""
TEAM_HUB_DATA_DIR=""
TEAM_HUB_OPERATION_ID=""
# The detached updater passes these private continuity fields in its
# environment so a beta-to-stable transition remains compatible with older
# signed installers that do not recognize new CLI flags. Explicit CLI values
# below override these defaults for current-version callers.
MANAGED_UPDATE_ID="${AGENTSDOCK_MANAGED_UPDATE_ID:-}"
EXPECTED_SERVICE_CGROUP="${AGENTSDOCK_EXPECTED_SERVICE_CGROUP:-}"
unset AGENTSDOCK_MANAGED_UPDATE_ID AGENTSDOCK_EXPECTED_SERVICE_CGROUP
SYSTEMD_MANAGED_STOP_ATTEMPTS=50
SYSTEMD_MANAGED_STOP_DELAY=0.1
SYSTEMD_MANAGED_KILL_ATTEMPTS=20

if [[ -t 1 ]] && [[ "${TERM:-}" != "dumb" ]] && [[ -z "${NO_COLOR:-}" ]]; then
  COLOR_GREEN=$'\033[32m'
  COLOR_RED=$'\033[31m'
  COLOR_YELLOW=$'\033[33m'
  COLOR_BOLD=$'\033[1m'
  COLOR_RESET=$'\033[0m'
else
  COLOR_GREEN=""
  COLOR_RED=""
  COLOR_YELLOW=""
  COLOR_BOLD=""
  COLOR_RESET=""
fi
CHECK_MARK="${COLOR_GREEN}✓${COLOR_RESET}"
CROSS_MARK="${COLOR_RED}✗${COLOR_RESET}"
DOT_MARK="${COLOR_YELLOW}○${COLOR_RESET}"

usage() {
  cat <<'USAGE'
Usage: ./install.sh [--port PORT] [--bind ADDRESS] [--release-version VERSION] [--team-hub-host|--reactivate-team-hub-host|--no-team-hub-host] [--team-hub-tailscale-serve-url URL] [--team-hub-direct-ip-url URL] [--non-interactive] [--allow-port-fallback|--no-port-fallback]

Installs or updates AgentsServer for the current user. Releases and Python
runtimes are versioned, the previous healthy release is retained for rollback,
and existing chat state and generated tokens are preserved. No sudo privileges
are required.

--non-interactive skips the optional tmux install prompt on macOS instead of
asking; use it for unattended/SSH-driven runs.

--port pins the exact requested port unless --allow-port-fallback is also set.
Without --port, setup may select one of the next 5 ports when the default is
already occupied by a service that does not authenticate as AgentsServer.

--allow-port-fallback enables nearby-port selection even with an explicit
--port value.

--no-port-fallback disables automatically retrying on the next free port when
the default port is already held by another process.

--team-hub-host designates this server as the one Team Hub host. It defaults
to host-local access. For remote private-tailnet access, also pass the exact
Tailscale Serve URL ending in /api/team-hub.
--team-hub-tailscale-serve-url selects private Tailscale Serve HTTPS transport
for this host. It implies --team-hub-host and rejects Funnel-capable ports.
--team-hub-direct-ip-url adds an advanced, unencrypted raw IPv4 route on the
same AgentsServer origin. It implies --team-hub-host. IP shape is not identity
or Tailscale attestation; credentials and messages are plaintext on this route.
--reactivate-team-hub-host explicitly reactivates preserved Hub state after
verifying its managed binding matches this server's durable identity and
writing a verified pre-reactivation snapshot. It may be combined with either
Team Hub route option above.
--no-team-hub-host stops Team Hub hosting while preserving its state. This beta
never silently reactivates preserved state. Without an explicit host option, an
existing host/disabled setting is preserved; new installs default to disabled.

--show-token prints the current access token for an already-installed
AgentsServer and exits immediately; it makes no other changes.
USAGE
}

SHOW_TOKEN="false"

while (($#)); do
  case "$1" in
    --port) PORT="${2:-}"; PORT_EXPLICIT="true"; shift 2 ;;
    --bind) BIND_ADDRESS="${2:-}"; BIND_EXPLICIT="true"; shift 2 ;;
    --release-version) RELEASE_VERSION="${2:-}"; shift 2 ;;
    --non-interactive) NON_INTERACTIVE="true"; shift ;;
    --allow-port-fallback) PORT_FALLBACK="true"; shift ;;
    --no-port-fallback) PORT_FALLBACK="false"; shift ;;
    --team-hub-host)
      if [[ "$TEAM_HUB_MODE_OVERRIDE" == "disabled" ]]; then
        echo "--team-hub-host and --no-team-hub-host cannot be combined." >&2
        exit 2
      fi
      TEAM_HUB_MODE_OVERRIDE="host"
      shift
      ;;
    --reactivate-team-hub-host)
      if [[ "$TEAM_HUB_MODE_OVERRIDE" == "disabled" ]]; then
        echo "--reactivate-team-hub-host and --no-team-hub-host cannot be combined." >&2
        exit 2
      fi
      TEAM_HUB_REACTIVATION_REQUESTED="true"
      TEAM_HUB_MODE_OVERRIDE="host"
      shift
      ;;
    # Internal: emitted only by an admitted detached updater after the live
    # host reported a bounded startup failure. The installer independently
    # rebinds and snapshots the cold generation before takeover.
    --repair-failed-team-hub-host)
      TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED="true"
      shift
      ;;
    --team-hub-tailscale-serve-url)
      if [[ "$TEAM_HUB_MODE_OVERRIDE" == "disabled" ]]; then
        echo "--team-hub-tailscale-serve-url and --no-team-hub-host cannot be combined." >&2
        exit 2
      fi
      if (($# < 2)) || [[ -z "${2:-}" || "${2:-}" == --* ]]; then
        echo "--team-hub-tailscale-serve-url requires a URL." >&2
        exit 2
      fi
      TEAM_HUB_URL_OVERRIDE="${2:-}"
      TEAM_HUB_TRANSPORT_OVERRIDE="tailscale_serve"
      TEAM_HUB_MODE_OVERRIDE="host"
      shift 2
      ;;
    --team-hub-direct-ip-url)
      if [[ "$TEAM_HUB_MODE_OVERRIDE" == "disabled" ]]; then
        echo "--team-hub-direct-ip-url and --no-team-hub-host cannot be combined." >&2
        exit 2
      fi
      if (($# < 2)) || [[ -z "${2:-}" || "${2:-}" == --* ]]; then
        echo "--team-hub-direct-ip-url requires a URL." >&2
        exit 2
      fi
      TEAM_HUB_DIRECT_IP_URL_OVERRIDE="${2:-}"
      TEAM_HUB_MODE_OVERRIDE="host"
      shift 2
      ;;
    --no-team-hub-host)
      if [[ "$TEAM_HUB_MODE_OVERRIDE" == "host" ]]; then
        echo "Team Hub host/reactivation options and --no-team-hub-host cannot be combined." >&2
        exit 2
      fi
      TEAM_HUB_MODE_OVERRIDE="disabled"
      shift
      ;;
    # Internal, fail-closed continuity assertions passed only by the
    # authenticated managed updater.
    --expected-server-identity) EXPECTED_SERVER_IDENTITY="${2:-}"; shift 2 ;;
    --expected-team-hub-id) EXPECTED_TEAM_HUB_ID="${2:-}"; shift 2 ;;
    --expected-team-hub-transport)
      if (($# < 2)); then
        echo "--expected-team-hub-transport requires a value." >&2
        exit 2
      fi
      EXPECTED_TEAM_HUB_TRANSPORT="${2:-}"
      EXPECTED_TEAM_HUB_TRANSPORT_SET="true"
      shift 2
      ;;
    --expected-team-hub-url)
      if (($# < 2)); then
        echo "--expected-team-hub-url requires a value (empty for loopback)." >&2
        exit 2
      fi
      EXPECTED_TEAM_HUB_URL="${2:-}"
      EXPECTED_TEAM_HUB_URL_SET="true"
      shift 2
      ;;
    --expected-team-hub-direct-ip-url)
      if (($# < 2)); then
        echo "--expected-team-hub-direct-ip-url requires a value (empty when absent)." >&2
        exit 2
      fi
      EXPECTED_TEAM_HUB_DIRECT_IP_URL="${2:-}"
      EXPECTED_TEAM_HUB_DIRECT_IP_URL_SET="true"
      shift 2
      ;;
    --team-hub-snapshot) TEAM_HUB_SNAPSHOT="${2:-}"; shift 2 ;;
    --team-hub-data-dir) TEAM_HUB_DATA_DIR="${2:-}"; shift 2 ;;
    --team-hub-operation-id) TEAM_HUB_OPERATION_ID="${2:-}"; shift 2 ;;
    --managed-update-id) MANAGED_UPDATE_ID="${2:-}"; shift 2 ;;
    --expected-service-cgroup) EXPECTED_SERVICE_CGROUP="${2:-}"; shift 2 ;;
    --show-token) SHOW_TOKEN="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "$PORT_FALLBACK" == "auto" ]]; then
  if [[ "$PORT_EXPLICIT" == "true" ]]; then
    PORT_FALLBACK="false"
  else
    PORT_FALLBACK="true"
  fi
fi

if [[ ! "$PORT" =~ ^[0-9]+$ ]] || ((PORT < 1 || PORT > 65535)); then
  echo "Port must be an integer between 1 and 65535." >&2
  exit 2
fi

if [[ -n "$EXPECTED_SERVER_IDENTITY" ]] && [[ ! "$EXPECTED_SERVER_IDENTITY" =~ ^[A-Za-z0-9_.:-]{8,240}$ ]]; then
  echo "Expected server identity is invalid." >&2
  exit 2
fi
if [[ -n "$EXPECTED_TEAM_HUB_ID" ]] && [[ ! "$EXPECTED_TEAM_HUB_ID" =~ ^[A-Za-z0-9_.:-]{8,240}$ ]]; then
  echo "Expected Team Hub identity is invalid." >&2
  exit 2
fi
if [[ -n "$TEAM_HUB_OPERATION_ID" ]] && [[ ! "$TEAM_HUB_OPERATION_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]]; then
  echo "Managed Team Hub operation ID is invalid." >&2
  exit 2
fi
if [[ -n "$MANAGED_UPDATE_ID" ]] && [[ ! "$MANAGED_UPDATE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]]; then
  echo "Managed update ID is invalid." >&2
  exit 2
fi
if [[ -n "$EXPECTED_SERVICE_CGROUP" ]] && [[ ! "$EXPECTED_SERVICE_CGROUP" =~ ^/([A-Za-z0-9_.@:-]+/)*[A-Za-z0-9_.@:-]+$ ]]; then
  echo "Expected service cgroup is invalid." >&2
  exit 2
fi
if [[ -n "$EXPECTED_SERVICE_CGROUP" && -z "$MANAGED_UPDATE_ID" ]]; then
  echo "Expected service cgroup requires a managed update ID." >&2
  exit 2
fi
if [[ "$TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED" == "true" ]]; then
  if [[ "$TEAM_HUB_REACTIVATION_REQUESTED" == "true" \
    || "$TEAM_HUB_MODE_OVERRIDE" == "disabled" ]]; then
    echo "Failed Team Hub repair cannot change or reactivate host mode." >&2
    exit 2
  fi
  if [[ -z "$EXPECTED_SERVER_IDENTITY" || -z "$MANAGED_UPDATE_ID" ]]; then
    echo "Failed Team Hub repair requires an identity-bound managed update." >&2
    exit 2
  fi
  if [[ -n "$EXPECTED_TEAM_HUB_ID" || -n "$TEAM_HUB_SNAPSHOT" \
    || -n "$TEAM_HUB_DATA_DIR" || -n "$TEAM_HUB_OPERATION_ID" ]]; then
    echo "Failed Team Hub repair cannot reuse live-host rollback arguments." >&2
    exit 2
  fi
  if [[ "$EXPECTED_TEAM_HUB_TRANSPORT_SET" != "true" \
    || "$EXPECTED_TEAM_HUB_URL_SET" != "true" \
    || "$EXPECTED_TEAM_HUB_DIRECT_IP_URL_SET" != "true" ]]; then
    echo "Failed Team Hub repair requires exact transport continuity assertions." >&2
    exit 2
  fi
fi
if [[ -n "$EXPECTED_TEAM_HUB_ID" ]]; then
  if [[ "$EXPECTED_TEAM_HUB_TRANSPORT_SET" == "false" && "$EXPECTED_TEAM_HUB_URL_SET" == "false" ]]; then
    # A beta.2 managed updater cannot pass these additive continuity fields.
    # Its only supported Team Hub transport was loopback, so bind that legacy
    # operation to loopback explicitly rather than consulting mutable env.
    EXPECTED_TEAM_HUB_TRANSPORT="loopback"
    EXPECTED_TEAM_HUB_TRANSPORT_SET="true"
    EXPECTED_TEAM_HUB_URL=""
    EXPECTED_TEAM_HUB_URL_SET="true"
  elif [[ "$EXPECTED_TEAM_HUB_TRANSPORT_SET" != "$EXPECTED_TEAM_HUB_URL_SET" ]]; then
    echo "Managed Team Hub transport and URL assertions must be supplied together." >&2
    exit 2
  fi
  if [[ "$EXPECTED_TEAM_HUB_DIRECT_IP_URL_SET" != "true" ]]; then
    # Runners predating the Direct IP route contract could only have accepted
    # a route set without Direct IP. Preserve that exact absence rather than
    # adopting a previously ignored environment value during the update.
    EXPECTED_TEAM_HUB_DIRECT_IP_URL=""
    EXPECTED_TEAM_HUB_DIRECT_IP_URL_SET="true"
  fi
fi
if [[ "$EXPECTED_TEAM_HUB_TRANSPORT_SET" == "true" && "$EXPECTED_TEAM_HUB_TRANSPORT" != "loopback" && "$EXPECTED_TEAM_HUB_TRANSPORT" != "tailscale_serve" && "$EXPECTED_TEAM_HUB_TRANSPORT" != "direct_ip" ]]; then
  echo "Expected Team Hub transport is invalid." >&2
  exit 2
fi
if [[ -n "$EXPECTED_TEAM_HUB_ID" || "$EXPECTED_TEAM_HUB_TRANSPORT_SET" == "true" || "$EXPECTED_TEAM_HUB_URL_SET" == "true" || "$EXPECTED_TEAM_HUB_DIRECT_IP_URL_SET" == "true" || -n "$TEAM_HUB_SNAPSHOT" || -n "$TEAM_HUB_DATA_DIR" || -n "$TEAM_HUB_OPERATION_ID" ]]; then
  if [[ "$TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED" != "true" ]] && { \
    [[ -z "$EXPECTED_SERVER_IDENTITY" || -z "$EXPECTED_TEAM_HUB_ID" \
      || "$EXPECTED_TEAM_HUB_TRANSPORT_SET" != "true" \
      || "$EXPECTED_TEAM_HUB_URL_SET" != "true" \
      || -z "$TEAM_HUB_SNAPSHOT" || -z "$TEAM_HUB_DATA_DIR" \
      || -z "$TEAM_HUB_OPERATION_ID" ]]; \
  }; then
    echo "Managed Team Hub rollback arguments must be supplied together with the expected server identity." >&2
    exit 2
  fi
fi

SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

normalize_managed_path() {
  local label="$1"
  local candidate="$2"
  local parent=""
  local leaf=""
  local physical_parent=""
  local normalized=""
  local home_physical=""
  if [[ -z "$candidate" || "$candidate" != /* \
    || "$candidate" == *$'\n'* || "$candidate" == *$'\r'* ]]; then
    echo "$label must be a non-empty absolute path without control characters." >&2
    return 1
  fi
  while [[ "$candidate" != "/" && "$candidate" == */ ]]; do
    candidate="${candidate%/}"
  done
  case "$candidate/" in
    *"/../"*|*"/./"*|*"//"*)
      echo "$label must not contain '.', '..', or repeated-slash path components: $candidate" >&2
      return 1
      ;;
  esac
  leaf="${candidate##*/}"
  parent="${candidate%/*}"
  [[ -n "$parent" ]] || parent="/"
  while [[ ! -d "$parent" && "$parent" != "/" ]]; do
    leaf="${parent##*/}/$leaf"
    parent="${parent%/*}"
    [[ -n "$parent" ]] || parent="/"
  done
  physical_parent="$(cd -P -- "$parent" 2>/dev/null && pwd -P)" || {
    echo "Could not resolve the parent of $label: $candidate" >&2
    return 1
  }
  if [[ "$physical_parent" == "/" ]]; then
    normalized="/$leaf"
  else
    normalized="$physical_parent/$leaf"
  fi
  home_physical="$(cd -P -- "$HOME" 2>/dev/null && pwd -P)" || return 1
  case "$normalized" in
    "/"|"/Applications"|"/Library"|"/System"|"/Users"|"/Volumes"|"/bin"|"/etc"|"/home"|"/opt"|"/private"|"/sbin"|"/tmp"|"/usr"|"/var"|\
    "$home_physical"|"$home_physical/.config"|"$home_physical/.local"|"$home_physical/.local/share"|"$home_physical/Library"|"$home_physical/Library/LaunchAgents")
      echo "Refusing unsafe $label target: $normalized" >&2
      return 1
      ;;
  esac
  printf '%s\n' "$normalized"
}

paths_overlap() {
  local first="$1"
  local second="$2"
  [[ "$first" == "$second" \
    || "$first" == "$second/"* \
    || "$second" == "$first/"* ]]
}

INSTALL_ROOT="$(normalize_managed_path AGENTS_SERVER_INSTALL_DIR "$INSTALL_ROOT")" \
  || exit 2
CONFIG_ROOT="$(normalize_managed_path AGENTS_SERVER_CONFIG_DIR "$CONFIG_ROOT")" \
  || exit 2
STATE_ROOT="$(normalize_managed_path AGENTSDOCK_STATE_DIR "$STATE_ROOT")" \
  || exit 2
LEGACY_STATE_GUARD="$(normalize_managed_path LEGACY_STATE_ROOT "$LEGACY_STATE_ROOT")" \
  || exit 2
DEFAULT_STATE_GUARD="$(normalize_managed_path DEFAULT_STATE_ROOT \
  "$HOME/.agentsdock")" || exit 2
LEGACY_STATE_ROOT="$LEGACY_STATE_GUARD"
for managed_root in "$INSTALL_ROOT" "$CONFIG_ROOT" "$STATE_ROOT"; do
  if [[ -L "$managed_root" ]]; then
    echo "Refusing symbolic-link managed root: $managed_root" >&2
    exit 2
  fi
done
if paths_overlap "$INSTALL_ROOT" "$CONFIG_ROOT" \
  || paths_overlap "$INSTALL_ROOT" "$STATE_ROOT" \
  || paths_overlap "$CONFIG_ROOT" "$STATE_ROOT" \
  || paths_overlap "$INSTALL_ROOT" "$LEGACY_STATE_GUARD" \
  || paths_overlap "$CONFIG_ROOT" "$LEGACY_STATE_GUARD" \
  || paths_overlap "$STATE_ROOT" "$LEGACY_STATE_GUARD"; then
  echo "Refusing overlapping install, configuration, and state roots; each must be a separate directory." >&2
  exit 2
fi
if [[ "$STATE_ROOT" == "$DEFAULT_STATE_GUARD" \
  && ( -e "$LEGACY_STATE_ROOT" || -L "$LEGACY_STATE_ROOT" ) \
  && ! -L "$LEGACY_STATE_ROOT" \
  && ! -e "$STATE_ROOT" ]]; then
  legacy_state_mode=""
  if [[ ! -d "$LEGACY_STATE_ROOT" || ! -O "$LEGACY_STATE_ROOT" ]]; then
    echo "The legacy state path is not a safe owned directory; refusing to migrate it." >&2
    exit 2
  fi
  legacy_state_mode="$(stat -c '%a' "$LEGACY_STATE_ROOT" 2>/dev/null \
    || stat -f '%Lp' "$LEGACY_STATE_ROOT" 2>/dev/null)" || exit 2
  if [[ ! "$legacy_state_mode" =~ ^[0-7]{3,4}$ \
    || $((8#$legacy_state_mode & 8#022)) -ne 0 ]]; then
    echo "The legacy state directory is group/world writable; refusing to migrate it." >&2
    exit 2
  fi
fi

if [[ -z "$RELEASE_VERSION" && -f "$SOURCE_DIR/VERSION" ]]; then
  RELEASE_VERSION="$(tr -d '[:space:]' < "$SOURCE_DIR/VERSION")"
fi
if [[ ! "$RELEASE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.-]+)?$ ]]; then
  echo "Release version is missing or invalid." >&2
  exit 2
fi
REQUESTED_RELEASE_VERSION="$RELEASE_VERSION"

validate_positive_integer() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]] || ((value < 1)); then
    echo "$name must be a positive integer, got: $value" >&2
    exit 2
  fi
}

validate_positive_integer "AGENTS_SERVER_DEPENDENCY_TIMEOUT_SECONDS" "$DEPENDENCY_SYNC_TIMEOUT_SECONDS"
validate_positive_integer "AGENTS_SERVER_INSTALL_HEARTBEAT_SECONDS" "$INSTALL_HEARTBEAT_SECONDS"
validate_positive_integer "AGENTS_SERVER_HEALTH_CHECK_ATTEMPTS" "$HEALTH_CHECK_ATTEMPTS"

RELEASES_ROOT="$INSTALL_ROOT/releases"
RELEASE_DIR="$RELEASES_ROOT/$RELEASE_VERSION"
STAGE_DIR="$RELEASES_ROOT/.staging-$RELEASE_VERSION-$$"
STAGE_DIR_DEVICE=""
STAGE_DIR_INODE=""
CANDIDATE_RUNTIME_ROOT="$STAGE_DIR"
CURRENT_LINK="$INSTALL_ROOT/current"
PREVIOUS_LINK="$INSTALL_ROOT/previous"
ACTIVATION_TRANSACTION_DIR="$INSTALL_ROOT/.activation-transaction"
ACTIVATION_TRANSACTION_RESUMED="false"
ACTIVATION_TRANSACTION_PHASE=""
ACTIVATION_ROLLBACK_FROM=""
ACTIVATION_TRANSACTION_ID=""
ACTIVATION_INTENT="ordinary"
ACTIVATION_HUB_KIND=""
ORIGINAL_OLD_SOURCE=""
ROLLBACK_RELEASE_ROOT=""
ENV_FILE="$CONFIG_ROOT/env"
LEGACY_SERVICE_FILE="$HOME/.config/systemd/user/$LEGACY_SERVICE_NAME.service"
OLD_TARGET=""
RELEASE_ACTIVATED="false"
CANDIDATE_SERVICE_MAY_HAVE_STARTED="false"
SERVICE_STOPPED_FOR_COLD_HANDOFF="false"
TEAM_HUB_COLD_GUARD_PENDING="false"
TEAM_HUB_COLD_GUARD_ID=""
TEAM_HUB_COLD_GUARD_DEVICE=""
TEAM_HUB_COLD_GUARD_INODE=""
TEAM_HUB_REACTIVATION_FENCE_DEVICE=""
TEAM_HUB_REACTIVATION_FENCE_INODE=""
TEAM_HUB_OPERATION_FENCE_DEVICE=""
TEAM_HUB_OPERATION_FENCE_INODE=""
TEAM_HUB_STARTUP_AUTHORITY_PENDING="false"
TEAM_HUB_RECOVERY_ATTEMPTED="false"
TEAM_HUB_OPERATION_FINALIZED="false"
TEAM_HUB_OPERATION_PENDING="false"
[[ -z "$EXPECTED_TEAM_HUB_ID" ]] || TEAM_HUB_OPERATION_PENDING="true"
if [[ ( "$TEAM_HUB_REACTIVATION_REQUESTED" == "true" \
  || "$TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED" == "true" ) \
  && "$TEAM_HUB_OPERATION_PENDING" == "true" ]]; then
  echo "Explicit Team Hub reactivation cannot be combined with a managed Team Hub update." >&2
  exit 2
fi
IN_EXIT_CLEANUP="false"
ENV_CONFIG_BACKUP=""
ENV_CONFIG_EXISTED="false"
ENV_CONFIG_CAPTURED="false"
SERVICE_CONFIG_BACKUP=""
SERVICE_CONFIG_EXISTED="false"
SERVICE_CONFIG_CAPTURED="false"
PRIOR_SERVICE_STATE="absent"
PRIOR_SERVICE_ENABLED="false"
PRIOR_LEGACY_SERVICE_STATE="absent"
PRIOR_LEGACY_SERVICE_ENABLED="false"
# Canonical, non-secret continuity proof captured from the authenticated old
# server immediately before takeover.  A disabled static host mode may still
# be an active secure-peer Teamspace client, so candidate health must preserve
# that exact pairing rather than misclassifying the client as a disabled Hub.
EXPECTED_TEAM_HUB_CLIENT_BINDING=""

scrub_staged_process_environment() {
  unset \
    AGENTSDOCK_AGENT_TOKEN \
    AGENTSDOCK_PROVIDER_AUTHORITY_FILE \
    AGENTSDOCK_PUBLISH_TOKEN \
    ZENITHBOT_AGENT_TOKEN \
    ZENITHDOCK_AGENT_TOKEN
}

run_without_server_secrets() (
  scrub_staged_process_environment
  "$@"
)

team_hub_control_runtime() {
  local preferred_root="${1:-}"
  local candidate=""
  for candidate in \
    "$ACTIVATION_TRANSACTION_DIR/candidate.retired" \
    "$preferred_root" \
    "${OLD_TARGET:-}" \
    "$CURRENT_LINK" \
    "$RELEASE_DIR" \
    "$STAGE_DIR" \
    "$SOURCE_DIR"; do
    [[ -n "$candidate" ]] || continue
    if [[ -f "$candidate/agentsdock_team_hub/store.py" && -x "$candidate/.venv/bin/python" ]]; then
      printf '%s\n%s\n' "$candidate/.venv/bin/python" "$candidate"
      return 0
    fi
  done
  return 1
}

clear_team_hub_operation_fence() {
  [[ "$TEAM_HUB_OPERATION_PENDING" == "true" ]] || return 0
  local allow_missing="${2:-false}"
  local runtime=""
  local python_path=""
  local source_root=""
  runtime="$(team_hub_control_runtime "${1:-}")" || {
    echo "No installed runtime can verify the Team Hub maintenance fence." >&2
    return 1
  }
  python_path="${runtime%%$'\n'*}"
  source_root="${runtime#*$'\n'}"
  run_without_server_secrets env PYTHONPATH="$source_root" "$python_path" -c '
from pathlib import Path
import sys
from agentsdock_team_hub.store import HubStore

cleared = HubStore.clear_maintenance_fence_control(
    Path(sys.argv[1]),
    expected_hub_id=sys.argv[2],
    expected_host_identity=sys.argv[3],
    expected_reason="server-update",
    expected_operation_id=sys.argv[4],
    expected_snapshot=Path(sys.argv[5]),
    expected_device=int(sys.argv[6]),
    expected_inode=int(sys.argv[7]),
)
if not cleared and sys.argv[8] != "true":
    raise RuntimeError("the exact Team Hub maintenance fence is missing")
' \
    "$TEAM_HUB_DATA_DIR" \
    "$EXPECTED_TEAM_HUB_ID" \
    "$EXPECTED_SERVER_IDENTITY" \
    "$TEAM_HUB_OPERATION_ID" \
    "$TEAM_HUB_SNAPSHOT" \
    "$TEAM_HUB_OPERATION_FENCE_DEVICE" \
    "$TEAM_HUB_OPERATION_FENCE_INODE" \
    "$allow_missing"
}

clear_team_hub_reactivation_fence() {
  [[ "$TEAM_HUB_REACTIVATION_FENCE_PENDING" == "true" ]] || return 0
  local allow_missing="${2:-false}"
  local runtime=""
  local python_path=""
  local source_root=""
  runtime="$(team_hub_control_runtime "${1:-}")" || {
    echo "No installed runtime can verify the Team Hub reactivation fence." >&2
    return 1
  }
  python_path="${runtime%%$'\n'*}"
  source_root="${runtime#*$'\n'}"
  run_without_server_secrets env PYTHONPATH="$source_root" "$python_path" -c '
from pathlib import Path
import sys
from agentsdock_team_hub.store import HubStore

cleared = HubStore.clear_maintenance_fence_control(
    Path(sys.argv[1]),
    expected_hub_id=sys.argv[2],
    expected_host_identity=sys.argv[3],
    expected_reason="host-reactivation",
    expected_operation_id=sys.argv[4],
    expected_snapshot=Path(sys.argv[5]),
    expected_device=int(sys.argv[6]),
    expected_inode=int(sys.argv[7]),
)
if not cleared and sys.argv[8] != "true":
    raise RuntimeError("the exact Team Hub reactivation fence is missing")
' \
    "$TEAM_HUB_CANONICAL_DATA_DIR" \
    "$TEAM_HUB_REACTIVATION_HUB_ID" \
    "$EXPECTED_SERVER_IDENTITY" \
    "$TEAM_HUB_REACTIVATION_OPERATION_ID" \
    "$TEAM_HUB_REACTIVATION_SNAPSHOT" \
    "$TEAM_HUB_REACTIVATION_FENCE_DEVICE" \
    "$TEAM_HUB_REACTIVATION_FENCE_INODE" \
    "$allow_missing"
}

team_hub_startup_authority_control() {
  local action="$1"
  local runtime_root="${2:-$RELEASE_DIR}"
  local allow_missing="${3:-false}"
  local data_dir=""
  local hub_id=""
  local reason=""
  local operation_id=""
  local snapshot=""
  if [[ "$TEAM_HUB_REACTIVATION_FENCE_PENDING" == "true" ]]; then
    data_dir="$TEAM_HUB_CANONICAL_DATA_DIR"
    hub_id="$TEAM_HUB_REACTIVATION_HUB_ID"
    reason="host-reactivation"
    operation_id="$TEAM_HUB_REACTIVATION_OPERATION_ID"
    snapshot="$TEAM_HUB_REACTIVATION_SNAPSHOT"
  elif [[ "$TEAM_HUB_OPERATION_PENDING" == "true" ]]; then
    data_dir="$TEAM_HUB_DATA_DIR"
    hub_id="$EXPECTED_TEAM_HUB_ID"
    reason="server-update"
    operation_id="$TEAM_HUB_OPERATION_ID"
    snapshot="$TEAM_HUB_SNAPSHOT"
  else
    return 0
  fi
  local arguments=(
    "${action}-fenced-start-authority"
    --data-dir "$data_dir"
    --snapshot "$snapshot"
    --expected-host-identity "$EXPECTED_SERVER_IDENTITY"
    --expected-hub-id "$hub_id"
    --expected-reason "$reason"
    --expected-operation-id "$operation_id"
  )
  if [[ "$action" == "clear" && "$allow_missing" == "true" ]]; then
    arguments+=(--allow-missing)
  fi
  run_without_server_secrets env PYTHONPATH="$runtime_root" \
    "$runtime_root/.venv/bin/python" -m agentsdock_team_hub.cli \
    "${arguments[@]}" >/dev/null
}

publish_team_hub_startup_authority() {
  if team_hub_startup_authority_control publish "${1:-$RELEASE_DIR}"; then
    TEAM_HUB_STARTUP_AUTHORITY_PENDING="true"
    return 0
  fi
  return 1
}

clear_team_hub_startup_authority() {
  [[ "$TEAM_HUB_STARTUP_AUTHORITY_PENDING" == "true" ]] || return 0
  if team_hub_startup_authority_control \
      clear "${1:-$RELEASE_DIR}" "${2:-false}"; then
    TEAM_HUB_STARTUP_AUTHORITY_PENDING="false"
    return 0
  fi
  return 1
}

mask_install_signals() {
  trap '' HUP INT TERM
}

resume_install_signals() {
  trap 'exit 130' HUP INT TERM
}

verify_team_hub_operation_fence() {
  [[ "$TEAM_HUB_OPERATION_PENDING" == "true" ]] || return 0
  local runtime=""
  local python_path=""
  local source_root=""
  local result=""
  local returned_device=""
  local returned_inode=""
  runtime="$(team_hub_control_runtime "${1:-}")" || {
    echo "No installed runtime can verify the Team Hub maintenance fence." >&2
    return 1
  }
  python_path="${runtime%%$'\n'*}"
  source_root="${runtime#*$'\n'}"
  result="$(run_without_server_secrets env PYTHONPATH="$source_root" "$python_path" -c '
import os
from pathlib import Path
import sys
from agentsdock_team_hub.store import HubStore

fence = Path(sys.argv[1]) / "maintenance-fence.json"
before = fence.lstat()
matched = HubStore.maintenance_fence_matches_control(
    Path(sys.argv[1]),
    expected_hub_id=sys.argv[2],
    expected_host_identity=sys.argv[3],
    expected_reason="server-update",
    expected_operation_id=sys.argv[4],
    expected_snapshot=Path(sys.argv[5]),
)
if not matched:
    raise RuntimeError("the exact Team Hub maintenance fence is missing")
after = fence.lstat()
if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
    raise RuntimeError("the exact Team Hub maintenance fence changed")
print(after.st_dev)
print(after.st_ino)
' \
    "$TEAM_HUB_DATA_DIR" \
    "$EXPECTED_TEAM_HUB_ID" \
    "$EXPECTED_SERVER_IDENTITY" \
    "$TEAM_HUB_OPERATION_ID" \
    "$TEAM_HUB_SNAPSHOT")" || return 1
  returned_device="${result%%$'\n'*}"
  returned_inode="${result#*$'\n'}"
  if [[ "$result" != *$'\n'* \
    || ! "$returned_device" =~ ^[1-9][0-9]*$ \
    || ! "$returned_inode" =~ ^[1-9][0-9]*$ \
    || "$returned_inode" == *$'\n'* ]]; then
    echo "Team Hub maintenance fence verifier returned invalid ownership." >&2
    return 1
  fi
  TEAM_HUB_OPERATION_FENCE_DEVICE="$returned_device"
  TEAM_HUB_OPERATION_FENCE_INODE="$returned_inode"
}

verify_team_hub_rollback_snapshot() {
  [[ "$TEAM_HUB_OPERATION_PENDING" == "true" ]] || return 0
  local runtime=""
  local python_path=""
  local source_root=""
  runtime="$(team_hub_control_runtime "${1:-}")" || {
    echo "No installed runtime can verify the Team Hub rollback snapshot." >&2
    return 1
  }
  python_path="${runtime%%$'\n'*}"
  source_root="${runtime#*$'\n'}"
  run_without_server_secrets env PYTHONPATH="$source_root" "$python_path" -m agentsdock_team_hub.cli \
    verify-snapshot \
    --data-dir "$TEAM_HUB_DATA_DIR" \
    --snapshot "$TEAM_HUB_SNAPSHOT" \
    --expected-host-identity "$EXPECTED_SERVER_IDENTITY" \
    --expected-hub-id "$EXPECTED_TEAM_HUB_ID" \
    --expected-operation-id "$TEAM_HUB_OPERATION_ID"
}

rebase_team_hub_rollback_snapshot() {
  [[ "$TEAM_HUB_OPERATION_PENDING" == "true" ]] || return 0
  run_without_server_secrets env PYTHONPATH="$CANDIDATE_RUNTIME_ROOT" \
    "$CANDIDATE_RUNTIME_ROOT/.venv/bin/python" -m agentsdock_team_hub.cli \
    rebase-snapshot \
    --data-dir "$TEAM_HUB_DATA_DIR" \
    --snapshot "$TEAM_HUB_SNAPSHOT" \
    --expected-host-identity "$EXPECTED_SERVER_IDENTITY" \
    --expected-hub-id "$EXPECTED_TEAM_HUB_ID" \
    --expected-operation-id "$TEAM_HUB_OPERATION_ID" >/dev/null
}

verify_team_hub_reactivation_snapshot() {
  [[ "$TEAM_HUB_REACTIVATION_REQUESTED" == "true" \
    || "$TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED" == "true" ]] || return 0
  local runtime_root="$1"
  run_without_server_secrets env PYTHONPATH="$runtime_root" \
    "$runtime_root/.venv/bin/python" -m agentsdock_team_hub.cli \
    verify-host-reactivation-snapshot \
    --data-dir "$TEAM_HUB_CANONICAL_DATA_DIR" \
      --snapshot "$TEAM_HUB_REACTIVATION_SNAPSHOT" \
      --expected-host-identity "$EXPECTED_SERVER_IDENTITY" \
      --expected-hub-id "$TEAM_HUB_REACTIVATION_HUB_ID" \
      --expected-operation-id "$TEAM_HUB_REACTIVATION_OPERATION_ID" >/dev/null
}

early_operation_cleanup() {
  local exit_status=$?
  trap - EXIT
  mask_install_signals
  set +e
  if [[ "$exit_status" != "0" && "$TEAM_HUB_OPERATION_PENDING" == "true" && "$TEAM_HUB_OPERATION_FINALIZED" != "true" ]]; then
    if clear_team_hub_operation_fence "$CURRENT_LINK"; then
      TEAM_HUB_OPERATION_FINALIZED="true"
    else
      echo "AgentsServer install failed before takeover and could not clear the exact Team Hub maintenance fence." >&2
    fi
  fi
  exit "$exit_status"
}

trap early_operation_cleanup EXIT
trap 'exit 130' HUP INT TERM

safe_config_python() {
  local candidate=""
  for candidate in \
    "/usr/bin/python3" \
    "$(command -v python3 2>/dev/null || true)" \
    "$STAGE_DIR/.venv/bin/python" \
    "$INSTALL_ROOT/current/.venv/bin/python"; do
    [[ -n "$candidate" && -x "$candidate" ]] || continue
    if [[ "$("$candidate" -c 'print("agentsdock-safe-config-v1")' 2>/dev/null || true)" \
      == "agentsdock-safe-config-v1" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

validate_bind_address() {
  local value="$1"
  local supplied_python="${2:-}"
  case "$value" in
    localhost|0.0.0.0|127.0.0.1|::|::1) return 0 ;;
  esac
  if [[ -z "$value" || ${#value} -gt 64 \
    || ! "$value" =~ ^[0-9A-Fa-f:.]+$ ]]; then
    return 1
  fi
  local python_path=""
  if [[ -n "$supplied_python" ]]; then
    [[ -x "$supplied_python" ]] || return 1
    python_path="$supplied_python"
  else
    # A fresh host may intentionally let uv create the release Python. The
    # strict canonical check is repeated with that staged interpreter before
    # any configuration or service publication; this early branch only needs
    # to reject control/config-injection characters without requiring Python.
    python_path="$(safe_config_python)" || return 0
  fi
  "$python_path" - "$value" <<'PY'
import ipaddress
import sys

value = sys.argv[1]
try:
    parsed = ipaddress.ip_address(value)
except ValueError:
    raise SystemExit(1)
if str(parsed) != value:
    raise SystemExit(1)
PY
}

read_owned_config_file() {
  local file="$1"
  local python_path=""
  python_path="$(safe_config_python)" || {
    echo "A trusted Python runtime is required to read existing AgentsServer configuration safely." >&2
    return 1
  }
  "$python_path" - "$file" <<'PY'
import os
from pathlib import Path
import stat
import sys

path = Path(os.path.abspath(os.path.expanduser(sys.argv[1])))
maximum = 16 * 1024 * 1024
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
try:
    descriptor = os.open(path, flags)
except FileNotFoundError:
    raise SystemExit(3)
try:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) & 0o022
        or not 0 <= before.st_size <= maximum
    ):
        raise PermissionError("configuration source is unsafe")
    chunks = []
    remaining = maximum + 1
    while remaining:
        chunk = os.read(descriptor, min(remaining, 1024 * 1024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    payload = b"".join(chunks)
    after = os.fstat(descriptor)
    linked = path.lstat()
    if (
        len(payload) > maximum
        or len(payload) != before.st_size
        or b"\0" in payload
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or (before.st_dev, before.st_ino) != (linked.st_dev, linked.st_ino)
    ):
        raise RuntimeError("configuration source changed while reading")
    sys.stdout.buffer.write(payload)
finally:
    os.close(descriptor)
PY
}

if ! validate_bind_address "$BIND_ADDRESS"; then
  echo "Bind address must be localhost or one canonical IPv4/IPv6 literal." >&2
  exit 2
fi

read_env_value() {
  local file="$1"
  local name="$2"
  local contents=""
  [[ -n "$file" && ( -e "$file" || -L "$file" ) ]] || return 0
  contents="$(read_owned_config_file "$file")" || return 1
  printf '%s\n' "$contents" | sed -n "s/^${name}=//p" | tail -n 1
}

env_file_has_key() {
  local file="$1"
  local name="$2"
  local contents=""
  [[ -n "$file" && ( -e "$file" || -L "$file" ) ]] || return 1
  contents="$(read_owned_config_file "$file")" || {
    echo "$file changed or became unsafe while reading configuration." >&2
    exit 1
  }
  printf '%s\n' "$contents" | grep -q "^${name}="
}

read_persisted_team_hub_config() {
  RESOLVED_TEAM_HUB_MODE=""
  if env_file_has_key "$ENV_FILE" AGENTSDOCK_TEAM_HUB_MODE; then
    RESOLVED_TEAM_HUB_MODE="$(read_env_value "$ENV_FILE" AGENTSDOCK_TEAM_HUB_MODE)"
  elif env_file_has_key "$LEGACY_ENV_FILE" AGENTSDOCK_TEAM_HUB_MODE; then
    RESOLVED_TEAM_HUB_MODE="$(read_env_value "$LEGACY_ENV_FILE" AGENTSDOCK_TEAM_HUB_MODE)"
  else
    RESOLVED_TEAM_HUB_MODE="${AGENTSDOCK_TEAM_HUB_MODE:-}"
  fi

  RESOLVED_TEAM_HUB_TRANSPORT=""
  RESOLVED_TEAM_HUB_TRANSPORT_SET="false"
  if env_file_has_key "$ENV_FILE" AGENTSDOCK_TEAM_HUB_TRANSPORT; then
    RESOLVED_TEAM_HUB_TRANSPORT="$(read_env_value "$ENV_FILE" AGENTSDOCK_TEAM_HUB_TRANSPORT)"
    RESOLVED_TEAM_HUB_TRANSPORT_SET="true"
  elif env_file_has_key "$LEGACY_ENV_FILE" AGENTSDOCK_TEAM_HUB_TRANSPORT; then
    RESOLVED_TEAM_HUB_TRANSPORT="$(read_env_value "$LEGACY_ENV_FILE" AGENTSDOCK_TEAM_HUB_TRANSPORT)"
    RESOLVED_TEAM_HUB_TRANSPORT_SET="true"
  elif [[ "${AGENTSDOCK_TEAM_HUB_TRANSPORT+x}" == "x" ]]; then
    RESOLVED_TEAM_HUB_TRANSPORT="$AGENTSDOCK_TEAM_HUB_TRANSPORT"
    RESOLVED_TEAM_HUB_TRANSPORT_SET="true"
  fi

  RESOLVED_TEAM_HUB_URL=""
  if env_file_has_key "$ENV_FILE" AGENTSDOCK_TEAM_HUB_URL; then
    RESOLVED_TEAM_HUB_URL="$(read_env_value "$ENV_FILE" AGENTSDOCK_TEAM_HUB_URL)"
  elif env_file_has_key "$LEGACY_ENV_FILE" AGENTSDOCK_TEAM_HUB_URL; then
    RESOLVED_TEAM_HUB_URL="$(read_env_value "$LEGACY_ENV_FILE" AGENTSDOCK_TEAM_HUB_URL)"
  else
    RESOLVED_TEAM_HUB_URL="${AGENTSDOCK_TEAM_HUB_URL:-}"
  fi

  RESOLVED_TEAM_HUB_DIRECT_IP_URL=""
  if env_file_has_key "$ENV_FILE" AGENTSDOCK_TEAM_HUB_DIRECT_IP_URL; then
    RESOLVED_TEAM_HUB_DIRECT_IP_URL="$(read_env_value "$ENV_FILE" AGENTSDOCK_TEAM_HUB_DIRECT_IP_URL)"
  elif env_file_has_key "$LEGACY_ENV_FILE" AGENTSDOCK_TEAM_HUB_DIRECT_IP_URL; then
    RESOLVED_TEAM_HUB_DIRECT_IP_URL="$(read_env_value "$LEGACY_ENV_FILE" AGENTSDOCK_TEAM_HUB_DIRECT_IP_URL)"
  else
    RESOLVED_TEAM_HUB_DIRECT_IP_URL="${AGENTSDOCK_TEAM_HUB_DIRECT_IP_URL:-}"
  fi
}

canonical_team_hub_tailnet_hostname() {
  local hostname="$1"
  local label=""
  local -a labels=()
  [[ "$hostname" != *. ]] || return 1
  IFS='.' read -r -a labels <<< "$hostname"
  ((${#labels[@]} >= 4)) || return 1
  [[ "${labels[${#labels[@]} - 2]}" == "ts" && "${labels[${#labels[@]} - 1]}" == "net" ]] || return 1
  for label in "${labels[@]}"; do
    (( ${#label} >= 1 && ${#label} <= 63 )) || return 1
    [[ "$label" != xn--* ]] || return 1
    if [[ ! "$label" =~ ^[a-z0-9]$ && ! "$label" =~ ^[a-z0-9][a-z0-9-]*[a-z0-9]$ ]]; then
      return 1
    fi
  done
}

canonical_team_hub_direct_ipv4_url() {
  local value="$1"
  local expected_port="$2"
  local direct_host=""
  local octet=""
  local -a octets=()
  [[ "$value" =~ ^http://([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):([0-9]{1,5})/api/team-hub$ ]] || return 1
  [[ "${BASH_REMATCH[2]}" == "$expected_port" ]] || return 1
  direct_host="${BASH_REMATCH[1]}"
  IFS='.' read -r -a octets <<< "$direct_host"
  ((${#octets[@]} == 4)) || return 1
  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^0$|^[1-9][0-9]{0,2}$ ]] || return 1
    ((10#$octet <= 255)) || return 1
  done
  ((10#${octets[0]} != 0 && 10#${octets[0]} != 127 && 10#${octets[0]} < 224)) || return 1
  [[ "$BIND_ADDRESS" == "0.0.0.0" \
    || "$BIND_ADDRESS" == "$direct_host" ]] || return 1
}

LEGACY_ENV_FILE=""
LEGACY_SERVICE_CONTENTS=""
if [[ -e "$LEGACY_SERVICE_FILE" || -L "$LEGACY_SERVICE_FILE" ]]; then
  if ! LEGACY_SERVICE_CONTENTS="$(read_owned_config_file "$LEGACY_SERVICE_FILE")"; then
    echo "$LEGACY_SERVICE_FILE is not a safe regular legacy service file." >&2
    exit 1
  fi
  LEGACY_ENV_FILE="$(printf '%s\n' "$LEGACY_SERVICE_CONTENTS" \
    | sed -n 's/^EnvironmentFile=//p' | tail -n 1)"
  LEGACY_ENV_FILE="${LEGACY_ENV_FILE#-}"
  LEGACY_ENV_FILE="${LEGACY_ENV_FILE#\"}"
  LEGACY_ENV_FILE="${LEGACY_ENV_FILE%\"}"
  if [[ "$LEGACY_ENV_FILE" == %h/* ]]; then
    LEGACY_ENV_FILE="$HOME/${LEGACY_ENV_FILE#%h/}"
  elif [[ -n "$LEGACY_ENV_FILE" && "$LEGACY_ENV_FILE" != /* ]]; then
    echo "$LEGACY_SERVICE_FILE has a non-absolute EnvironmentFile path." >&2
    exit 1
  fi
fi
if [[ -z "$LEGACY_ENV_FILE" \
  && ( -e "$HOME/Zenithbot/.env" || -L "$HOME/Zenithbot/.env" ) ]]; then
  LEGACY_ENV_FILE="$HOME/Zenithbot/.env"
fi

for existing_config in "$ENV_FILE" "$LEGACY_ENV_FILE"; do
  [[ -n "$existing_config" && ( -e "$existing_config" || -L "$existing_config" ) ]] \
    || continue
  if ! read_owned_config_file "$existing_config" >/dev/null; then
    echo "$existing_config is not a safe regular configuration file." >&2
    exit 1
  fi
done

find_existing_token() {
  local candidate found_token
  for candidate in "$ENV_FILE" "$LEGACY_ENV_FILE"; do
    [[ -n "$candidate" && ( -e "$candidate" || -L "$candidate" ) ]] || continue
    found_token="$(read_env_value "$candidate" AGENTSDOCK_AGENT_TOKEN)" || return 1
    if [[ -z "$found_token" ]]; then
      found_token="$(read_env_value "$candidate" ZENITHDOCK_AGENT_TOKEN)" \
        || return 1
    fi
    if [[ -z "$found_token" ]]; then
      found_token="$(read_env_value "$candidate" ZENITHBOT_AGENT_TOKEN)" \
        || return 1
    fi
    [[ -z "$found_token" ]] || { printf '%s' "$found_token"; return 0; }
  done
  if [[ -n "$LEGACY_SERVICE_CONTENTS" ]]; then
    found_token="$(printf '%s\n' "$LEGACY_SERVICE_CONTENTS" \
      | grep -E '^Environment="?ZENITHDOCK_AGENT_TOKEN=' | tail -n 1 || true)"
    found_token="${found_token#*ZENITHDOCK_AGENT_TOKEN=}"
    found_token="${found_token%\"}"
    [[ -z "$found_token" ]] || { printf '%s' "$found_token"; return 0; }
  fi
  return 1
}

if [[ "$SHOW_TOKEN" == "true" ]]; then
  if TOKEN_TO_SHOW="$(find_existing_token)"; then
    printf '%s\n' "$TOKEN_TO_SHOW"
    exit 0
  fi
  echo "No AgentsServer access token found at $ENV_FILE. Run install.sh first." >&2
  exit 1
fi

OS_NAME="$(uname -s)"
SYSTEMD_SERVICE_FILE="$HOME/.config/systemd/user/$SERVICE_NAME.service"
LABEL="com.agentsdock.server"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
SERVER_PATH=""
append_server_path() {
  local candidate="$1"
  [[ -n "$candidate" ]] || return 0
  case ":$SERVER_PATH:" in
    *":$candidate:"*) ;;
    *) SERVER_PATH="${SERVER_PATH:+$SERVER_PATH:}$candidate" ;;
  esac
}

append_server_path_list() {
  local path_list="$1"
  local candidate
  local old_ifs="$IFS"
  IFS=":"
  for candidate in $path_list; do
    append_server_path "$candidate"
  done
  IFS="$old_ifs"
}

EXISTING_PATH="$(read_env_value "$ENV_FILE" PATH)"
[[ -n "$EXISTING_PATH" ]] || EXISTING_PATH="$(read_env_value "$LEGACY_ENV_FILE" PATH)"
# Prefer the previously saved runtime PATH when present, otherwise retain the
# launcher's PATH. Add standard user and Homebrew locations without allowing
# repeated installs to grow the saved value indefinitely.
append_server_path_list "${EXISTING_PATH:-${PATH:-}}"
append_server_path "$HOME/.local/bin"
append_server_path "$HOME/.cargo/bin"
append_server_path "/opt/homebrew/bin"
append_server_path "/usr/local/bin"
append_server_path "/usr/bin"
append_server_path "/bin"
export PATH="$SERVER_PATH"

if [[ "$PORT_EXPLICIT" != "true" ]]; then
  existing_network_value="$(read_env_value "$ENV_FILE" AGENTSDOCK_AGENT_PORT)" \
    || exit 1
  [[ -n "$existing_network_value" ]] || existing_network_value="$(read_env_value \
    "$LEGACY_ENV_FILE" AGENTSDOCK_AGENT_PORT)" || exit 1
  [[ -n "$existing_network_value" ]] || existing_network_value="$(read_env_value \
    "$LEGACY_ENV_FILE" ZENITHBOT_AGENT_PORT)" || exit 1
  [[ -n "$existing_network_value" ]] || existing_network_value="$(read_env_value \
    "$LEGACY_ENV_FILE" ZENITHDOCK_AGENT_PORT)" || exit 1
  if [[ -n "$existing_network_value" ]]; then
    if [[ ! "$existing_network_value" =~ ^[0-9]+$ \
      || "$existing_network_value" -lt 1 \
      || "$existing_network_value" -gt 65535 ]]; then
      echo "The persisted AgentsServer port is invalid." >&2
      exit 2
    fi
    PORT="$existing_network_value"
  fi
fi
if [[ "$BIND_EXPLICIT" != "true" ]]; then
  existing_network_value="$(read_env_value "$ENV_FILE" AGENTSDOCK_AGENT_BIND)" \
    || exit 1
  [[ -n "$existing_network_value" ]] || existing_network_value="$(read_env_value \
    "$LEGACY_ENV_FILE" AGENTSDOCK_AGENT_BIND)" || exit 1
  [[ -n "$existing_network_value" ]] || existing_network_value="$(read_env_value \
    "$LEGACY_ENV_FILE" ZENITHBOT_AGENT_BIND)" || exit 1
  [[ -n "$existing_network_value" ]] || existing_network_value="$(read_env_value \
    "$LEGACY_ENV_FILE" ZENITHDOCK_AGENT_BIND)" || exit 1
  if [[ -n "$existing_network_value" ]]; then
    validate_bind_address "$existing_network_value" || {
      echo "The persisted AgentsServer bind address is invalid." >&2
      exit 2
    }
    BIND_ADDRESS="$existing_network_value"
  fi
fi

EXISTING_ENV_TEAM_HUB_MODE_SET="false"
EXISTING_ENV_TEAM_HUB_MODE_VALUE=""
EXISTING_ENV_TEAM_HUB_TRANSPORT_SET="false"
EXISTING_ENV_TEAM_HUB_TRANSPORT_VALUE=""
EXISTING_ENV_TEAM_HUB_URL_SET="false"
EXISTING_ENV_TEAM_HUB_URL_VALUE=""
EXISTING_ENV_TEAM_HUB_DIRECT_IP_URL_SET="false"
EXISTING_ENV_TEAM_HUB_DIRECT_IP_URL_VALUE=""
if [[ -f "$ENV_FILE" && ! -L "$ENV_FILE" ]]; then
  if env_file_has_key "$ENV_FILE" AGENTSDOCK_TEAM_HUB_MODE; then
    EXISTING_ENV_TEAM_HUB_MODE_SET="true"
    EXISTING_ENV_TEAM_HUB_MODE_VALUE="$(read_env_value "$ENV_FILE" AGENTSDOCK_TEAM_HUB_MODE)"
  fi
  if env_file_has_key "$ENV_FILE" AGENTSDOCK_TEAM_HUB_TRANSPORT; then
    EXISTING_ENV_TEAM_HUB_TRANSPORT_SET="true"
    EXISTING_ENV_TEAM_HUB_TRANSPORT_VALUE="$(read_env_value "$ENV_FILE" AGENTSDOCK_TEAM_HUB_TRANSPORT)"
  fi
  if env_file_has_key "$ENV_FILE" AGENTSDOCK_TEAM_HUB_URL; then
    EXISTING_ENV_TEAM_HUB_URL_SET="true"
    EXISTING_ENV_TEAM_HUB_URL_VALUE="$(read_env_value "$ENV_FILE" AGENTSDOCK_TEAM_HUB_URL)"
  fi
  if env_file_has_key "$ENV_FILE" AGENTSDOCK_TEAM_HUB_DIRECT_IP_URL; then
    EXISTING_ENV_TEAM_HUB_DIRECT_IP_URL_SET="true"
    EXISTING_ENV_TEAM_HUB_DIRECT_IP_URL_VALUE="$(read_env_value "$ENV_FILE" AGENTSDOCK_TEAM_HUB_DIRECT_IP_URL)"
  fi
fi

read_persisted_team_hub_config
EXISTING_TEAM_HUB_MODE="$RESOLVED_TEAM_HUB_MODE"
TEAM_HUB_MODE="${TEAM_HUB_MODE_OVERRIDE:-${EXISTING_TEAM_HUB_MODE:-disabled}}"
if [[ "$TEAM_HUB_MODE" != "host" && "$TEAM_HUB_MODE" != "disabled" ]]; then
  echo "AGENTSDOCK_TEAM_HUB_MODE must be host or disabled." >&2
  exit 2
fi
if [[ "$TEAM_HUB_REACTIVATION_REQUESTED" == "true" && "$EXISTING_TEAM_HUB_MODE" != "disabled" ]]; then
  echo "Explicit Team Hub reactivation requires a previously disabled Hub host." >&2
  exit 2
fi
if [[ "$TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED" == "true" \
  && "$EXISTING_TEAM_HUB_MODE" != "host" ]]; then
  echo "Failed Team Hub repair requires an existing configured Hub host." >&2
  exit 2
fi
EXISTING_TEAM_HUB_TRANSPORT="$RESOLVED_TEAM_HUB_TRANSPORT"
EXISTING_TEAM_HUB_TRANSPORT_SET="$RESOLVED_TEAM_HUB_TRANSPORT_SET"
EXISTING_TEAM_HUB_URL="$RESOLVED_TEAM_HUB_URL"
EXISTING_TEAM_HUB_DIRECT_IP_URL="$RESOLVED_TEAM_HUB_DIRECT_IP_URL"
PREVIOUS_TEAM_HUB_TRANSPORT="loopback"
PREVIOUS_TEAM_HUB_MODE="${EXISTING_TEAM_HUB_MODE:-disabled}"
if [[ "$EXISTING_TEAM_HUB_TRANSPORT_SET" == "true" ]]; then
  PREVIOUS_TEAM_HUB_TRANSPORT="$EXISTING_TEAM_HUB_TRANSPORT"
fi
PREVIOUS_TEAM_HUB_URL="$EXISTING_TEAM_HUB_URL"
PREVIOUS_TEAM_HUB_DIRECT_IP_URL="$EXISTING_TEAM_HUB_DIRECT_IP_URL"
PRIOR_PORT="$PORT"
PRIOR_BIND_ADDRESS="$BIND_ADDRESS"
if [[ "$TEAM_HUB_MODE" == "disabled" ]]; then
  TEAM_HUB_TRANSPORT="loopback"
  TEAM_HUB_URL=""
else
  if [[ -n "$TEAM_HUB_TRANSPORT_OVERRIDE" ]]; then
    TEAM_HUB_TRANSPORT="$TEAM_HUB_TRANSPORT_OVERRIDE"
  elif [[ "$EXISTING_TEAM_HUB_TRANSPORT_SET" == "true" ]]; then
    TEAM_HUB_TRANSPORT="$EXISTING_TEAM_HUB_TRANSPORT"
  else
    TEAM_HUB_TRANSPORT="loopback"
  fi
  TEAM_HUB_URL="${TEAM_HUB_URL_OVERRIDE:-$EXISTING_TEAM_HUB_URL}"
  TEAM_HUB_DIRECT_IP_URL="${TEAM_HUB_DIRECT_IP_URL_OVERRIDE:-$EXISTING_TEAM_HUB_DIRECT_IP_URL}"
  if [[ -n "$TEAM_HUB_DIRECT_IP_URL_OVERRIDE" && -z "$TEAM_HUB_TRANSPORT_OVERRIDE" ]] && {
    [[ "$EXISTING_TEAM_HUB_TRANSPORT_SET" != "true" ]] \
      || [[ "$EXISTING_TEAM_HUB_MODE" != "host" ]]
  }; then
    TEAM_HUB_TRANSPORT="direct_ip"
    TEAM_HUB_URL="$TEAM_HUB_DIRECT_IP_URL"
  fi
fi
case "$TEAM_HUB_TRANSPORT" in
  loopback)
    if [[ -n "$TEAM_HUB_URL" ]]; then
      echo "Loopback Team Hub transport does not accept an external Hub URL." >&2
      exit 2
    fi
    ;;
  tailscale_serve)
    if [[ "$TEAM_HUB_MODE" != "host" ]]; then
      echo "Tailscale Serve Team Hub transport requires host mode." >&2
      exit 2
    fi
    TEAM_HUB_URL_LOWER="$(printf '%s' "$TEAM_HUB_URL" | tr '[:upper:]' '[:lower:]')"
    if [[ "$TEAM_HUB_URL" != "$TEAM_HUB_URL_LOWER" ]]; then
      echo "Team Hub Tailscale Serve URL must be canonical HTTPS on an explicit *.ts.net port and end in /api/team-hub." >&2
      exit 2
    fi
    if [[ "$TEAM_HUB_URL" =~ ^https://([a-z0-9][a-z0-9.-]*\.ts\.net):([0-9]{1,5})/api/team-hub$ ]]; then
      TEAM_HUB_SERVE_HOST="${BASH_REMATCH[1]}"
      TEAM_HUB_SERVE_PORT="${BASH_REMATCH[2]}"
    else
      echo "Team Hub Tailscale Serve URL must be canonical HTTPS on an explicit *.ts.net port and end in /api/team-hub." >&2
      exit 2
    fi
    if [[ "$TEAM_HUB_SERVE_PORT" == "443" || "$TEAM_HUB_SERVE_PORT" == "8443" || "$TEAM_HUB_SERVE_PORT" == "10000" ]]; then
      echo "Team Hub Tailscale Serve URL is invalid or uses a Funnel-capable port." >&2
      exit 2
    fi
    if [[ "$TEAM_HUB_SERVE_PORT" != "8444" ]]; then
      echo "Team Hub Tailscale Serve URL must use the private beta port 8444." >&2
      exit 2
    fi
    if ! canonical_team_hub_tailnet_hostname "$TEAM_HUB_SERVE_HOST"; then
      echo "Team Hub Tailscale Serve URL has a noncanonical tailnet hostname." >&2
      exit 2
    fi
    ;;
  direct_ip)
    if [[ "$TEAM_HUB_MODE" != "host" || -z "$TEAM_HUB_URL" || "$TEAM_HUB_URL" != "$TEAM_HUB_DIRECT_IP_URL" ]]; then
      echo "Direct-IP Team Hub transport requires the exact configured direct-IP URL in host mode." >&2
      exit 2
    fi
    ;;
  *)
    echo "AGENTSDOCK_TEAM_HUB_TRANSPORT must be loopback, tailscale_serve, or direct_ip." >&2
    exit 2
    ;;
esac
if [[ -n "$TEAM_HUB_DIRECT_IP_URL" ]] && ! canonical_team_hub_direct_ipv4_url "$TEAM_HUB_DIRECT_IP_URL" "$PORT"; then
  echo "Team Hub Direct IP URL must be exact http://<literal-ip>:$PORT/api/team-hub on the AgentsServer port." >&2
  exit 2
fi
if [[ "$EXPECTED_TEAM_HUB_DIRECT_IP_URL_SET" == "true" ]] && [[ "$TEAM_HUB_DIRECT_IP_URL" != "$EXPECTED_TEAM_HUB_DIRECT_IP_URL" ]]; then
  echo "Managed Team Hub Direct IP route changed after update acceptance." >&2
  exit 2
fi
if [[ -n "$EXPECTED_TEAM_HUB_ID" \
  || "$TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED" == "true" ]] && {
  [[ "$TEAM_HUB_TRANSPORT" != "$EXPECTED_TEAM_HUB_TRANSPORT" ]] \
    || [[ "$TEAM_HUB_URL" != "$EXPECTED_TEAM_HUB_URL" ]]
}; then
  echo "Managed Team Hub transport or URL changed after update acceptance." >&2
  exit 2
fi
if [[ "$EXISTING_TEAM_HUB_MODE" == "host" && "$TEAM_HUB_MODE" == "host" ]] && {
  [[ "$PREVIOUS_TEAM_HUB_TRANSPORT" != "$TEAM_HUB_TRANSPORT" ]] \
    || [[ "$PREVIOUS_TEAM_HUB_URL" != "$TEAM_HUB_URL" ]]
}; then
  echo "Changing an existing Team Hub origin is not supported by this beta." >&2
  exit 2
fi
if [[ "$EXISTING_TEAM_HUB_MODE" == "host" && "$TEAM_HUB_MODE" == "host" && "$PREVIOUS_TEAM_HUB_DIRECT_IP_URL" != "$TEAM_HUB_DIRECT_IP_URL" ]]; then
  echo "Changing an existing Team Hub Direct IP origin is not supported by this beta." >&2
  exit 2
fi
if [[ -n "$EXPECTED_TEAM_HUB_ID" && "$TEAM_HUB_MODE" != "host" ]]; then
  echo "Managed Team Hub continuity requires AGENTSDOCK_TEAM_HUB_MODE=host." >&2
  exit 2
fi
TEAM_HUB_CANONICAL_DATA_DIR="$STATE_ROOT/team-hub"
if [[ "$TEAM_HUB_OPERATION_PENDING" == "true" ]]; then
  TEAM_HUB_DATA_DIR="$(normalize_managed_path \
    TEAM_HUB_DATA_DIR "$TEAM_HUB_DATA_DIR")" || exit 2
  TEAM_HUB_SNAPSHOT="$(normalize_managed_path \
    TEAM_HUB_SNAPSHOT "$TEAM_HUB_SNAPSHOT")" || exit 2
  if [[ "$TEAM_HUB_DATA_DIR" != "$TEAM_HUB_CANONICAL_DATA_DIR" ]]; then
    echo "Managed Team Hub data must use the configured AgentsServer state directory." >&2
    exit 2
  fi
fi
if [[ "$TEAM_HUB_MODE" == "host" && "$TEAM_HUB_OPERATION_PENDING" != "true" ]]; then
  TEAM_HUB_EXISTING_STATE="false"
  for candidate in \
    "$TEAM_HUB_CANONICAL_DATA_DIR/team-hub.sqlite3" \
    "$TEAM_HUB_CANONICAL_DATA_DIR/team-hub.sqlite3-wal" \
    "$TEAM_HUB_CANONICAL_DATA_DIR/team-hub.sqlite3-shm" \
    "$TEAM_HUB_CANONICAL_DATA_DIR/access-token-signing.key" \
    "$TEAM_HUB_CANONICAL_DATA_DIR/maintenance-fence.json"; do
    if [[ -e "$candidate" || -L "$candidate" ]]; then
      TEAM_HUB_EXISTING_STATE="true"
      break
    fi
  done
  if [[ "$TEAM_HUB_EXISTING_STATE" != "true" && -d "$TEAM_HUB_CANONICAL_DATA_DIR" ]]; then
    if find "$TEAM_HUB_CANONICAL_DATA_DIR" -maxdepth 1 -type f -name '*.proof' -print -quit | grep -q .; then
      TEAM_HUB_EXISTING_STATE="true"
    fi
  fi
  if [[ "$TEAM_HUB_REACTIVATION_REQUESTED" == "true" && "$TEAM_HUB_EXISTING_STATE" != "true" ]]; then
    echo "No preserved Team Hub state is available for explicit reactivation." >&2
    echo "  Use --team-hub-host to create a new Hub host instead." >&2
    exit 1
  fi
  if [[ "$TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED" == "true" \
    && "$TEAM_HUB_EXISTING_STATE" != "true" ]]; then
    echo "Failed Team Hub repair requires preserved bound Hub state." >&2
    exit 1
  fi
  if [[ "$TEAM_HUB_EXISTING_STATE" == "true" \
    && "$TEAM_HUB_REACTIVATION_REQUESTED" != "true" \
    && "$TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED" != "true" ]]; then
    echo "Existing Team Hub state requires explicit verified reactivation." >&2
    echo "  Re-run with --reactivate-team-hub-host to verify its managed binding and write a pre-reactivation snapshot." >&2
    exit 1
  fi
fi

RELEASE_FILES=(activation_transaction.py agent_server.py team_hub_host.py secure_peer_runtime.py secure_peer_delivery.py agentsdock_jobs.py agentsdock_chats.py agentsdock_emergency.py agentsdock_publish.py agentsdock_mail.py agentsdock_team.py claude_sdk_client.py codex_app_server.py cursor_agent_client.py cursor_process_guard.py install.sh uninstall.sh update_runner.py pyproject.toml uv.lock VERSION release-public-key.pem)
RELEASE_DIRECTORIES=(agentsdock_team_hub)
TEAM_HUB_RELEASE_FILES=(
  __init__.py
  auth.py
  cli.py
  database.py
  security.py
  secure_peer.py
  secure_peer_hub.py
  service.py
  store.py
  migrations/__init__.py
  migrations/0001_identity_auth.sql
  migrations/0002_teamspace_ledger.sql
  migrations/0003_service_runtime.sql
  migrations/0004_managed_host_binding.sql
  migrations/0005_tailnet_bootstrap_delegations.sql
  migrations/0006_team_network_mailbox.sql
  migrations/0007_local_agent_mail.sql
  migrations/0008_managed_server_session.sql
  migrations/0009_team_messages.sql
  migrations/0010_team_attachment_orphan_reclamation.sql
  migrations/0011_human_admin_paging.sql
)

for name in "${RELEASE_FILES[@]}"; do
  if [[ ! -f "$SOURCE_DIR/$name" || -L "$SOURCE_DIR/$name" ]]; then
    echo "$name is missing beside install.sh or is not a regular release file." >&2
    exit 1
  fi
done
for name in "${RELEASE_DIRECTORIES[@]}"; do
  if [[ ! -d "$SOURCE_DIR/$name" || -L "$SOURCE_DIR/$name" ]]; then
    echo "$name is missing beside install.sh or is not a real directory." >&2
    exit 1
  fi
  if find "$SOURCE_DIR/$name" \( -type l -o -type f \( -name '*.pyc' -o -name '*.pyo' \) -o -type d -name '__pycache__' -o \( ! -type d ! -type f \) \) -print -quit | grep -q .; then
    echo "$name contains linked or generated entries and cannot be installed." >&2
    exit 1
  fi
done
for name in "${TEAM_HUB_RELEASE_FILES[@]}"; do
  if [[ ! -f "$SOURCE_DIR/agentsdock_team_hub/$name" || -L "$SOURCE_DIR/agentsdock_team_hub/$name" ]]; then
    echo "agentsdock_team_hub/$name is missing or is not a regular release file." >&2
    exit 1
  fi
done
TEAM_HUB_RELEASE_FILE_COUNT="$(find "$SOURCE_DIR/agentsdock_team_hub" -type f | wc -l)"
TEAM_HUB_RELEASE_FILE_COUNT="${TEAM_HUB_RELEASE_FILE_COUNT//[[:space:]]/}"
if [[ "$TEAM_HUB_RELEASE_FILE_COUNT" != "${#TEAM_HUB_RELEASE_FILES[@]}" ]]; then
  echo "agentsdock_team_hub contains unexpected release files." >&2
  exit 1
fi
TEAM_HUB_RELEASE_DIRECTORY_COUNT="$(find "$SOURCE_DIR/agentsdock_team_hub" -type d | wc -l)"
TEAM_HUB_RELEASE_DIRECTORY_COUNT="${TEAM_HUB_RELEASE_DIRECTORY_COUNT//[[:space:]]/}"
if [[ "$TEAM_HUB_RELEASE_DIRECTORY_COUNT" != "2" ]]; then
  echo "agentsdock_team_hub contains unexpected release directories." >&2
  exit 1
fi

current_release_binding() {
  if [[ -L "$CURRENT_LINK" ]]; then
    printf 'symlink:%s' "$(readlink "$CURRENT_LINK")"
  elif [[ -d "$CURRENT_LINK" ]]; then
    printf 'directory'
  elif [[ -e "$CURRENT_LINK" ]]; then
    return 1
  else
    printf 'missing'
  fi
}

assert_team_hub_config_unchanged() {
  read_persisted_team_hub_config
  if [[ "$RESOLVED_TEAM_HUB_MODE" != "$EXISTING_TEAM_HUB_MODE" \
    || "$RESOLVED_TEAM_HUB_TRANSPORT_SET" != "$EXISTING_TEAM_HUB_TRANSPORT_SET" \
    || "$RESOLVED_TEAM_HUB_TRANSPORT" != "$EXISTING_TEAM_HUB_TRANSPORT" \
    || "$RESOLVED_TEAM_HUB_URL" != "$EXISTING_TEAM_HUB_URL" \
    || "$RESOLVED_TEAM_HUB_DIRECT_IP_URL" != "$EXISTING_TEAM_HUB_DIRECT_IP_URL" ]]; then
    echo "Team Hub configuration changed while the installer was preparing." >&2
    return 1
  fi
}

validate_managed_team_hub_inputs() {
  local runtime_root="$1"
  local current_binding=""
  local expected_current_binding=""
  local candidate=""
  [[ "$TEAM_HUB_OPERATION_PENDING" == "true" ]] || return 0
  expected_current_binding="$INITIAL_CURRENT_LINK_BINDING"
  assert_team_hub_config_unchanged || return
  current_binding="$(current_release_binding)" || {
    echo "The current release changed to an unsafe path while the installer was preparing." >&2
    return 1
  }
  if [[ "$RELEASE_ACTIVATED" == "true" ]]; then
    expected_current_binding="symlink:$RELEASE_DIR"
  fi
  if [[ "$current_binding" != "$expected_current_binding" ]]; then
    echo "The current release changed while the installer was preparing." >&2
    return 1
  fi
  if [[ ! -d "$TEAM_HUB_DATA_DIR" || -L "$TEAM_HUB_DATA_DIR" || ! -d "$TEAM_HUB_SNAPSHOT" || -L "$TEAM_HUB_SNAPSHOT" ]]; then
    echo "Managed Team Hub data or snapshot directory changed or became unsafe." >&2
    return 1
  fi
  for candidate in manifest.json team-hub.sqlite3 access-token-signing.key; do
    if [[ ! -f "$TEAM_HUB_SNAPSHOT/$candidate" || -L "$TEAM_HUB_SNAPSHOT/$candidate" ]]; then
      echo "Managed Team Hub snapshot changed or has an unsafe $candidate file." >&2
      return 1
    fi
  done
  if ! verify_team_hub_operation_fence "$runtime_root"; then
    echo "Managed Team Hub installer no longer owns the exact live maintenance fence." >&2
    return 1
  fi
  if ! verify_team_hub_rollback_snapshot "$runtime_root"; then
    echo "Managed Team Hub rollback snapshot no longer passes full read-only verification." >&2
    return 1
  fi
}

validate_team_hub_reactivation_inputs() {
  local runtime_root="$1"
  local current_binding=""
  local expected_current_binding=""
  local candidate=""
  [[ "$TEAM_HUB_REACTIVATION_REQUESTED" == "true" \
    || "$TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED" == "true" ]] || return 0
  expected_current_binding="$INITIAL_CURRENT_LINK_BINDING"
  assert_team_hub_config_unchanged || return
  current_binding="$(current_release_binding)" || {
    echo "The current release changed to an unsafe path while Team Hub reactivation was preparing." >&2
    return 1
  }
  if [[ "$RELEASE_ACTIVATED" == "true" ]]; then
    expected_current_binding="symlink:$RELEASE_DIR"
  fi
  if [[ "$current_binding" != "$expected_current_binding" ]]; then
    echo "The current release changed while Team Hub reactivation was preparing." >&2
    return 1
  fi
  if [[ ! -d "$TEAM_HUB_CANONICAL_DATA_DIR" \
    || -L "$TEAM_HUB_CANONICAL_DATA_DIR" \
    || ! -d "$TEAM_HUB_REACTIVATION_SNAPSHOT" \
    || -L "$TEAM_HUB_REACTIVATION_SNAPSHOT" ]]; then
    echo "Team Hub reactivation data or snapshot changed or became unsafe." >&2
    return 1
  fi
  for candidate in manifest.json team-hub.sqlite3 access-token-signing.key; do
    if [[ ! -f "$TEAM_HUB_REACTIVATION_SNAPSHOT/$candidate" \
      || -L "$TEAM_HUB_REACTIVATION_SNAPSHOT/$candidate" ]]; then
      echo "Team Hub reactivation snapshot changed or has an unsafe $candidate file." >&2
      return 1
    fi
  done
  if ! verify_team_hub_reactivation_snapshot "$runtime_root"; then
    echo "Team Hub reactivation snapshot no longer passes exact read-only verification." >&2
    return 1
  fi
  if ! run_without_server_secrets env PYTHONPATH="$runtime_root" \
    "$runtime_root/.venv/bin/python" -m agentsdock_team_hub.cli \
    verify-server-identity \
    --server-state-dir "$STATE_ROOT" \
    --expected-identity "$EXPECTED_SERVER_IDENTITY" >/dev/null; then
    echo "AgentsServer identity changed while Team Hub reactivation was preparing." >&2
    return 1
  fi
}

if [[ "$TEAM_HUB_OPERATION_PENDING" == "true" ]]; then
  INITIAL_CURRENT_LINK_BINDING="$(current_release_binding)" || {
    echo "Managed Team Hub update requires a safe current release path." >&2
    exit 1
  }
  TEAM_HUB_SNAPSHOT_PARENT="${TEAM_HUB_SNAPSHOT%/*}"
  TEAM_HUB_SNAPSHOT_NAME="${TEAM_HUB_SNAPSHOT##*/}"
  if [[ "$TEAM_HUB_SNAPSHOT_PARENT" != "$TEAM_HUB_DATA_DIR/maintenance-backups" || ! "$TEAM_HUB_SNAPSHOT_NAME" =~ ^snapshot_[A-Za-z0-9_]+$ ]]; then
    echo "Managed Team Hub snapshot is not an exact maintenance generation." >&2
    exit 2
  fi
  if [[ ! -d "$TEAM_HUB_DATA_DIR" || -L "$TEAM_HUB_DATA_DIR" || ! -d "$TEAM_HUB_SNAPSHOT" || -L "$TEAM_HUB_SNAPSHOT" ]]; then
    echo "Managed Team Hub data or snapshot directory is unavailable or unsafe." >&2
    exit 1
  fi
  for candidate in manifest.json team-hub.sqlite3 access-token-signing.key; do
    if [[ ! -f "$TEAM_HUB_SNAPSHOT/$candidate" || -L "$TEAM_HUB_SNAPSHOT/$candidate" ]]; then
      echo "Managed Team Hub snapshot is missing a safe $candidate file." >&2
      exit 1
    fi
  done
  if ! verify_team_hub_operation_fence "$CURRENT_LINK"; then
    echo "Managed Team Hub installer takeover does not own the exact live maintenance fence." >&2
    exit 1
  fi
  if ! verify_team_hub_rollback_snapshot "$CURRENT_LINK"; then
    echo "Managed Team Hub rollback snapshot failed full read-only verification before candidate activation." >&2
    exit 1
  fi
elif [[ "$TEAM_HUB_REACTIVATION_REQUESTED" == "true" \
  || "$TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED" == "true" ]]; then
  INITIAL_CURRENT_LINK_BINDING="$(current_release_binding)" || {
    echo "Team Hub reactivation requires a safe current release path." >&2
    exit 1
  }
fi

PREFLIGHT_FAILED="false"
MISSING_PREREQUISITE_NAMES=()
MISSING_PREREQUISITE_GUIDANCE=()
record_prerequisite_failure() {
  local prerequisite_name="$1"
  local guidance="$2"
  PREFLIGHT_FAILED="true"
  MISSING_PREREQUISITE_NAMES+=("$prerequisite_name")
  MISSING_PREREQUISITE_GUIDANCE+=("$guidance")
  echo "Unavailable prerequisite: $prerequisite_name" >&2
  echo "  $guidance" >&2
}

require_command() {
  local command_name="$1"
  local guidance="$2"
  command -v "$command_name" >/dev/null 2>&1 || record_prerequisite_failure "$command_name" "$guidance"
}

require_uv_runtime() {
  local guidance="$1"
  if command -v uv >/dev/null 2>&1 && uv --version >/dev/null 2>&1; then
    return 0
  fi
  record_prerequisite_failure "uv" "$guidance"
}

probe_service_manager() {
  local output=""
  if [[ "$OS_NAME" == "Darwin" ]] && command -v launchctl >/dev/null 2>&1; then
    if ! output="$(launchctl print "gui/$UID" 2>&1)"; then
      [[ -z "$output" ]] || echo "  launchctl: ${output//$'\n'/ }" >&2
      record_prerequisite_failure \
        "macOS launchd user domain gui/$UID" \
        "Log into a macOS GUI user session and verify: launchctl print gui/$UID"
    fi
  elif [[ "$OS_NAME" == "Linux" ]] && command -v systemctl >/dev/null 2>&1; then
    if ! output="$(systemctl --user show-environment 2>&1)"; then
      [[ -z "$output" ]] || echo "  systemctl: ${output//$'\n'/ }" >&2
      record_prerequisite_failure \
        "systemctl --user session" \
        "Log into a systemd user session and verify: systemctl --user show-environment"
    fi
  fi
}

cgroup_path_is_within() {
  local path="/${1#/}"
  local ancestor="/${2#/}"
  [[ "$path" == "$ancestor" || "$path" == "$ancestor/"* ]]
}

verify_managed_update_runner_isolated() {
  [[ -n "$MANAGED_UPDATE_ID" && "$OS_NAME" == "Linux" ]] || return 0
  if [[ -z "$EXPECTED_SERVICE_CGROUP" ]]; then
    record_prerequisite_failure \
      "managed updater service-cgroup proof" \
      "Retry from AgentsDock; the authenticated updater did not bind this install to the exact AgentsServer service cgroup."
    return
  fi
  if [[ ! -r /proc/self/cgroup ]]; then
    record_prerequisite_failure \
      "managed updater service-cgroup proof" \
      "Retry after checking the host's /proc and systemd user session."
    return
  fi
  local hierarchy=""
  local controllers=""
  local path=""
  local inspected="false"
  while IFS=: read -r hierarchy controllers path; do
    [[ -n "$path" ]] || continue
    inspected="true"
    if cgroup_path_is_within "$path" "$EXPECTED_SERVICE_CGROUP"; then
      record_prerequisite_failure \
        "managed updater isolation" \
        "Retry after AgentsServer creates its detached updater outside agents-server.service."
      return
    fi
  done < /proc/self/cgroup
  if [[ "$inspected" != "true" ]]; then
    record_prerequisite_failure \
      "managed updater service-cgroup proof" \
      "Retry after checking the host's /proc and systemd user session."
  fi
}

TMUX_WARNING=""

tmux_working() {
  command -v tmux >/dev/null 2>&1 && tmux -V >/dev/null 2>&1
}

offer_brew_tmux_install() {
  # Only ever offered on macOS with Homebrew present; never attempted over a
  # non-interactive/SSH-driven run, where there is no one to answer a prompt.
  [[ "$NON_INTERACTIVE" != "true" && -t 0 ]] || return 1
  command -v brew >/dev/null 2>&1 || return 1
  local reply=""
  read -r -p "      tmux was not found. Install it now with Homebrew (brew install tmux)? [y/N] " reply || return 1
  case "$reply" in
    y|Y|yes|YES) ;;
    *) return 1 ;;
  esac
  echo "      Installing tmux with Homebrew"
  brew install tmux
}

check_tmux_prerequisite() {
  # tmux is optional: it only backs the persistent chat terminal, tmux-pane
  # inspection, and in-app managed updates. The rest of AgentsServer (chats,
  # turns, jobs, files) runs without it, so a missing tmux is a warning, not
  # a preflight failure.
  local guidance=""
  tmux_working && return 0
  if [[ "$OS_NAME" == "Darwin" ]]; then
    if offer_brew_tmux_install && tmux_working; then
      return 0
    fi
    guidance="Install tmux with Homebrew: brew install tmux"
  else
    guidance="Install tmux with your package manager, for example: sudo apt install tmux, sudo dnf install tmux, or sudo pacman -S tmux."
  fi
  TMUX_WARNING="tmux is unavailable, so the persistent chat terminal, tmux-pane inspection, and in-app managed updates will not work. $guidance Then rerun install.sh to enable them; everything else about AgentsServer works without it."
  echo "Optional prerequisite unavailable: tmux" >&2
  echo "  $TMUX_WARNING" >&2
}

check_darwin_architecture() {
  local architecture=""
  architecture="$(uname -m 2>/dev/null || true)"
  if [[ "$architecture" == "arm64" ]]; then
    return 0
  fi
  echo "Unsupported macOS architecture: ${architecture:-unknown}." >&2
  echo "AgentsServer requires a native Apple silicon (arm64) macOS environment because patched cryptography releases no longer support Intel macOS. Use Apple silicon or Linux; no state, release, configuration, or service changes were made." >&2
  return 1
}

preflight_prerequisites() {
  case "$OS_NAME" in
    Darwin)
      check_darwin_architecture || return 1
      require_uv_runtime "Install the trusted uv package manager before running this installer: brew install uv."
      require_command "launchctl" "launchctl is included with macOS; run this installer from a supported macOS user session."
      ;;
    Linux)
      require_uv_runtime "Install the trusted uv package manager from your OS/package-management environment, then rerun install.sh."
      require_command "systemctl" "AgentsServer's Linux installer requires systemd and a working systemctl --user session."
      ;;
    *)
      echo "Unsupported host OS: $OS_NAME" >&2
      PREFLIGHT_FAILED="true"
      ;;
  esac
  case "$OS_NAME" in
    Darwin|Linux) check_tmux_prerequisite ;;
  esac
  probe_service_manager
  verify_managed_update_runner_isolated
  if [[ "$PREFLIGHT_FAILED" == "true" ]]; then
    local names=""
    local actions=""
    local index
    for ((index = 0; index < ${#MISSING_PREREQUISITE_NAMES[@]}; index++)); do
      [[ -z "$names" ]] || names+=", "
      names+="${MISSING_PREREQUISITE_NAMES[$index]}"
      [[ -z "$actions" ]] || actions+=" "
      actions+="${MISSING_PREREQUISITE_GUIDANCE[$index]}"
    done
    if [[ -n "$names" ]]; then
      echo "Missing prerequisites: $names. $actions Then run install.sh again; no state, release, configuration, or service changes were made." >&2
    else
      echo "Prerequisite check failed for unsupported host OS $OS_NAME; no state, release, configuration, or service changes were made." >&2
    fi
    return 1
  fi
}

# This deliberately runs before the cleanup trap, directory creation, state
# migration, release staging, or service changes.
preflight_prerequisites || exit 1
UV_BIN="$(command -v uv)" || exit 1
[[ "$UV_BIN" == /* && -x "$UV_BIN" ]] || {
  echo "The trusted uv executable must resolve to an absolute executable path." >&2
  exit 1
}

ACTIVE_STAGE_PID=""
ACTIVE_STAGE_PGID=""
INSTALL_LOCK_DIR="$INSTALL_ROOT/.install-lock"
INSTALL_LOCK_HELD="false"
INSTALL_LOCK_DEVICE=""
INSTALL_LOCK_INODE=""
PREVIOUS_LINK_WAS_SYMLINK="false"
PREVIOUS_LINK_TARGET=""
PREVIOUS_LINK_STATE_CAPTURED="false"
CURRENT_LINK_STATE_CAPTURED="false"
CURRENT_LINK_WAS_SYMLINK="false"
CURRENT_LINK_WAS_DIRECTORY="false"
CURRENT_LINK_TARGET=""

validate_install_layout_paths() {
  local candidate=""
  local candidate_mode=""
  for candidate in "$INSTALL_ROOT" "$RELEASES_ROOT"; do
    if [[ -L "$candidate" \
      || ( -e "$candidate" && ! -d "$candidate" ) \
      || ( -d "$candidate" && ! -O "$candidate" ) ]]; then
      echo "The AgentsServer install layout contains an unsafe directory: $candidate" >&2
      return 1
    fi
    [[ -d "$candidate" ]] || continue
    candidate_mode="$(stat -c '%a' "$candidate" 2>/dev/null \
      || stat -f '%Lp' "$candidate" 2>/dev/null)" || return 1
    if [[ ! "$candidate_mode" =~ ^[0-7]{3,4}$ \
      || $((8#$candidate_mode & 8#022)) -ne 0 ]]; then
      echo "The AgentsServer install layout is group/world writable: $candidate" >&2
      return 1
    fi
  done
}

systemd_unit_snapshot() {
  local unit="$1"
  local config_exists="$2"
  local load_state=""
  local active_state=""
  local enabled_state=""
  local enabled_status=0
  load_state="$(systemctl --user show "$unit" \
    --property=LoadState --value 2>/dev/null)" || return 1
  active_state="$(systemctl --user show "$unit" \
    --property=ActiveState --value 2>/dev/null)" || return 1
  [[ "$load_state" != *$'\n'* && "$active_state" != *$'\n'* ]] || return 1
  case "$load_state" in
    loaded|not-found) ;;
    *) return 1 ;;
  esac
  case "$active_state" in
    active) active_state="running" ;;
    inactive|failed) active_state="stopped" ;;
    *) return 1 ;;
  esac
  if enabled_state="$(systemctl --user is-enabled "$unit" 2>/dev/null)"; then
    enabled_status=0
  else
    enabled_status=$?
  fi
  [[ "$enabled_state" != *$'\n'* ]] || return 1
  case "$enabled_status:$enabled_state" in
    0:enabled|0:enabled-runtime) enabled_state="true" ;;
    1:disabled) enabled_state="false" ;;
    1:not-found|4:not-found)
      [[ "$load_state" == "not-found" && "$config_exists" != "true" ]] \
        || return 1
      enabled_state="false"
      ;;
    *) return 1 ;;
  esac
  if [[ "$config_exists" != "true" && ( \
      "$load_state" != "not-found" \
      || "$active_state" != "stopped" \
      || "$enabled_state" != "false" ) ]]; then
    return 1
  fi
  if [[ "$config_exists" != "true" ]]; then
    active_state="absent"
  fi
  printf '%s|%s|%s\n' "$active_state" "$enabled_state" "$load_state"
}

backup_runtime_configuration() {
  local activation_intent="ordinary"
  if [[ "$TEAM_HUB_OPERATION_PENDING" == "true" ]]; then
    activation_intent="server-update"
  elif [[ "$TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED" == "true" ]]; then
    activation_intent="failed-host-repair"
  elif [[ "$TEAM_HUB_REACTIVATION_REQUESTED" == "true" ]]; then
    activation_intent="host-reactivation"
  fi
  ACTIVATION_INTENT="$activation_intent"
  local captured_value=""
  local prior_network_config=""
  if [[ -f "$ENV_FILE" && ! -L "$ENV_FILE" ]]; then
    prior_network_config="$ENV_FILE"
  elif [[ -n "$LEGACY_ENV_FILE" \
    && -f "$LEGACY_ENV_FILE" \
    && ! -L "$LEGACY_ENV_FILE" ]]; then
    prior_network_config="$LEGACY_ENV_FILE"
  fi
  if [[ -n "$prior_network_config" ]]; then
    captured_value="$(read_env_value \
      "$prior_network_config" AGENTSDOCK_AGENT_PORT)" || return 1
    [[ -n "$captured_value" ]] || captured_value="$(read_env_value \
      "$prior_network_config" ZENITHBOT_AGENT_PORT)" || return 1
    [[ -n "$captured_value" ]] || captured_value="$(read_env_value \
      "$prior_network_config" ZENITHDOCK_AGENT_PORT)" || return 1
    if [[ -n "$captured_value" ]]; then
      [[ "$captured_value" =~ ^[0-9]+$ \
        && "$captured_value" -ge 1 \
        && "$captured_value" -le 65535 ]] || return 1
      PRIOR_PORT="$captured_value"
    fi
    captured_value="$(read_env_value \
      "$prior_network_config" AGENTSDOCK_AGENT_BIND)" || return 1
    [[ -n "$captured_value" ]] || captured_value="$(read_env_value \
      "$prior_network_config" ZENITHBOT_AGENT_BIND)" || return 1
    [[ -n "$captured_value" ]] || captured_value="$(read_env_value \
      "$prior_network_config" ZENITHDOCK_AGENT_BIND)" || return 1
    if [[ -n "$captured_value" ]]; then
      validate_bind_address "$captured_value" "$STAGE_DIR/.venv/bin/python" \
        || return 1
      PRIOR_BIND_ADDRESS="$captured_value"
    fi
  fi
  if [[ -f "$ENV_FILE" && ! -L "$ENV_FILE" ]]; then
    ENV_CONFIG_EXISTED="true"
  elif [[ -e "$ENV_FILE" || -L "$ENV_FILE" ]]; then
    echo "$ENV_FILE is not a regular configuration file." >&2
    return 1
  fi
  ENV_CONFIG_CAPTURED="true"

  local service_file="$SYSTEMD_SERVICE_FILE"
  [[ "$OS_NAME" != "Darwin" ]] || service_file="$PLIST"
  if [[ -f "$service_file" && ! -L "$service_file" ]]; then
    SERVICE_CONFIG_EXISTED="true"
  elif [[ -e "$service_file" || -L "$service_file" ]]; then
    echo "$service_file is not a regular service configuration file." >&2
    return 1
  fi
  SERVICE_CONFIG_CAPTURED="true"
  if [[ "$OS_NAME" == "Darwin" ]]; then
    local launchd_state=""
    launchd_state="$(launchd_target_snapshot "gui/$(id -u)/$LABEL")" \
      || return 1
    if [[ "$SERVICE_CONFIG_EXISTED" != "true" ]]; then
      [[ "$launchd_state" == "not-found" ]] || {
        echo "The loaded AgentsServer service has no safely restorable plist." >&2
        return 1
      }
      PRIOR_SERVICE_STATE="absent"
    elif [[ "$launchd_state" == "loaded" ]]; then
      PRIOR_SERVICE_STATE="running"
    elif [[ "$launchd_state" == "not-found" ]]; then
      PRIOR_SERVICE_STATE="stopped"
    else
      return 1
    fi
    local disabled_services=""
    disabled_services="$(launchctl print-disabled "gui/$(id -u)" 2>/dev/null)" \
      || return 1
    if printf '%s\n' "$disabled_services" \
      | grep -Eq "\"$LABEL\"[[:space:]]*=>[[:space:]]*true"; then
      PRIOR_SERVICE_ENABLED="false"
    else
      PRIOR_SERVICE_ENABLED="true"
    fi
  else
    local current_snapshot=""
    current_snapshot="$(systemd_unit_snapshot \
      "$SERVICE_NAME.service" "$SERVICE_CONFIG_EXISTED")" || {
      echo "The current AgentsServer service state could not be captured authoritatively." >&2
      return 1
    }
    PRIOR_SERVICE_STATE="${current_snapshot%%|*}"
    current_snapshot="${current_snapshot#*|}"
    PRIOR_SERVICE_ENABLED="${current_snapshot%%|*}"
  fi
  if [[ "$OS_NAME" == "Linux" ]]; then
    local legacy_exists="false"
    local legacy_snapshot=""
    if [[ -e "$LEGACY_SERVICE_FILE" || -L "$LEGACY_SERVICE_FILE" ]]; then
      if ! read_owned_config_file "$LEGACY_SERVICE_FILE" >/dev/null; then
        echo "$LEGACY_SERVICE_FILE cannot be captured safely for rollback." >&2
        return 1
      fi
      legacy_exists="true"
    fi
    legacy_snapshot="$(systemd_unit_snapshot \
      "$LEGACY_SERVICE_NAME.service" "$legacy_exists")" || {
      echo "The legacy service state could not be captured authoritatively." >&2
      return 1
    }
    PRIOR_LEGACY_SERVICE_STATE="${legacy_snapshot%%|*}"
    legacy_snapshot="${legacy_snapshot#*|}"
    PRIOR_LEGACY_SERVICE_ENABLED="${legacy_snapshot%%|*}"
    if [[ "$legacy_exists" != "true" \
      && "$PRIOR_LEGACY_SERVICE_STATE" != "absent" ]]; then
      echo "The loaded legacy service has no safely restorable unit file." >&2
      return 1
    fi
  fi

  if [[ -L "$CURRENT_LINK" ]]; then
    CURRENT_LINK_WAS_SYMLINK="true"
    CURRENT_LINK_TARGET="$(readlink "$CURRENT_LINK")"
  elif [[ -d "$CURRENT_LINK" ]]; then
    CURRENT_LINK_WAS_DIRECTORY="true"
  elif [[ -e "$CURRENT_LINK" ]]; then
    echo "$CURRENT_LINK is not a supported release link or directory." >&2
    return 1
  fi
  CURRENT_LINK_STATE_CAPTURED="true"

  if [[ -L "$PREVIOUS_LINK" ]]; then
    PREVIOUS_LINK_WAS_SYMLINK="true"
    PREVIOUS_LINK_TARGET="$(readlink "$PREVIOUS_LINK")"
  elif [[ -e "$PREVIOUS_LINK" ]]; then
    echo "$PREVIOUS_LINK is not a symbolic link." >&2
    return 1
  fi
  PREVIOUS_LINK_STATE_CAPTURED="true"

  ACTIVATION_TRANSACTION_ID="$(
    run_without_server_secrets env PYTHONPATH="$STAGE_DIR" \
      "$STAGE_DIR/.venv/bin/python" -m activation_transaction begin \
      --root "$INSTALL_ROOT" \
      --current "$CURRENT_LINK" \
      --previous "$PREVIOUS_LINK" \
      --env "$ENV_FILE" \
      --service "$service_file" \
      --release-dir "$RELEASE_DIR" \
      --release-version "$RELEASE_VERSION" \
      --old-source "$ORIGINAL_OLD_SOURCE" \
      --old-target "$OLD_TARGET" \
      --candidate-source "$STAGE_DIR" \
      --service-state "$PRIOR_SERVICE_STATE" \
      --service-enabled "$PRIOR_SERVICE_ENABLED" \
      --legacy-service-state "$PRIOR_LEGACY_SERVICE_STATE" \
      --legacy-service-enabled "$PRIOR_LEGACY_SERVICE_ENABLED" \
      --prior-port "$PRIOR_PORT" \
      --prior-bind-address "$PRIOR_BIND_ADDRESS" \
      --intent "$activation_intent" \
      --client-binding "$EXPECTED_TEAM_HUB_CLIENT_BINDING"
  )" || return
  if [[ ! "$ACTIVATION_TRANSACTION_ID" =~ ^activation-[0-9a-f]{24}$ \
    || "$ACTIVATION_TRANSACTION_ID" == *$'\n'* ]]; then
    echo "Activation transaction returned an invalid identity." >&2
    return 1
  fi
  ACTIVATION_TRANSACTION_PHASE="prepared"
  ACTIVATION_ROLLBACK_FROM=""
  ENV_CONFIG_BACKUP="$ACTIVATION_TRANSACTION_DIR/env.backup"
  SERVICE_CONFIG_BACKUP="$ACTIVATION_TRANSACTION_DIR/service.backup"
}

activation_service_config_path() {
  if [[ "$OS_NAME" == "Darwin" ]]; then
    printf '%s\n' "$PLIST"
  else
    printf '%s\n' "$SYSTEMD_SERVICE_FILE"
  fi
}

activation_transaction_command() {
  local preferred_root="$1"
  shift
  local runtime_root=""
  local candidate=""
  for candidate in \
    "$ACTIVATION_TRANSACTION_DIR/candidate.retired" \
    "$preferred_root" \
    "$STAGE_DIR" \
    "$RELEASE_DIR" \
    "$SOURCE_DIR"; do
    [[ -n "$candidate" ]] || continue
    if [[ -f "$candidate/activation_transaction.py" \
      && -x "$candidate/.venv/bin/python" ]]; then
      runtime_root="$candidate"
      break
    fi
  done
  [[ -n "$runtime_root" ]] || return 1
  run_without_server_secrets env PYTHONPATH="$runtime_root" \
    "$runtime_root/.venv/bin/python" -m activation_transaction "$@"
}

record_activation_phase() {
  local phase="$1"
  local runtime_root="${2:-$CANDIDATE_RUNTIME_ROOT}"
  local previous_phase="$ACTIVATION_TRANSACTION_PHASE"
  [[ -n "$ACTIVATION_TRANSACTION_ID" ]] || return 0
  local service_file=""
  local hub_kind=""
  local hub_data_dir=""
  local hub_id=""
  local operation_id=""
  local snapshot=""
  local fence_device="0"
  local fence_inode="0"
  local result=""
  service_file="$(activation_service_config_path)"
  if [[ "$phase" != "rolled-back" && "$phase" != "rollback-healthy" \
    && "$TEAM_HUB_REACTIVATION_FENCE_PENDING" == "true" ]]; then
    hub_kind="host-reactivation"
    hub_data_dir="$TEAM_HUB_CANONICAL_DATA_DIR"
    hub_id="$TEAM_HUB_REACTIVATION_HUB_ID"
    operation_id="$TEAM_HUB_REACTIVATION_OPERATION_ID"
    snapshot="$TEAM_HUB_REACTIVATION_SNAPSHOT"
    fence_device="$TEAM_HUB_REACTIVATION_FENCE_DEVICE"
    fence_inode="$TEAM_HUB_REACTIVATION_FENCE_INODE"
  elif [[ "$phase" != "rolled-back" && "$phase" != "rollback-healthy" \
    && "$TEAM_HUB_OPERATION_PENDING" == "true" ]]; then
    hub_kind="server-update"
    hub_data_dir="$TEAM_HUB_DATA_DIR"
    hub_id="$EXPECTED_TEAM_HUB_ID"
    operation_id="$TEAM_HUB_OPERATION_ID"
    snapshot="$TEAM_HUB_SNAPSHOT"
    fence_device="${TEAM_HUB_OPERATION_FENCE_DEVICE:-0}"
    fence_inode="${TEAM_HUB_OPERATION_FENCE_INODE:-0}"
  fi
  local arguments=(
    record
    --root "$INSTALL_ROOT"
    --current "$CURRENT_LINK"
    --previous "$PREVIOUS_LINK"
    --env "$ENV_FILE"
    --service "$service_file"
    --release-dir "$RELEASE_DIR"
    --release-version "$RELEASE_VERSION"
    --transaction-id "$ACTIVATION_TRANSACTION_ID"
    --phase "$phase"
    --authority-pending "$TEAM_HUB_STARTUP_AUTHORITY_PENDING"
  )
  if [[ -n "$hub_kind" ]]; then
    ACTIVATION_HUB_KIND="$hub_kind"
    arguments+=(
      --hub-kind "$hub_kind"
      --hub-data-dir "$hub_data_dir"
      --hub-id "$hub_id"
      --host-identity "$EXPECTED_SERVER_IDENTITY"
      --operation-id "$operation_id"
      --snapshot "$snapshot"
      --fence-device "$fence_device"
      --fence-inode "$fence_inode"
    )
  fi
  if [[ "$TEAM_HUB_COLD_GUARD_PENDING" == "true" ]]; then
    arguments+=(
      --guard-id "$TEAM_HUB_COLD_GUARD_ID"
      --guard-device "$TEAM_HUB_COLD_GUARD_DEVICE"
      --guard-inode "$TEAM_HUB_COLD_GUARD_INODE"
    )
  fi
  result="$(activation_transaction_command "$runtime_root" "${arguments[@]}")" \
    || return 1
  if [[ -n "$hub_kind" ]]; then
    local returned_device="${result%%$'\n'*}"
    local returned_inode="${result#*$'\n'}"
    if [[ "$result" != *$'\n'* \
      || ! "$returned_device" =~ ^[1-9][0-9]*$ \
      || ! "$returned_inode" =~ ^[1-9][0-9]*$ \
      || "$returned_inode" == *$'\n'* ]]; then
      echo "Activation transaction returned invalid Team Hub fence ownership." >&2
      return 1
    fi
    if [[ "$hub_kind" == "server-update" ]]; then
      TEAM_HUB_OPERATION_FENCE_DEVICE="$returned_device"
      TEAM_HUB_OPERATION_FENCE_INODE="$returned_inode"
    else
      TEAM_HUB_REACTIVATION_FENCE_DEVICE="$returned_device"
      TEAM_HUB_REACTIVATION_FENCE_INODE="$returned_inode"
    fi
  elif [[ -n "$result" ]]; then
    echo "Activation transaction returned unexpected output." >&2
    return 1
  fi
  ACTIVATION_TRANSACTION_PHASE="$phase"
  if [[ "$phase" == "rolling-back" && -z "$ACTIVATION_ROLLBACK_FROM" ]]; then
    ACTIVATION_ROLLBACK_FROM="$previous_phase"
  fi
}

replace_activation_config() {
  local kind="$1"
  local source="$2"
  local mode="$3"
  local runtime_root="${4:-$CANDIDATE_RUNTIME_ROOT}"
  [[ -n "$ACTIVATION_TRANSACTION_ID" ]] || return 1
  activation_transaction_command "$runtime_root" replace-config \
    --root "$INSTALL_ROOT" \
    --current "$CURRENT_LINK" \
    --previous "$PREVIOUS_LINK" \
    --env "$ENV_FILE" \
    --service "$(activation_service_config_path)" \
    --release-dir "$RELEASE_DIR" \
    --release-version "$RELEASE_VERSION" \
    --transaction-id "$ACTIVATION_TRANSACTION_ID" \
    --kind "$kind" \
    --source "$source" \
    --mode "$mode" >/dev/null
}

restore_activation_files() {
  local runtime_root="${1:-$CANDIDATE_RUNTIME_ROOT}"
  activation_transaction_command "$runtime_root" restore-files \
    --root "$INSTALL_ROOT" \
    --current "$CURRENT_LINK" \
    --previous "$PREVIOUS_LINK" \
    --env "$ENV_FILE" \
    --service "$(activation_service_config_path)" \
    --release-dir "$RELEASE_DIR" \
    --release-version "$RELEASE_VERSION" \
    --transaction-id "$ACTIVATION_TRANSACTION_ID" >/dev/null
}

activate_transaction_files() {
  local runtime_root="${1:-$CANDIDATE_RUNTIME_ROOT}"
  activation_transaction_command "$runtime_root" activate-files \
    --root "$INSTALL_ROOT" \
    --current "$CURRENT_LINK" \
    --previous "$PREVIOUS_LINK" \
    --env "$ENV_FILE" \
    --service "$(activation_service_config_path)" \
    --release-dir "$RELEASE_DIR" \
    --release-version "$RELEASE_VERSION" \
    --transaction-id "$ACTIVATION_TRANSACTION_ID" >/dev/null
}

finish_activation_transaction() {
  local runtime_root="${1:-$CANDIDATE_RUNTIME_ROOT}"
  [[ -n "$ACTIVATION_TRANSACTION_ID" ]] || return 0
  if activation_transaction_command "$runtime_root" finish \
      --root "$INSTALL_ROOT" \
      --current "$CURRENT_LINK" \
      --previous "$PREVIOUS_LINK" \
      --env "$ENV_FILE" \
      --service "$(activation_service_config_path)" \
      --release-dir "$RELEASE_DIR" \
      --release-version "$RELEASE_VERSION" \
      --transaction-id "$ACTIVATION_TRANSACTION_ID" >/dev/null; then
    ACTIVATION_TRANSACTION_ID=""
    ACTIVATION_TRANSACTION_PHASE=""
    ACTIVATION_ROLLBACK_FROM=""
    ACTIVATION_HUB_KIND=""
    return 0
  fi
  return 1
}

assert_env_backup_team_hub_config() {
  [[ "$ENV_CONFIG_EXISTED" == "true" ]] || return 0
  [[ -n "$ENV_CONFIG_BACKUP" && -f "$ENV_CONFIG_BACKUP" ]] || return 1
  local mismatch="false"
  local actual_set="false"
  actual_set="false"
  env_file_has_key "$ENV_CONFIG_BACKUP" AGENTSDOCK_TEAM_HUB_MODE && actual_set="true"
  if [[ "$actual_set" != "$EXISTING_ENV_TEAM_HUB_MODE_SET" ]] \
    || { [[ "$actual_set" == "true" ]] \
      && [[ "$(read_env_value "$ENV_CONFIG_BACKUP" AGENTSDOCK_TEAM_HUB_MODE)" != "$EXISTING_ENV_TEAM_HUB_MODE_VALUE" ]]; }; then
    mismatch="true"
  fi
  actual_set="false"
  env_file_has_key "$ENV_CONFIG_BACKUP" AGENTSDOCK_TEAM_HUB_TRANSPORT && actual_set="true"
  if [[ "$actual_set" != "$EXISTING_ENV_TEAM_HUB_TRANSPORT_SET" ]] \
    || { [[ "$actual_set" == "true" ]] \
      && [[ "$(read_env_value "$ENV_CONFIG_BACKUP" AGENTSDOCK_TEAM_HUB_TRANSPORT)" != "$EXISTING_ENV_TEAM_HUB_TRANSPORT_VALUE" ]]; }; then
    mismatch="true"
  fi
  actual_set="false"
  env_file_has_key "$ENV_CONFIG_BACKUP" AGENTSDOCK_TEAM_HUB_URL && actual_set="true"
  if [[ "$actual_set" != "$EXISTING_ENV_TEAM_HUB_URL_SET" ]] \
    || { [[ "$actual_set" == "true" ]] \
      && [[ "$(read_env_value "$ENV_CONFIG_BACKUP" AGENTSDOCK_TEAM_HUB_URL)" != "$EXISTING_ENV_TEAM_HUB_URL_VALUE" ]]; }; then
    mismatch="true"
  fi
  actual_set="false"
  env_file_has_key "$ENV_CONFIG_BACKUP" AGENTSDOCK_TEAM_HUB_DIRECT_IP_URL && actual_set="true"
  if [[ "$actual_set" != "$EXISTING_ENV_TEAM_HUB_DIRECT_IP_URL_SET" ]] \
    || { [[ "$actual_set" == "true" ]] \
      && [[ "$(read_env_value "$ENV_CONFIG_BACKUP" AGENTSDOCK_TEAM_HUB_DIRECT_IP_URL)" != "$EXISTING_ENV_TEAM_HUB_DIRECT_IP_URL_VALUE" ]]; }; then
    mismatch="true"
  fi
  if [[ "$mismatch" == "true" ]]; then
    echo "The captured rollback configuration does not match the verified Team Hub configuration." >&2
    return 1
  fi
}

restore_regular_configuration() {
  local target="$1"
  local backup="$2"
  local existed="$3"
  if [[ "$existed" == "true" ]]; then
    [[ -n "$backup" && -f "$backup" ]] || return 1
    cp -p "$backup" "$target"
  else
    if [[ -d "$target" && ! -L "$target" ]]; then
      echo "Refusing to replace unexpected configuration directory $target." >&2
      return 1
    fi
    if [[ -e "$target" || -L "$target" ]]; then
      rm -f "$target"
    fi
  fi
}

restore_runtime_configuration() {
  [[ "$ENV_CONFIG_CAPTURED" != "true" ]] || \
    restore_regular_configuration "$ENV_FILE" "$ENV_CONFIG_BACKUP" "$ENV_CONFIG_EXISTED" || return
  local service_file="$SYSTEMD_SERVICE_FILE"
  [[ "$OS_NAME" != "Darwin" ]] || service_file="$PLIST"
  [[ "$SERVICE_CONFIG_CAPTURED" != "true" ]] || \
    restore_regular_configuration "$service_file" "$SERVICE_CONFIG_BACKUP" "$SERVICE_CONFIG_EXISTED" || return
}

restore_release_links() {
  [[ "$CURRENT_LINK_STATE_CAPTURED" == "true" ]] || return 0
  if [[ "$CURRENT_LINK_WAS_DIRECTORY" == "true" ]]; then
    if [[ -n "$OLD_TARGET" && -d "$OLD_TARGET" ]]; then
      if [[ -e "$CURRENT_LINK" && ! -L "$CURRENT_LINK" ]]; then
        echo "Refusing to replace unexpected current release path $CURRENT_LINK." >&2
        return 1
      fi
      ln -sfn "$OLD_TARGET" "$CURRENT_LINK" || return
    elif [[ ! -d "$CURRENT_LINK" || -L "$CURRENT_LINK" ]]; then
      echo "The original current release directory cannot be recovered." >&2
      return 1
    fi
  elif [[ "$CURRENT_LINK_WAS_SYMLINK" == "true" ]]; then
    if [[ -n "$OLD_TARGET" && -e "$OLD_TARGET" ]]; then
      ln -sfn "$OLD_TARGET" "$CURRENT_LINK" || return
    elif [[ -L "$CURRENT_LINK" && "$(readlink "$CURRENT_LINK")" == "$CURRENT_LINK_TARGET" ]]; then
      :
    else
      echo "The original current release link cannot be recovered." >&2
      return 1
    fi
  elif [[ -L "$CURRENT_LINK" ]]; then
    rm -f "$CURRENT_LINK" || return
  elif [[ -e "$CURRENT_LINK" ]]; then
    echo "Refusing to replace unexpected current release path $CURRENT_LINK." >&2
    return 1
  fi

  if [[ "$PREVIOUS_LINK_STATE_CAPTURED" == "true" ]]; then
    if [[ "$PREVIOUS_LINK_WAS_SYMLINK" == "true" ]]; then
      ln -sfn "$PREVIOUS_LINK_TARGET" "$PREVIOUS_LINK" || return
    elif [[ -L "$PREVIOUS_LINK" ]]; then
      rm -f "$PREVIOUS_LINK" || return
    elif [[ -e "$PREVIOUS_LINK" ]]; then
      echo "Refusing to replace unexpected previous release path $PREVIOUS_LINK." >&2
      return 1
    fi
  fi
}

restore_pre_candidate_changes() {
  restore_release_links || return
  restore_runtime_configuration || return
}

signal_active_stage() {
  local signal_name="$1"
  if [[ -n "$ACTIVE_STAGE_PGID" ]] && kill "-$signal_name" -- "-$ACTIVE_STAGE_PGID" >/dev/null 2>&1; then
    return 0
  fi
  [[ -z "$ACTIVE_STAGE_PID" ]] || kill "-$signal_name" "$ACTIVE_STAGE_PID" >/dev/null 2>&1 || true
}

stop_active_stage() {
  [[ -n "$ACTIVE_STAGE_PID" ]] || return 0
  signal_active_stage TERM
  local attempt
  for attempt in $(seq 1 20); do
    kill -0 "$ACTIVE_STAGE_PID" >/dev/null 2>&1 || break
    sleep 0.05
  done
  if kill -0 "$ACTIVE_STAGE_PID" >/dev/null 2>&1; then
    signal_active_stage KILL
  fi
  wait "$ACTIVE_STAGE_PID" 2>/dev/null || true
  ACTIVE_STAGE_PID=""
  ACTIVE_STAGE_PGID=""
}

install_lock_python() {
  local candidate=""
  local probe=""
  for candidate in \
    "$STAGE_DIR/.venv/bin/python" \
    "$RELEASE_DIR/.venv/bin/python" \
    "$CURRENT_LINK/.venv/bin/python" \
    "$ACTIVATION_TRANSACTION_DIR/candidate.retired/.venv/bin/python" \
    "$(command -v python3 2>/dev/null || true)" \
    "/usr/bin/python3"; do
    [[ -n "$candidate" && -x "$candidate" ]] || continue
    probe="$("$candidate" -c 'print("agentsdock-install-lock-v1")' 2>/dev/null || true)"
    [[ "$probe" == "agentsdock-install-lock-v1" ]] || continue
    printf '%s\n' "$candidate"
    return 0
  done
  return 1
}

install_lock_control() {
  local action="$1"
  local expected_device="${2:-0}"
  local expected_inode="${3:-0}"
  local python_path=""
  python_path="$(install_lock_python)" || return 1
  "$python_path" - \
    "$action" "$INSTALL_ROOT" "$$" "$expected_device" "$expected_inode" <<'PY'
import errno
import os
from pathlib import Path
import secrets
import stat
import sys

action, raw_root, raw_pid, raw_device, raw_inode = sys.argv[1:]
root = Path(os.path.abspath(raw_root))
pid = int(raw_pid)
lock = root / ".install-lock"

root_info = root.lstat()
if (
    not stat.S_ISDIR(root_info.st_mode)
    or root_info.st_uid != os.geteuid()
    or stat.S_IMODE(root_info.st_mode) & 0o022
):
    raise PermissionError("AgentsServer install root is unsafe")
releases = root / "releases"
try:
    releases_info = releases.lstat()
except FileNotFoundError:
    pass
else:
    if (
        not stat.S_ISDIR(releases_info.st_mode)
        or releases_info.st_uid != os.geteuid()
        or stat.S_IMODE(releases_info.st_mode) & 0o022
    ):
        raise PermissionError("AgentsServer releases root is unsafe")


def fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def open_lock_directory() -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(lock, flags)
    info = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        os.close(descriptor)
        raise PermissionError("AgentsServer install lock directory is unsafe")
    return descriptor, info


def read_owner(directory_descriptor: int) -> tuple[int, tuple[int, int]]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open("pid", flags, dir_fd=directory_descriptor)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) not in {0o600, 0o644}
            or not 1 <= info.st_size <= 32
        ):
            raise PermissionError("AgentsServer install lock owner is unsafe")
        raw = os.read(descriptor, 33)
        if len(raw) > 32 or os.read(descriptor, 1):
            raise RuntimeError("AgentsServer install lock owner is invalid")
    finally:
        os.close(descriptor)
    try:
        value = raw.decode("ascii").strip()
    except UnicodeError as exc:
        raise RuntimeError("AgentsServer install lock owner is invalid") from exc
    if not value.isdigit() or int(value) <= 1:
        raise RuntimeError("AgentsServer install lock owner is invalid")
    return int(value), (int(info.st_dev), int(info.st_ino))


if action == "acquire":
    candidate = root / f".install-lock.{pid}.{secrets.token_hex(12)}.tmp"
    os.mkdir(candidate, 0o700)
    os.chmod(candidate, 0o700)
    candidate_info = candidate.lstat()
    owned = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(candidate / "pid", flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            payload = f"{pid}\n".encode("ascii")
            offset = 0
            while offset < len(payload):
                offset += os.write(descriptor, payload[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        fsync_directory(candidate)
        for _attempt in range(32):
            try:
                os.rename(candidate, lock)
            except OSError as exc:
                if exc.errno not in {errno.EEXIST, errno.ENOTEMPTY}:
                    raise
                directory_descriptor, directory_info = open_lock_directory()
                try:
                    try:
                        owner_pid, owner_identity = read_owner(directory_descriptor)
                    except FileNotFoundError:
                        # An old installer may have crashed in mkdir->pid. The
                        # next atomic directory rename replaces only that
                        # exact empty namespace; a populated replacement wins.
                        continue
                    try:
                        os.kill(owner_pid, 0)
                    except ProcessLookupError:
                        pass
                    except PermissionError:
                        raise RuntimeError(
                            f"another AgentsServer installation is active ({owner_pid})"
                        )
                    else:
                        raise RuntimeError(
                            f"another AgentsServer installation is active ({owner_pid})"
                        )
                    # unlinkat is relative to the pinned old directory. If a
                    # competing reaper has already replaced the lock path,
                    # this can never remove the new owner's pid.
                    try:
                        current_owner, current_identity = read_owner(
                            directory_descriptor
                        )
                    except FileNotFoundError:
                        continue
                    if current_owner != owner_pid or current_identity != owner_identity:
                        continue
                    try:
                        os.unlink("pid", dir_fd=directory_descriptor)
                    except FileNotFoundError:
                        continue
                    os.fsync(directory_descriptor)
                finally:
                    os.close(directory_descriptor)
                continue
            else:
                owned = True
                for _ in range(3):
                    try:
                        fsync_directory(root)
                        break
                    except OSError:
                        continue
                else:
                    raise RuntimeError("AgentsServer install lock was not durable")
                published = lock.lstat()
                if (
                    published.st_dev != candidate_info.st_dev
                    or published.st_ino != candidate_info.st_ino
                ):
                    raise RuntimeError("AgentsServer install lock ownership changed")
                print(published.st_dev)
                print(published.st_ino)
                raise SystemExit(0)
        raise RuntimeError("AgentsServer install lock ownership kept changing")
    finally:
        if not owned:
            try:
                (candidate / "pid").unlink()
            except FileNotFoundError:
                pass
            try:
                candidate.rmdir()
            except FileNotFoundError:
                pass
elif action == "release":
    expected = (int(raw_device), int(raw_inode))
    directory_descriptor, directory_info = open_lock_directory()
    try:
        if (directory_info.st_dev, directory_info.st_ino) != expected:
            raise RuntimeError("AgentsServer install lock ownership changed")
        owner_pid, _owner_identity = read_owner(directory_descriptor)
        if owner_pid != pid:
            raise RuntimeError("AgentsServer install lock owner changed")
        os.unlink("pid", dir_fd=directory_descriptor)
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    linked = lock.lstat()
    if (linked.st_dev, linked.st_ino) != expected:
        raise RuntimeError("AgentsServer install lock ownership changed")
    os.rmdir(lock)
    for _ in range(3):
        try:
            fsync_directory(root)
            break
        except OSError:
            continue
    else:
        raise RuntimeError("AgentsServer install lock release was not durable")
else:
    raise RuntimeError("AgentsServer install lock action is invalid")
PY
}

release_install_lock() {
  [[ "$INSTALL_LOCK_HELD" == "true" ]] || return 0
  if install_lock_control release \
      "$INSTALL_LOCK_DEVICE" "$INSTALL_LOCK_INODE" >/dev/null; then
    INSTALL_LOCK_HELD="false"
    INSTALL_LOCK_DEVICE=""
    INSTALL_LOCK_INODE=""
    return 0
  fi
  echo "The exact AgentsServer install lock could not be released safely." >&2
  return 1
}

team_hub_transaction_requires_recovery() {
  [[ "$TEAM_HUB_OPERATION_PENDING" == "true" \
    && "$TEAM_HUB_OPERATION_FINALIZED" != "true" ]] && return 0
  [[ "$TEAM_HUB_REACTIVATION_FENCE_PENDING" == "true" \
    && "$TEAM_HUB_REACTIVATION_FINALIZED" != "true" ]] && return 0
  return 1
}

cleanup() {
  local exit_status=$?
  trap - EXIT
  mask_install_signals
  IN_EXIT_CLEANUP="true"
  set +e
  stop_active_stage
  if [[ "$exit_status" != "0" \
    && -n "$ACTIVATION_TRANSACTION_ID" \
    && "$TEAM_HUB_RECOVERY_ATTEMPTED" != "true" ]]; then
    TEAM_HUB_RECOVERY_ATTEMPTED="true"
    case "$ACTIVATION_TRANSACTION_PHASE" in
      committing|committed)
        if declare -F complete_activation_commit >/dev/null \
          && ! complete_activation_commit; then
          echo "The candidate passed its commit boundary; exact finalization remains pending for retry." >&2
        fi
        ;;
      rollback-healthy)
        if declare -F finish_activation_transaction >/dev/null \
          && ! finish_activation_transaction "$STAGE_DIR"; then
          echo "The verified rollback remains durably journaled for retirement." >&2
        fi
        ;;
      *)
        if declare -F restore_previous_release_transaction >/dev/null \
          && ! restore_previous_release_transaction; then
          echo "Activation rollback is incomplete; the exact transaction remains fail-closed for retry." >&2
        fi
        ;;
    esac
  fi
  if [[ "$exit_status" != "0" \
    && -z "$ACTIVATION_TRANSACTION_ID" \
    && "$TEAM_HUB_RECOVERY_ATTEMPTED" != "true" ]] \
    && { team_hub_transaction_requires_recovery \
      || [[ "$TEAM_HUB_COLD_GUARD_PENDING" == "true" ]] \
      || [[ "$SERVICE_STOPPED_FOR_COLD_HANDOFF" == "true" ]]; }; then
    TEAM_HUB_RECOVERY_ATTEMPTED="true"
    if [[ "$CANDIDATE_SERVICE_MAY_HAVE_STARTED" == "true" ]]; then
      if declare -F restore_previous_release >/dev/null && restore_previous_release; then
        [[ "$TEAM_HUB_OPERATION_PENDING" != "true" ]] || TEAM_HUB_OPERATION_FINALIZED="true"
      elif [[ "$TEAM_HUB_OPERATION_PENDING" == "true" \
        || "$TEAM_HUB_REACTIVATION_FENCE_PENDING" == "true" ]]; then
        echo "Team Hub rollback is incomplete; the exact maintenance fence remains fail-closed when present." >&2
      fi
    elif restore_pre_candidate_changes; then
      local cold_handoff_released="true"
      if [[ "$TEAM_HUB_OPERATION_PENDING" == "true" ]]; then
        cold_handoff_released="false"
        if clear_team_hub_operation_fence "$CANDIDATE_RUNTIME_ROOT"; then
          TEAM_HUB_OPERATION_FINALIZED="true"
          cold_handoff_released="true"
        else
          echo "AgentsServer install failed before candidate health and could not safely release Team Hub maintenance." >&2
        fi
      elif [[ "$TEAM_HUB_REACTIVATION_FENCE_PENDING" == "true" \
        && "$TEAM_HUB_REACTIVATION_FINALIZED" != "true" ]]; then
        cold_handoff_released="false"
        if clear_team_hub_reactivation_fence "$CANDIDATE_RUNTIME_ROOT"; then
          TEAM_HUB_REACTIVATION_FINALIZED="true"
          cold_handoff_released="true"
        else
          echo "AgentsServer install failed before takeover and could not safely release Team Hub reactivation maintenance." >&2
        fi
      fi
      if [[ "$TEAM_HUB_COLD_GUARD_PENDING" == "true" ]]; then
        if ! clear_team_hub_cold_guard "$CANDIDATE_RUNTIME_ROOT"; then
          cold_handoff_released="false"
          echo "AgentsServer install could not clear the exact Team Hub startup guard." >&2
        fi
      fi
      if [[ "$SERVICE_STOPPED_FOR_COLD_HANDOFF" == "true" \
        && "$cold_handoff_released" == "true" ]]; then
        if restart_service && wait_for_previous_release_health; then
          SERVICE_STOPPED_FOR_COLD_HANDOFF="false"
        else
          echo "The pre-candidate Team Hub fence was released, but the previous service did not recover." >&2
        fi
      fi
    elif [[ "$TEAM_HUB_OPERATION_PENDING" == "true" \
      || "$TEAM_HUB_REACTIVATION_FENCE_PENDING" == "true" ]]; then
      echo "AgentsServer install failed before candidate health and could not restore local configuration; Team Hub remains fail-closed." >&2
    fi
  fi
  release_install_lock
  if [[ -n "$STAGE_DIR_DEVICE" && -n "$STAGE_DIR_INODE" ]]; then
    local cleanup_python=""
    cleanup_python="$(install_lock_python 2>/dev/null \
      || command -v python3 2>/dev/null || true)"
    if [[ -n "$cleanup_python" ]]; then
      "$cleanup_python" - \
        "$STAGE_DIR" "$STAGE_DIR_DEVICE" "$STAGE_DIR_INODE" <<'PY' || true
import os
from pathlib import Path
import shutil
import stat
import sys

path = Path(sys.argv[1])
expected = (int(sys.argv[2]), int(sys.argv[3]))
try:
    info = path.lstat()
except FileNotFoundError:
    raise SystemExit(0)
if (
    (info.st_dev, info.st_ino) != expected
    or not stat.S_ISDIR(info.st_mode)
    or info.st_uid != os.geteuid()
    or stat.S_IMODE(info.st_mode) & 0o022
):
    # The original stage was activated/renamed or the pathname was replaced.
    # Never recurse through a namespace that is no longer ours.
    raise SystemExit(0)
if not shutil.rmtree.avoids_symlink_attacks:
    raise RuntimeError("safe staged-release cleanup is unavailable")
shutil.rmtree(path)
PY
    fi
  fi
  exit "$exit_status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

acquire_install_lock() {
  validate_install_layout_paths || return 1
  if [[ ! -e "$INSTALL_ROOT" && ! -L "$INSTALL_ROOT" ]]; then
    (umask 077; mkdir -p "$INSTALL_ROOT") || return 1
  fi
  validate_install_layout_paths || return 1
  local result=""
  if ! result="$(install_lock_control acquire)"; then
    echo "Another AgentsServer installation is already running or its lock is unsafe." >&2
    echo "  Wait for it to finish, or cancel it from AgentsDock before retrying." >&2
    return 1
  fi
  INSTALL_LOCK_DEVICE="${result%%$'\n'*}"
  INSTALL_LOCK_INODE="${result#*$'\n'}"
  if [[ "$result" != *$'\n'* \
    || ! "$INSTALL_LOCK_DEVICE" =~ ^[1-9][0-9]*$ \
    || ! "$INSTALL_LOCK_INODE" =~ ^[1-9][0-9]*$ \
    || "$INSTALL_LOCK_INODE" == *$'\n'* ]]; then
    echo "The AgentsServer install lock returned invalid ownership." >&2
    return 1
  fi
  INSTALL_LOCK_HELD="true"
}

validate_exclusive_install_state() {
  if [[ -d "$ACTIVATION_TRANSACTION_DIR" \
    && ! -L "$ACTIVATION_TRANSACTION_DIR" ]]; then
    ACTIVATION_TRANSACTION_RESUMED="true"
  elif [[ -e "$ACTIVATION_TRANSACTION_DIR" \
    || -L "$ACTIVATION_TRANSACTION_DIR" ]]; then
    echo "The pending activation transaction path is unsafe." >&2
    return 1
  elif ! validate_managed_team_hub_inputs "$CURRENT_LINK"; then
    echo "Managed Team Hub inputs changed before the installer acquired exclusive ownership." >&2
    return 1
  fi
}

# Existing installs and ordinary supported hosts have a trusted Python before
# staging, so exclusion precedes even dependency work. A truly fresh host
# without Python may build only its PID-unique staging runtime first; no
# release link, configuration, state, or service mutation occurs before the
# same lock is acquired below.
validate_install_layout_paths || exit 1
if install_lock_python >/dev/null 2>&1; then
  acquire_install_lock || exit 1
  validate_exclusive_install_state || exit 1
fi

run_timed_stage() {
  local label="$1"
  local timeout_seconds="$2"
  local guidance="$3"
  shift 3
  local started_at="$SECONDS"
  local next_heartbeat=$((SECONDS + INSTALL_HEARTBEAT_SECONDS))
  local elapsed=0
  local status=0

  echo "      $label (timeout: ${timeout_seconds}s)"
  # A separate process group lets timeout/cancellation terminate workers
  # spawned by uv or by the uv bootstrap script, not only their parent shell.
  set -m
  "$@" &
  ACTIVE_STAGE_PID="$!"
  ACTIVE_STAGE_PGID="$ACTIVE_STAGE_PID"
  set +m
  while kill -0 "$ACTIVE_STAGE_PID" >/dev/null 2>&1; do
    elapsed=$((SECONDS - started_at))
    if ((SECONDS >= next_heartbeat)); then
      echo "      Still working on $label (${elapsed}s elapsed)"
      next_heartbeat=$((SECONDS + INSTALL_HEARTBEAT_SECONDS))
    fi
    if ((elapsed >= timeout_seconds)); then
      echo "$label timed out after ${timeout_seconds}s." >&2
      echo "  $guidance" >&2
      stop_active_stage
      return 124
    fi
    sleep 1
  done

  if wait "$ACTIVE_STAGE_PID"; then
    ACTIVE_STAGE_PID=""
    ACTIVE_STAGE_PGID=""
    return 0
  else
    status=$?
  fi
  ACTIVE_STAGE_PID=""
  ACTIVE_STAGE_PGID=""
  echo "$label failed with exit code $status." >&2
  echo "  $guidance" >&2
  return "$status"
}

sync_release_dependencies() (
  # Managed updates may be launched from a long-lived tmux server. Never let
  # project/virtual-environment selectors inherited by that server redirect
  # this release sync into an unrelated workspace.
  # PEP 517 build subprocesses inherit uv's environment. Start from a narrow
  # allowlist so credentials and unrelated project selectors from the calling
  # desktop/tmux/service environment never enter third-party build hooks.
  env -i \
    HOME="$HOME" \
    LANG=C \
    LC_ALL=C \
    PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin" \
    UV_PROJECT_ENVIRONMENT="$STAGE_DIR/.venv" \
    "$UV_BIN" sync \
      --project "$STAGE_DIR" \
      --python '>=3.10' \
      --no-dev \
      --frozen
)

validate_staged_release_runtime() (
  scrub_staged_process_environment
  "$STAGE_DIR/.venv/bin/python" -c 'import websockets' >/dev/null
  "$STAGE_DIR/.venv/bin/python" -c 'from importlib.metadata import version; import claude_agent_sdk; sdk_version = version("claude-agent-sdk"); raise SystemExit(0 if sdk_version == "0.2.130" else f"expected claude-agent-sdk 0.2.130, got {sdk_version}")'
  "$STAGE_DIR/.venv/bin/python" -c 'import croniter, dateutil; from zoneinfo import ZoneInfo; ZoneInfo("America/Los_Angeles")' >/dev/null
  "$STAGE_DIR/.venv/bin/python" -m py_compile \
    "$STAGE_DIR/activation_transaction.py" \
    "$STAGE_DIR/agent_server.py" \
    "$STAGE_DIR/team_hub_host.py" \
    "$STAGE_DIR/secure_peer_runtime.py" \
    "$STAGE_DIR/secure_peer_delivery.py" \
    "$STAGE_DIR/agentsdock_jobs.py" \
    "$STAGE_DIR/agentsdock_chats.py" \
    "$STAGE_DIR/agentsdock_emergency.py" \
    "$STAGE_DIR/agentsdock_publish.py" \
    "$STAGE_DIR/agentsdock_mail.py" \
    "$STAGE_DIR/agentsdock_team.py" \
    "$STAGE_DIR/claude_sdk_client.py" \
    "$STAGE_DIR/codex_app_server.py" \
    "$STAGE_DIR/cursor_agent_client.py" \
    "$STAGE_DIR/cursor_process_guard.py" \
    "$STAGE_DIR/update_runner.py"
  "$STAGE_DIR/.venv/bin/python" -m compileall -q "$STAGE_DIR/agentsdock_team_hub"
  PYTHONPATH="$STAGE_DIR" "$STAGE_DIR/.venv/bin/python" -c 'import agentsdock_team_hub, cursor_agent_client, cursor_process_guard, secure_peer_delivery, secure_peer_runtime, team_hub_host, agentsdock_mail, agentsdock_team; from agentsdock_team_hub import secure_peer, secure_peer_hub' >/dev/null
)

abort_unclaimed_team_hub_reactivation() {
  local hub_id="$1"
  local operation_id="$2"
  local snapshot="$3"
  local fence_device="$4"
  local fence_inode="$5"
  run_without_server_secrets env PYTHONPATH="$CANDIDATE_RUNTIME_ROOT" \
    "$CANDIDATE_RUNTIME_ROOT/.venv/bin/python" -m agentsdock_team_hub.cli \
    abort-host-reactivation-preflight \
    --data-dir "$TEAM_HUB_CANONICAL_DATA_DIR" \
    --server-state-dir "$STATE_ROOT" \
    --expected-hub-id "$hub_id" \
    --expected-operation-id "$operation_id" \
    --expected-snapshot "$snapshot" \
    --expected-device "$fence_device" \
    --expected-inode "$fence_inode" >/dev/null 2>&1
}

adopt_team_hub_reactivation() {
  local hub_id="$1"
  local operation_id="$2"
  local snapshot="$3"
  local fence_device="$4"
  local fence_inode="$5"
  run_without_server_secrets env PYTHONPATH="$CANDIDATE_RUNTIME_ROOT" \
    "$CANDIDATE_RUNTIME_ROOT/.venv/bin/python" -m agentsdock_team_hub.cli \
    adopt-host-reactivation-preflight \
    --data-dir "$TEAM_HUB_CANONICAL_DATA_DIR" \
    --server-state-dir "$STATE_ROOT" \
    --expected-hub-id "$hub_id" \
    --expected-operation-id "$operation_id" \
    --expected-snapshot "$snapshot" \
    --expected-device "$fence_device" \
    --expected-inode "$fence_inode" >/dev/null
}

begin_team_hub_cold_guard() {
  local result=""
  local identity=""
  local remainder=""
  if ! result="$(
    run_without_server_secrets env PYTHONPATH="$CANDIDATE_RUNTIME_ROOT" \
      "$CANDIDATE_RUNTIME_ROOT/.venv/bin/python" -m agentsdock_team_hub.cli \
      begin-host-cold-handoff \
      --data-dir "$TEAM_HUB_CANONICAL_DATA_DIR" \
      --server-state-dir "$STATE_ROOT"
  )"; then
    return 1
  fi
  identity="${result%%$'\n'*}"
  remainder="${result#*$'\n'}"
  TEAM_HUB_COLD_GUARD_ID="${remainder%%$'\n'*}"
  remainder="${remainder#*$'\n'}"
  TEAM_HUB_COLD_GUARD_DEVICE="${remainder%%$'\n'*}"
  TEAM_HUB_COLD_GUARD_INODE="${remainder#*$'\n'}"
  if [[ "$result" != *$'\n'* \
    || ( -n "$EXPECTED_SERVER_IDENTITY" && "$identity" != "$EXPECTED_SERVER_IDENTITY" ) \
    || ! "$TEAM_HUB_COLD_GUARD_ID" =~ ^cold-handoff-[0-9a-f]{24}$ \
    || ! "$TEAM_HUB_COLD_GUARD_DEVICE" =~ ^[0-9]+$ \
    || ! "$TEAM_HUB_COLD_GUARD_INODE" =~ ^[0-9]+$ \
    || "$TEAM_HUB_COLD_GUARD_INODE" == *$'\n'* ]]; then
    echo "Team Hub cold-handoff guard returned an invalid result." >&2
    return 1
  fi
  EXPECTED_SERVER_IDENTITY="$identity"
  TEAM_HUB_COLD_GUARD_PENDING="true"
}

clear_team_hub_cold_guard() {
  [[ "$TEAM_HUB_COLD_GUARD_PENDING" == "true" ]] || return 0
  local runtime_root="${1:-$RELEASE_DIR}"
  local allow_missing="${2:-false}"
  [[ -x "$runtime_root/.venv/bin/python" ]] || return 1
  if run_without_server_secrets env PYTHONPATH="$runtime_root" \
    "$runtime_root/.venv/bin/python" -m agentsdock_team_hub.cli \
    clear-host-cold-handoff \
    --data-dir "$TEAM_HUB_CANONICAL_DATA_DIR" \
    --server-state-dir "$STATE_ROOT" \
    --expected-guard-id "$TEAM_HUB_COLD_GUARD_ID" \
    --expected-device "$TEAM_HUB_COLD_GUARD_DEVICE" \
    --expected-inode "$TEAM_HUB_COLD_GUARD_INODE" >/dev/null; then
    TEAM_HUB_COLD_GUARD_PENDING="false"
    return 0
  fi
  if [[ "$allow_missing" == "true" \
    && ! -e "$TEAM_HUB_CANONICAL_DATA_DIR/.managed-startup-guard.json" \
    && ! -L "$TEAM_HUB_CANONICAL_DATA_DIR/.managed-startup-guard.json" ]]; then
    TEAM_HUB_COLD_GUARD_PENDING="false"
    return 0
  fi
  return 1
}

invalid_team_hub_reactivation_result() {
  local hub_id="$1"
  local operation_id="$2"
  local snapshot="$3"
  local fence_device="$4"
  local fence_inode="$5"
  echo "Team Hub reactivation preflight returned an invalid result." >&2
  if ! abort_unclaimed_team_hub_reactivation \
      "$hub_id" "$operation_id" "$snapshot" "$fence_device" "$fence_inode"; then
    echo "Any committed Team Hub reactivation fence remains fail-closed." >&2
  fi
  return 1
}

prepare_team_hub_reactivation() {
  [[ "$TEAM_HUB_REACTIVATION_REQUESTED" == "true" \
    || "$TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED" == "true" ]] || return 0
  local result=""
  local identity=""
  local remainder=""
  local hub_id=""
  local operation_id=""
  local snapshot=""
  local fence_device=""
  local fence_inode=""
  local snapshot_parent=""
  local snapshot_name=""
  if ! result="$(
    run_without_server_secrets env PYTHONPATH="$CANDIDATE_RUNTIME_ROOT" \
      "$CANDIDATE_RUNTIME_ROOT/.venv/bin/python" -m agentsdock_team_hub.cli \
      prepare-host-reactivation \
      --data-dir "$TEAM_HUB_CANONICAL_DATA_DIR" \
      --server-state-dir "$STATE_ROOT"
  )"; then
    echo "Team Hub reactivation preflight failed; hosting mode and the active release were not changed." >&2
    return 1
  fi
  if [[ "$result" != *$'\n'* ]]; then
    echo "Team Hub reactivation preflight returned a truncated result; any committed fence remains fail-closed." >&2
    return 1
  fi
  identity="${result%%$'\n'*}"
  remainder="${result#*$'\n'}"
  if [[ "$remainder" != *$'\n'* ]]; then
    echo "Team Hub reactivation preflight returned a truncated result; any committed fence remains fail-closed." >&2
    return 1
  fi
  hub_id="${remainder%%$'\n'*}"
  remainder="${remainder#*$'\n'}"
  if [[ "$remainder" != *$'\n'* ]]; then
    echo "Team Hub reactivation preflight returned a truncated result; any committed fence remains fail-closed." >&2
    return 1
  fi
  operation_id="${remainder%%$'\n'*}"
  remainder="${remainder#*$'\n'}"
  if [[ "$remainder" != *$'\n'* ]]; then
    echo "Team Hub reactivation preflight returned a truncated result; any committed fence remains fail-closed." >&2
    return 1
  fi
  snapshot="${remainder%%$'\n'*}"
  remainder="${remainder#*$'\n'}"
  if [[ "$remainder" != *$'\n'* ]]; then
    echo "Team Hub reactivation preflight returned a truncated result; any committed fence remains fail-closed." >&2
    return 1
  fi
  fence_device="${remainder%%$'\n'*}"
  fence_inode="${remainder#*$'\n'}"
  if [[ ! "$identity" =~ ^[0-9a-f]{24}$ \
    || ! "$hub_id" =~ ^[A-Za-z0-9_.:-]{8,240}$ \
    || ! "$operation_id" =~ ^host-reactivation-[0-9a-f]{24}$ \
    || -z "$snapshot" \
    || "$snapshot" == *$'\n'* \
    || ! "$fence_device" =~ ^[0-9]+$ \
    || ! "$fence_inode" =~ ^[0-9]+$ \
    || "$fence_inode" == *$'\n'* ]]; then
    echo "Team Hub reactivation preflight returned an invalid identity, Hub, operation, or snapshot." >&2
    invalid_team_hub_reactivation_result \
      "$hub_id" "$operation_id" "$snapshot" "$fence_device" "$fence_inode" || true
    return 1
  fi
  snapshot_parent="${snapshot%/*}"
  snapshot_name="${snapshot##*/}"
  if [[ "$snapshot_parent" != "$TEAM_HUB_CANONICAL_DATA_DIR/maintenance-backups" \
    || ! "$snapshot_name" =~ ^snapshot_[0-9]{20}_[0-9a-f]{16}$ \
    || ! -d "$snapshot" \
    || -L "$snapshot" ]]; then
    echo "Team Hub reactivation preflight returned an unsafe snapshot path." >&2
    invalid_team_hub_reactivation_result \
      "$hub_id" "$operation_id" "$snapshot" "$fence_device" "$fence_inode" || true
    return 1
  fi
  if [[ -n "$EXPECTED_SERVER_IDENTITY" && "$EXPECTED_SERVER_IDENTITY" != "$identity" ]]; then
    echo "Team Hub reactivation identity does not match the expected AgentsServer identity." >&2
    invalid_team_hub_reactivation_result \
      "$hub_id" "$operation_id" "$snapshot" "$fence_device" "$fence_inode" || true
    return 1
  fi
  # Own the parsed operation in shell state before the durable adoption call.
  # If adoption commits its rename but reports an fsync ambiguity, EXIT cleanup
  # must see and either exactly clear this fence or keep the old host stopped;
  # it must never restart legacy code against an adopted rollback generation.
  EXPECTED_SERVER_IDENTITY="$identity"
  TEAM_HUB_REACTIVATION_HUB_ID="$hub_id"
  TEAM_HUB_REACTIVATION_OPERATION_ID="$operation_id"
  TEAM_HUB_REACTIVATION_SNAPSHOT="$snapshot"
  TEAM_HUB_REACTIVATION_FENCE_DEVICE="$fence_device"
  TEAM_HUB_REACTIVATION_FENCE_INODE="$fence_inode"
  TEAM_HUB_REACTIVATION_FENCE_PENDING="true"
  if ! adopt_team_hub_reactivation \
      "$hub_id" "$operation_id" "$snapshot" "$fence_device" "$fence_inode"; then
    echo "Team Hub reactivation preflight could not be durably adopted." >&2
    if abort_unclaimed_team_hub_reactivation \
        "$hub_id" "$operation_id" "$snapshot" "$fence_device" "$fence_inode"; then
      TEAM_HUB_REACTIVATION_FENCE_PENDING="false"
      TEAM_HUB_REACTIVATION_FINALIZED="true"
    else
      echo "The exact Team Hub reactivation operation remains fail-closed." >&2
    fi
    return 1
  fi
  echo "      Verified preserved Team Hub binding and snapshot: $snapshot"
}

migrate_legacy_state() {
  [[ "$STATE_ROOT" == "$DEFAULT_STATE_GUARD" ]] || return 0
  if [[ -L "$LEGACY_STATE_ROOT" ]]; then
    return 0
  fi
  if [[ -e "$LEGACY_STATE_ROOT" && ! -e "$STATE_ROOT" ]]; then
    local legacy_mode=""
    if [[ ! -d "$LEGACY_STATE_ROOT" \
      || ! -O "$LEGACY_STATE_ROOT" \
      || -L "$LEGACY_STATE_ROOT" ]]; then
      echo "The legacy state path is not a safe owned directory; refusing to migrate it." >&2
      return 1
    fi
    legacy_mode="$(stat -c '%a' "$LEGACY_STATE_ROOT" 2>/dev/null \
      || stat -f '%Lp' "$LEGACY_STATE_ROOT" 2>/dev/null)" || return 1
    if [[ ! "$legacy_mode" =~ ^[0-7]{3,4}$ \
      || $((8#$legacy_mode & 8#022)) -ne 0 ]]; then
      echo "The legacy state directory is group/world writable; refusing to migrate it." >&2
      return 1
    fi
    echo "      Migrating existing AgentsDock history to $STATE_ROOT"
    mv "$LEGACY_STATE_ROOT" "$STATE_ROOT"
    ln -s "$STATE_ROOT" "$LEGACY_STATE_ROOT"
  elif [[ -e "$LEGACY_STATE_ROOT" && -e "$STATE_ROOT" ]]; then
    echo "Both $LEGACY_STATE_ROOT and $STATE_ROOT exist; refusing to guess which history is canonical." >&2
    exit 1
  elif [[ -d "$STATE_ROOT" && ! -e "$LEGACY_STATE_ROOT" ]]; then
    ln -s "$STATE_ROOT" "$LEGACY_STATE_ROOT"
  fi
}

echo "[1/7] Preparing the versioned AgentsServer runtime"
if [[ ! -e "$RELEASES_ROOT" && ! -L "$RELEASES_ROOT" ]]; then
  (umask 077; mkdir -p "$RELEASES_ROOT")
fi
validate_install_layout_paths || exit 1

[[ -x "$UV_BIN" ]] \
  && "$UV_BIN" --version >/dev/null 2>&1 \
  || { echo "A trusted uv installation is not available on PATH." >&2; exit 1; }

if [[ -e "$STAGE_DIR" || -L "$STAGE_DIR" ]]; then
  echo "The staged release path already exists; refusing to delete an unowned path: $STAGE_DIR" >&2
  exit 1
fi
(umask 077; mkdir "$STAGE_DIR")
stage_identity="$(stat -c $'%d\n%i' "$STAGE_DIR" 2>/dev/null \
  || stat -f $'%d\n%i' "$STAGE_DIR" 2>/dev/null)" || exit 1
STAGE_DIR_DEVICE="${stage_identity%%$'\n'*}"
STAGE_DIR_INODE="${stage_identity#*$'\n'}"
if [[ "$stage_identity" != *$'\n'* \
  || ! "$STAGE_DIR_DEVICE" =~ ^[1-9][0-9]*$ \
  || ! "$STAGE_DIR_INODE" =~ ^[1-9][0-9]*$ \
  || "$STAGE_DIR_INODE" == *$'\n'* ]]; then
  echo "The staged release returned invalid ownership." >&2
  exit 1
fi
for name in "${RELEASE_FILES[@]}"; do
  install -m 644 "$SOURCE_DIR/$name" "$STAGE_DIR/$name"
done
mkdir -p "$STAGE_DIR/agentsdock_team_hub/migrations"
chmod 755 "$STAGE_DIR/agentsdock_team_hub" "$STAGE_DIR/agentsdock_team_hub/migrations"
for name in "${TEAM_HUB_RELEASE_FILES[@]}"; do
  install -m 644 \
    "$SOURCE_DIR/agentsdock_team_hub/$name" \
    "$STAGE_DIR/agentsdock_team_hub/$name"
done
chmod 755 "$STAGE_DIR/agent_server.py" "$STAGE_DIR/agentsdock_jobs.py" "$STAGE_DIR/agentsdock_chats.py" "$STAGE_DIR/agentsdock_emergency.py" "$STAGE_DIR/agentsdock_publish.py" "$STAGE_DIR/agentsdock_mail.py" "$STAGE_DIR/agentsdock_team.py" "$STAGE_DIR/install.sh" "$STAGE_DIR/uninstall.sh" "$STAGE_DIR/update_runner.py"

echo "[2/7] Resolving the release dependencies with uv"
if run_timed_stage \
  "dependency resolution" \
  "$DEPENDENCY_SYNC_TIMEOUT_SECONDS" \
  "Review the uv output above. Verify disk space and outbound HTTPS access, then run install.sh again; the active release was not changed." \
  sync_release_dependencies; then
  :
else
  stage_status=$?
  exit "$stage_status"
fi
if [[ ! -d "$STAGE_DIR/.venv" || -L "$STAGE_DIR/.venv" || ! -x "$STAGE_DIR/.venv/bin/python" ]]; then
  echo "Dependency resolution did not create the isolated release runtime at $STAGE_DIR/.venv." >&2
  echo "  The active release was not changed. Review the uv output above, then run install.sh again." >&2
  exit 1
fi
validate_staged_release_runtime
if ! validate_bind_address "$BIND_ADDRESS" "$STAGE_DIR/.venv/bin/python"; then
  echo "Bind address must be localhost or one canonical IPv4/IPv6 literal." >&2
  exit 2
fi
if [[ "$INSTALL_LOCK_HELD" != "true" ]]; then
  acquire_install_lock || exit 1
  validate_exclusive_install_state || exit 1
fi
migrate_legacy_state
mkdir -p "$CONFIG_ROOT" "$STATE_ROOT" "$STATE_ROOT/admin"
chmod 700 "$CONFIG_ROOT" "$STATE_ROOT" "$STATE_ROOT/admin"
TOKEN="$(find_existing_token || true)"
generate_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    run_without_server_secrets "$STAGE_DIR/.venv/bin/python" -c 'import secrets; print(secrets.token_hex(32))'
  fi
}
[[ "$TOKEN" =~ ^[A-Za-z0-9_-]{32,}$ ]] || TOKEN="$(generate_token)"

PRESERVE_SOURCE=""
[[ -z "$LEGACY_ENV_FILE" || ( ! -e "$LEGACY_ENV_FILE" && ! -L "$LEGACY_ENV_FILE" ) ]] \
  || PRESERVE_SOURCE="$LEGACY_ENV_FILE"
[[ ! -e "$ENV_FILE" && ! -L "$ENV_FILE" ]] || PRESERVE_SOURCE="$ENV_FILE"

write_runtime_env() {
  local env_temp="$CONFIG_ROOT/.env.activation-$ACTIVATION_TRANSACTION_ID-env.source"
  (umask 077; set -o noclobber; : > "$env_temp") 2>/dev/null || return 1
  chmod 600 "$env_temp" || return 1
  if [[ -n "$PRESERVE_SOURCE" ]]; then
    local preserved_contents=""
    local filter_status=0
    preserved_contents="$(read_owned_config_file "$PRESERVE_SOURCE")" || return 1
    if printf '%s\n' "$preserved_contents" \
      | grep -Ev '^(AGENTSDOCK_(STATE_DIR|AGENT_CWD|AGENT_BIND|AGENT_PORT|AGENT_TOKEN|TEAM_HUB_MODE|TEAM_HUB_TRANSPORT|TEAM_HUB_URL|TEAM_HUB_DIRECT_IP_URL|TEAM_HUB_REACTIVATION_HUB_ID|TEAM_HUB_REACTIVATION_OPERATION_ID|TEAM_HUB_REACTIVATION_SNAPSHOT|TEAM_HUB_UPDATE_HUB_ID|TEAM_HUB_UPDATE_OPERATION_ID|TEAM_HUB_UPDATE_SNAPSHOT)|AGENTS_SERVER_(STATE_DIR|INSTALL_DIR)|ZENITHBOT_AGENT_(DIR|CWD|BIND|PORT|TOKEN)|ZENITHDOCK_AGENT_TOKEN|PATH)=' \
      > "$env_temp"; then
      :
    else
      filter_status=$?
      [[ "$filter_status" == "1" ]] || return "$filter_status"
    fi
  else
    : > "$env_temp"
  fi
  cat >> "$env_temp" <<EOF
AGENTSDOCK_STATE_DIR=$STATE_ROOT
AGENTSDOCK_AGENT_CWD=$HOME
AGENTSDOCK_AGENT_BIND=$BIND_ADDRESS
AGENTSDOCK_AGENT_PORT=$PORT
AGENTSDOCK_AGENT_TOKEN=$TOKEN
AGENTSDOCK_TEAM_HUB_MODE=$TEAM_HUB_MODE
AGENTSDOCK_TEAM_HUB_TRANSPORT=$TEAM_HUB_TRANSPORT
AGENTSDOCK_TEAM_HUB_URL=$TEAM_HUB_URL
AGENTSDOCK_TEAM_HUB_DIRECT_IP_URL=$TEAM_HUB_DIRECT_IP_URL
AGENTS_SERVER_INSTALL_DIR=$INSTALL_ROOT
PATH=$SERVER_PATH
EOF
  if ! replace_activation_config env "$env_temp" 600; then
    return 1
  fi
  PRESERVE_SOURCE="$ENV_FILE"
}

launchd_target_snapshot() {
  local target="$1"
  local output=""
  local status=0
  if output="$(launchctl print "$target" 2>&1)"; then
    printf '%s\n' "loaded"
    return 0
  else
    status=$?
  fi
  case "$output" in
    *"Could not find service"*|*"service not found"*|*"No such process"*)
      printf '%s\n' "not-found"
      return 0
      ;;
  esac
  [[ -z "$output" ]] || printf '%s\n' "$output" >&2
  return "$status"
}

wait_for_launch_agent_removal() {
  local service_target="$1"
  local attempt
  for ((attempt = 1; attempt <= LAUNCHCTL_STOP_ATTEMPTS; attempt++)); do
    local state=""
    state="$(launchd_target_snapshot "$service_target")" || return 1
    [[ "$state" != "not-found" ]] || return 0
    sleep "$LAUNCHCTL_STOP_DELAY"
  done
  echo "Timed out waiting for $LABEL to stop." >&2
  return 1
}

transient_launchctl_bootstrap_error() {
  local status="$1"
  local output="$2"
  # launchctl collapses launchd's EALREADY into status 5 and this generic EIO text.
  [[ "$output" == *"Operation already in progress"* ]] || \
    { ((status == 5)) && [[ "$output" == *"Bootstrap failed: 5: Input/output error"* ]]; }
}

bootstrap_launch_agent() {
  local domain="$1"
  local service_target="$2"
  local allow_transient_retry="$3"
  local attempt=1
  local output=""
  local status=0

  while ((attempt <= LAUNCHCTL_BOOTSTRAP_ATTEMPTS)); do
    if output="$(launchctl bootstrap "$domain" "$PLIST" 2>&1)"; then
      [[ -z "$output" ]] || printf '%s\n' "$output"
      return 0
    else
      status=$?
    fi
    if [[ "$allow_transient_retry" != "true" ]] || \
      ! transient_launchctl_bootstrap_error "$status" "$output" || \
      ((attempt == LAUNCHCTL_BOOTSTRAP_ATTEMPTS)); then
      [[ -z "$output" ]] || printf '%s\n' "$output" >&2
      return "$status"
    fi
    wait_for_launch_agent_removal "$service_target" || return 1
    sleep "$LAUNCHCTL_STOP_DELAY"
    ((attempt += 1))
  done
  return "$status"
}

systemd_service_active_state() {
  systemctl --user show "$SERVICE_NAME.service" --property=ActiveState --value
}

managed_systemd_service_is_stopped() {
  local state=""
  state="$(systemd_service_active_state 2>/dev/null)" || return 1
  state="${state%%$'\n'*}"
  [[ "$state" == "inactive" || "$state" == "failed" ]]
}

wait_for_managed_systemd_stop() {
  local attempts="$1"
  local attempt=1
  local state=""
  while ((attempt <= attempts)); do
    if ! state="$(systemd_service_active_state 2>/dev/null)"; then
      return 1
    fi
    state="${state%%$'\n'*}"
    case "$state" in
      inactive|failed) return 0 ;;
      active|activating|deactivating|reloading) ;;
      *) return 1 ;;
    esac
    sleep "$SYSTEMD_MANAGED_STOP_DELAY"
    ((attempt += 1))
  done
  return 1
}

stop_managed_systemd_service_bounded() {
  # This path is reachable only from the authenticated managed updater after
  # AgentsServer closed work admission, retired idle provider supervisors,
  # proved an empty descendant set, and the installer proved it is outside the
  # exact service cgroup. Never use a broad process match here.
  systemctl --user stop --no-block "$SERVICE_NAME.service" || return
  if wait_for_managed_systemd_stop "$SYSTEMD_MANAGED_STOP_ATTEMPTS"; then
    return 0
  fi
  # Close the poll/kill race: the exact unit may have reached inactive after
  # the final timed poll. Never turn that normal completion into a false
  # updater failure or send a signal to a later state.
  if managed_systemd_service_is_stopped; then
    return 0
  fi
  echo "AgentsServer did not finish its bounded managed-update stop; terminating the exact drained service cgroup." >&2
  if ! systemctl --user kill \
      --kill-who=all \
      --signal=SIGKILL \
      "$SERVICE_NAME.service"; then
    # systemctl may race the unit's final transition and report that there is
    # nothing left to kill. An authoritative inactive state is success.
    managed_systemd_service_is_stopped || return
  fi
  if wait_for_managed_systemd_stop "$SYSTEMD_MANAGED_KILL_ATTEMPTS"; then
    return 0
  fi
  echo "AgentsServer did not reach a stopped state after exact-unit termination." >&2
  return 1
}

restart_managed_systemd_service_bounded() {
  stop_managed_systemd_service_bounded || return
  # Do not attach the updater to the service start job. The following
  # authenticated health check proves the candidate or enters rollback.
  systemctl --user start --no-block "$SERVICE_NAME.service"
}

restart_service() {
  if [[ "$OS_NAME" == "Linux" ]]; then
    local legacy_exists="false"
    local legacy_snapshot=""
    [[ -f "$LEGACY_SERVICE_FILE" && ! -L "$LEGACY_SERVICE_FILE" ]] \
      && legacy_exists="true"
    if [[ "$PRIOR_LEGACY_SERVICE_STATE" == "absent" ]]; then
      legacy_snapshot="$(systemd_unit_snapshot \
        "$LEGACY_SERVICE_NAME.service" "$legacy_exists")" || return 1
      [[ "${legacy_snapshot%%|*}" == "absent" ]] || return 1
    else
      systemctl --user disable --now "$LEGACY_SERVICE_NAME.service" \
        >/dev/null || return 1
      legacy_snapshot="$(systemd_unit_snapshot \
        "$LEGACY_SERVICE_NAME.service" "$legacy_exists")" || return 1
      [[ "${legacy_snapshot%%|*}" == "stopped" \
        && "${legacy_snapshot#*|}" == "false|"* ]] || return 1
    fi
    systemctl --user daemon-reload || return
    systemctl --user enable "$SERVICE_NAME.service" >/dev/null || return
    if [[ -n "$MANAGED_UPDATE_ID" ]]; then
      restart_managed_systemd_service_bounded
    else
      systemctl --user restart "$SERVICE_NAME.service"
    fi
  else
    local domain="gui/$(id -u)"
    local service_target="$domain/$LABEL"
    local had_service="false"
    local service_state=""
    local output=""
    local status=0
    service_state="$(launchd_target_snapshot "$service_target")" || return 1
    if [[ "$service_state" == "loaded" ]]; then
      had_service="true"
      # bootout acknowledges the request before launchd has removed the job.
      if output="$(launchctl bootout "$service_target" 2>&1)"; then
        [[ -z "$output" ]] || printf '%s\n' "$output"
      else
        status=$?
        service_state="$(launchd_target_snapshot "$service_target")" || return 1
        if [[ "$service_state" == "loaded" ]]; then
          [[ -z "$output" ]] || printf '%s\n' "$output" >&2
          return "$status"
        fi
      fi
      wait_for_launch_agent_removal "$service_target" || return 1
    fi
    # A persistent launchd disabled override survives bootout and makes
    # bootstrap fail. Candidate installation intentionally enables its unit;
    # rollback later restores the exact captured override.
    launchctl enable "$service_target" >/dev/null || return 1
    bootstrap_launch_agent "$domain" "$service_target" "$had_service"
  fi
}

restore_previous_release_transaction() {
  [[ -n "$ACTIVATION_TRANSACTION_ID" ]] || return 1
  if [[ "$ACTIVATION_TRANSACTION_PHASE" == "committing" \
    || "$ACTIVATION_TRANSACTION_PHASE" == "committed" ]]; then
    echo "The activation transaction passed its irreversible commit boundary; rollback is forbidden." >&2
    return 1
  fi

  if [[ "$ACTIVATION_TRANSACTION_PHASE" == "rollback-healthy" ]]; then
    finish_activation_transaction "$STAGE_DIR"
    return
  fi
  local rollback_from_phase="${ACTIVATION_ROLLBACK_FROM:-$ACTIVATION_TRANSACTION_PHASE}"
  local rollback_control_runtime="$CANDIDATE_RUNTIME_ROOT"
  if [[ "$rollback_from_phase" == "fencing" \
    && "$TEAM_HUB_COLD_GUARD_PENDING" == "true" \
    && "$TEAM_HUB_REACTIVATION_FENCE_PENDING" != "true" ]]; then
    # A crash can occur after the preflight CLI durably publishes its handoff
    # but before shell receives/adopts the result. The store returns that exact
    # resumable operation; adopt it before any rollback decision.
    TEAM_HUB_REACTIVATION_REQUESTED="true"
    if ! prepare_team_hub_reactivation; then
      echo "The interrupted Team Hub reactivation preflight could not be recovered." >&2
      return 1
    fi
  fi
  if [[ "$ACTIVATION_TRANSACTION_PHASE" != "rolling-back" ]]; then
    if [[ "$ACTIVATION_TRANSACTION_PHASE" == "fencing" \
      && "$TEAM_HUB_OPERATION_PENDING" == "true" ]]; then
      TEAM_HUB_OPERATION_FENCE_DEVICE=""
      TEAM_HUB_OPERATION_FENCE_INODE=""
    fi
    if ! record_activation_phase rolling-back "$CANDIDATE_RUNTIME_ROOT"; then
      echo "The activation transaction could not durably enter rollback." >&2
      return 1
    fi
  fi

  if [[ "$ACTIVATION_TRANSACTION_PHASE" != "rolled-back" ]]; then
    case "$rollback_from_phase" in
      linking|linked|stopping|stopped|fencing|fenced|authorizing|authority)
      # The link can expose the candidate to an already-loaded service unit,
      # but a first install has no unit yet: treating that proven absence as a
      # stop failure would wedge otherwise recoverable pre-service rollback.
      if [[ "$PRIOR_SERVICE_STATE" == "absent" ]]; then
        :
      elif ! suppress_service_autostart_for_rollback; then
        echo "The service manager could not durably suppress candidate restart; rollback was not attempted." >&2
        return 1
      elif ! stop_service; then
        echo "The candidate service could not be stopped, so rollback was not attempted." >&2
        return 1
      fi
      ;;
      candidate-starting|candidate-healthy)
      if ! suppress_service_autostart_for_rollback; then
        echo "The service manager could not durably suppress candidate restart; rollback was not attempted." >&2
        return 1
      fi
      if ! stop_service; then
        echo "The candidate service could not be stopped, so rollback was not attempted." >&2
        return 1
      fi
      ;;
      *) ;;
    esac

    if [[ "$TEAM_HUB_OPERATION_PENDING" == "true" \
      || "$TEAM_HUB_REACTIVATION_FENCE_PENDING" == "true" ]]; then
      if ! restore_team_hub_snapshot; then
        echo "The verified Team Hub snapshot could not be restored; the previous release was not started." >&2
        return 1
      fi
    fi
    if ! restore_activation_files "$CANDIDATE_RUNTIME_ROOT"; then
      echo "The Team Hub snapshot was restored, but the previous release configuration could not be restored." >&2
      return 1
    fi
    if [[ -x "$ACTIVATION_TRANSACTION_DIR/candidate.retired/.venv/bin/python" ]]; then
      rollback_control_runtime="$ACTIVATION_TRANSACTION_DIR/candidate.retired"
    elif [[ ! -x "$rollback_control_runtime/.venv/bin/python" ]]; then
      rollback_control_runtime="$STAGE_DIR"
    fi
    if [[ "$TEAM_HUB_COLD_GUARD_PENDING" == "true" ]]; then
      local allow_missing_guard="false"
      case "$rollback_from_phase" in
        authority|candidate-starting|candidate-healthy) allow_missing_guard="true" ;;
      esac
      if ! clear_team_hub_cold_guard \
          "$rollback_control_runtime" "$allow_missing_guard"; then
        echo "The previous release was restored, but its exact startup guard could not be cleared." >&2
        return 1
      fi
    fi
    # The receipt itself remains the last Hub startup blocker.  Persist exact
    # release/configuration rollback before consuming it, so a crash cannot
    # expose the restored database through candidate links.
    if ! record_activation_phase rolled-back "$rollback_control_runtime"; then
      echo "Rollback files were restored, but their durable activation state was not recorded." >&2
      return 1
    fi
  fi

  if ! clear_team_hub_startup_authority "$rollback_control_runtime" true; then
    echo "The prior release was restored, but candidate startup authority could not be retired." >&2
    return 1
  fi
  TEAM_HUB_STARTUP_AUTHORITY_PENDING="false"
  TEAM_HUB_OPERATION_FINALIZED="true"
  TEAM_HUB_REACTIVATION_FINALIZED="true"
  TEAM_HUB_OPERATION_PENDING="false"
  TEAM_HUB_REACTIVATION_FENCE_PENDING="false"
  if ! acknowledge_team_hub_restore_receipt "$rollback_control_runtime" true; then
    echo "The restored Team Hub generation could not be acknowledged safely." >&2
    return 1
  fi

  case "$rollback_from_phase" in
    linking|linked|stopping|stopped|fencing|fenced|authorizing|authority)
    if [[ "$PRIOR_SERVICE_STATE" != "absent" ]]; then
      if ! restore_prior_service_state; then
        echo "The previous release configuration was restored, but its prior service state was not." >&2
        return 1
      fi
      if [[ "$PRIOR_SERVICE_STATE" == "running" ]] \
        && ! wait_for_previous_release_health; then
        echo "The previous service restarted, but its exact server and Team Hub identities were not healthy; rollback is incomplete." >&2
        return 1
      fi
    fi
    ;;
    candidate-starting|candidate-healthy)
    if ! restore_prior_service_state; then
      echo "The previous release configuration was restored, but its prior service state was not." >&2
      return 1
    fi
    if [[ "$PRIOR_SERVICE_STATE" == "running" ]]; then
      if ! wait_for_previous_release_health; then
        echo "The previous service restarted, but its exact server and Team Hub identities were not healthy; rollback is incomplete." >&2
        return 1
      fi
    elif [[ "$OS_NAME" == "Linux" \
      && "$PRIOR_SERVICE_STATE" == "absent" \
      && "$PRIOR_LEGACY_SERVICE_STATE" == "running" ]]; then
      if ! wait_for_legacy_release_health "$rollback_control_runtime"; then
        echo "The restored legacy service did not become authenticated and healthy." >&2
        return 1
      fi
    fi
    ;;
  esac
  if ! record_activation_phase rollback-healthy "$rollback_control_runtime" \
    || ! finish_activation_transaction "$rollback_control_runtime"; then
    echo "Rollback succeeded but its activation transaction could not be retired." >&2
    return 1
  fi
  return 0
}

restore_previous_release() {
  TEAM_HUB_RECOVERY_ATTEMPTED="true"
  mask_install_signals
  local status=0
  if restore_previous_release_transaction; then
    status=0
  else
    status=$?
  fi
  if [[ "$IN_EXIT_CLEANUP" != "true" ]]; then
    resume_install_signals
  fi
  return "$status"
}

stop_service() {
  if [[ "$OS_NAME" == "Linux" ]]; then
    if [[ -n "$MANAGED_UPDATE_ID" ]]; then
      stop_managed_systemd_service_bounded
    else
      systemctl --user stop "$SERVICE_NAME.service"
    fi
    return
  fi
  local domain="gui/$(id -u)"
  local service_target="$domain/$LABEL"
  local service_state=""
  local output=""
  local status=0
  service_state="$(launchd_target_snapshot "$service_target")" || return 1
  if [[ "$service_state" == "not-found" ]]; then
    return 0
  fi
  if output="$(launchctl bootout "$service_target" 2>&1)"; then
    [[ -z "$output" ]] || printf '%s\n' "$output"
  else
    status=$?
    service_state="$(launchd_target_snapshot "$service_target")" || return 1
    if [[ "$service_state" == "loaded" ]]; then
      [[ -z "$output" ]] || printf '%s\n' "$output" >&2
      return "$status"
    fi
  fi
  wait_for_launch_agent_removal "$service_target"
}

suppress_service_autostart_for_rollback() {
  # Keep the rollback exclusion in the service manager, not only in the new
  # runtime.  An older release may not recognize the restore receipt; this
  # durable disable prevents reboot/autorestart between file restoration and
  # the journal's rolled-back boundary from opening the restored Hub.
  if [[ "$OS_NAME" == "Linux" ]]; then
    systemctl --user disable "$SERVICE_NAME.service" >/dev/null || return 1
  else
    launchctl disable "gui/$(id -u)/$LABEL" >/dev/null || return 1
  fi
}

restore_prior_service_state() {
  # Links and configuration have already been restored from the journal. Keep
  # the pre-install running/enabled state exact; a failed first install must
  # not leave its candidate running, and a previously stopped service must not
  # be started merely because rollback succeeded.
  if [[ "$OS_NAME" == "Linux" ]]; then
    systemctl --user daemon-reload || return 1
    if [[ "$PRIOR_SERVICE_ENABLED" == "true" ]]; then
      systemctl --user enable "$SERVICE_NAME.service" >/dev/null || return 1
    elif [[ "$PRIOR_SERVICE_STATE" == "absent" ]]; then
      systemctl --user disable "$SERVICE_NAME.service" >/dev/null 2>&1 || true
    else
      systemctl --user disable "$SERVICE_NAME.service" >/dev/null || return 1
    fi
    if [[ "$PRIOR_SERVICE_STATE" == "running" ]]; then
      if [[ -n "$MANAGED_UPDATE_ID" ]]; then
        systemctl --user start --no-block "$SERVICE_NAME.service" || return 1
      else
        systemctl --user start "$SERVICE_NAME.service" || return 1
      fi
      :
    else
      systemctl --user stop "$SERVICE_NAME.service" >/dev/null 2>&1 || {
        [[ "$PRIOR_SERVICE_STATE" == "absent" ]] || return 1
      }
    fi
    if [[ "$PRIOR_LEGACY_SERVICE_ENABLED" == "true" ]]; then
      systemctl --user enable "$LEGACY_SERVICE_NAME.service" >/dev/null || return 1
    elif [[ "$PRIOR_LEGACY_SERVICE_STATE" == "absent" ]]; then
      systemctl --user disable "$LEGACY_SERVICE_NAME.service" >/dev/null 2>&1 || true
    else
      systemctl --user disable "$LEGACY_SERVICE_NAME.service" >/dev/null || return 1
    fi
    if [[ "$PRIOR_LEGACY_SERVICE_STATE" == "running" ]]; then
      systemctl --user start "$LEGACY_SERVICE_NAME.service" || return 1
    else
      systemctl --user stop "$LEGACY_SERVICE_NAME.service" >/dev/null 2>&1 || {
        [[ "$PRIOR_LEGACY_SERVICE_STATE" == "absent" ]] || return 1
      }
    fi
    local current_exists="false"
    local legacy_exists="false"
    local observed_snapshot=""
    [[ -f "$SYSTEMD_SERVICE_FILE" && ! -L "$SYSTEMD_SERVICE_FILE" ]] \
      && current_exists="true"
    [[ -f "$LEGACY_SERVICE_FILE" && ! -L "$LEGACY_SERVICE_FILE" ]] \
      && legacy_exists="true"
    if [[ "$PRIOR_SERVICE_STATE" != "running" ]]; then
      observed_snapshot="$(systemd_unit_snapshot \
        "$SERVICE_NAME.service" "$current_exists")" || return 1
      [[ "${observed_snapshot%%|*}" == "$PRIOR_SERVICE_STATE" \
        && "${observed_snapshot#*|}" == "$PRIOR_SERVICE_ENABLED|"* ]] \
        || return 1
    fi
    if [[ "$PRIOR_LEGACY_SERVICE_STATE" != "running" ]]; then
      observed_snapshot="$(systemd_unit_snapshot \
        "$LEGACY_SERVICE_NAME.service" "$legacy_exists")" || return 1
      [[ "${observed_snapshot%%|*}" == "$PRIOR_LEGACY_SERVICE_STATE" \
        && "${observed_snapshot#*|}" == "$PRIOR_LEGACY_SERVICE_ENABLED|"* ]] \
        || return 1
    fi
    return 0
  fi

  local domain="gui/$(id -u)"
  local service_target="$domain/$LABEL"
  local launchd_state=""
  if [[ "$PRIOR_SERVICE_STATE" == "running" ]]; then
    # launchd refuses both bootstrap and kickstart while a persistent disabled
    # override is set. Temporarily enable, restore the running job, then put a
    # deliberately disabled-but-running prior state back exactly.
    launchctl enable "$service_target" >/dev/null || return 1
    launchd_state="$(launchd_target_snapshot "$service_target")" || return 1
    if [[ "$launchd_state" == "loaded" ]]; then
      launchctl kickstart -k "$service_target" >/dev/null || return 1
    else
      bootstrap_launch_agent "$domain" "$service_target" false || return 1
    fi
    if [[ "$PRIOR_SERVICE_ENABLED" != "true" ]]; then
      launchctl disable "$service_target" >/dev/null || return 1
    fi
    return 0
  fi
  if [[ "$PRIOR_SERVICE_ENABLED" == "true" ]]; then
    launchctl enable "$service_target" >/dev/null || return 1
  else
    launchctl disable "$service_target" >/dev/null || return 1
  fi
  stop_service || return 1
  launchd_state="$(launchd_target_snapshot "$service_target")" || return 1
  [[ "$launchd_state" == "not-found" ]]
}

restore_team_hub_snapshot() {
  if [[ "$TEAM_HUB_REACTIVATION_REQUESTED" == "true" \
    || "$TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED" == "true" ]]; then
    local reactivation_python="$CANDIDATE_RUNTIME_ROOT/.venv/bin/python"
    if [[ ! -x "$reactivation_python" ]]; then
      echo "The candidate runtime cannot restore the Team Hub reactivation snapshot." >&2
      return 1
    fi
    echo "      Restoring the verified pre-reactivation Team Hub snapshot"
    if run_without_server_secrets env PYTHONPATH="$CANDIDATE_RUNTIME_ROOT" \
      "$reactivation_python" -m agentsdock_team_hub.cli \
      restore-host-reactivation-snapshot \
      --data-dir "$TEAM_HUB_CANONICAL_DATA_DIR" \
      --snapshot "$TEAM_HUB_REACTIVATION_SNAPSHOT" \
      --expected-host-identity "$EXPECTED_SERVER_IDENTITY" \
      --expected-hub-id "$TEAM_HUB_REACTIVATION_HUB_ID" \
      --expected-operation-id "$TEAM_HUB_REACTIVATION_OPERATION_ID"; then
      return 0
    fi
    echo "      Verifying a previously completed reactivation restore"
    run_without_server_secrets env PYTHONPATH="$CANDIDATE_RUNTIME_ROOT" \
      "$reactivation_python" -m agentsdock_team_hub.cli \
      confirm-restored-host-reactivation-snapshot \
      --data-dir "$TEAM_HUB_CANONICAL_DATA_DIR" \
      --snapshot "$TEAM_HUB_REACTIVATION_SNAPSHOT" \
      --expected-host-identity "$EXPECTED_SERVER_IDENTITY" \
      --expected-hub-id "$TEAM_HUB_REACTIVATION_HUB_ID" \
      --expected-operation-id "$TEAM_HUB_REACTIVATION_OPERATION_ID"
    return
  fi
  [[ -n "$EXPECTED_TEAM_HUB_ID" ]] || return 0
  local restore_python="$CANDIDATE_RUNTIME_ROOT/.venv/bin/python"
  if [[ ! -x "$restore_python" ]]; then
    echo "The candidate runtime cannot verify the Team Hub rollback snapshot." >&2
    return 1
  fi
  echo "      Restoring the verified Team Hub maintenance snapshot"
  if run_without_server_secrets env PYTHONPATH="$CANDIDATE_RUNTIME_ROOT" "$restore_python" -m agentsdock_team_hub.cli \
      restore-snapshot \
      --data-dir "$TEAM_HUB_DATA_DIR" \
      --snapshot "$TEAM_HUB_SNAPSHOT" \
      --expected-host-identity "$EXPECTED_SERVER_IDENTITY" \
      --expected-hub-id "$EXPECTED_TEAM_HUB_ID" \
      --expected-operation-id "$TEAM_HUB_OPERATION_ID"; then
    return 0
  fi
  echo "      Verifying a previously completed maintenance restore"
  run_without_server_secrets env PYTHONPATH="$CANDIDATE_RUNTIME_ROOT" "$restore_python" -m agentsdock_team_hub.cli \
    confirm-restored-snapshot \
    --data-dir "$TEAM_HUB_DATA_DIR" \
    --snapshot "$TEAM_HUB_SNAPSHOT" \
    --expected-host-identity "$EXPECTED_SERVER_IDENTITY" \
    --expected-hub-id "$EXPECTED_TEAM_HUB_ID" \
    --expected-operation-id "$TEAM_HUB_OPERATION_ID"
}

acknowledge_team_hub_restore_receipt() {
  local runtime_root="${1:-$CANDIDATE_RUNTIME_ROOT}"
  local allow_missing="${2:-false}"
  local command=""
  local data_dir=""
  local snapshot=""
  local hub_id=""
  local operation_id=""
  case "$ACTIVATION_HUB_KIND" in
    host-reactivation)
      command="acknowledge-restored-host-reactivation-snapshot"
      data_dir="$TEAM_HUB_CANONICAL_DATA_DIR"
      snapshot="$TEAM_HUB_REACTIVATION_SNAPSHOT"
      hub_id="$TEAM_HUB_REACTIVATION_HUB_ID"
      operation_id="$TEAM_HUB_REACTIVATION_OPERATION_ID"
      ;;
    server-update)
      command="acknowledge-restored-snapshot"
      data_dir="$TEAM_HUB_DATA_DIR"
      snapshot="$TEAM_HUB_SNAPSHOT"
      hub_id="$EXPECTED_TEAM_HUB_ID"
      operation_id="$TEAM_HUB_OPERATION_ID"
      ;;
    "") return 0 ;;
    *) return 1 ;;
  esac
  local arguments=(
    "$command"
    --data-dir "$data_dir"
    --snapshot "$snapshot"
    --expected-host-identity "$EXPECTED_SERVER_IDENTITY"
    --expected-hub-id "$hub_id"
    --expected-operation-id "$operation_id"
  )
  [[ "$allow_missing" != "true" ]] || arguments+=(--allow-missing)
  run_without_server_secrets env PYTHONPATH="$runtime_root" \
    "$runtime_root/.venv/bin/python" -m agentsdock_team_hub.cli \
    "${arguments[@]}" >/dev/null
}

port_has_listener() {
  local port="$1"
  # Keep the probe in a subshell so both the socket descriptor and diagnostic
  # redirection are scoped to this check. A bare `exec ... 2>/dev/null` here
  # would permanently silence the installer's stderr after the first probe.
  (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null || return 1
  return 0
}

describe_port_listener() {
  local port="$1"
  command -v lsof >/dev/null 2>&1 || return 0
  lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {print "  " $1 " (pid " $2 ")"}' | sort -u
}

write_service_files() {
  local service_temp=""
  if [[ "$OS_NAME" == "Linux" ]]; then
    USER_SERVICE_DIR="$HOME/.config/systemd/user"
    mkdir -p "$USER_SERVICE_DIR"
    service_temp="$USER_SERVICE_DIR/.agents-server.service.activation-$ACTIVATION_TRANSACTION_ID-service.source"
    (umask 077; set -o noclobber; : > "$service_temp") 2>/dev/null || return 1
    chmod 600 "$service_temp" || return 1
    cat > "$service_temp" <<EOF
[Unit]
Description=AgentsServer
After=network-online.target

[Service]
Type=simple
WorkingDirectory=$CURRENT_LINK
EnvironmentFile=$ENV_FILE
ExecStart=$CURRENT_LINK/.venv/bin/python $CURRENT_LINK/agent_server.py serve --bind $BIND_ADDRESS --port $PORT
Restart=always
RestartSec=2
# Shutdown normally completes in under a second after provider admission is
# drained. Bound orphaned cgroup descendants so even a legacy updater invoking
# synchronous systemctl restart cannot be stranded behind systemd's 90s
# default. New managed updaters use the stricter external stop/start path too.
TimeoutStopSec=10s
# Keep the coordinator alive long enough to record/recover agent failures
# when systemd-oomd must choose among pressured user services. Provider
# subprocesses remain in this cgroup and are stopped with the service.
ManagedOOMPreference=avoid

[Install]
WantedBy=default.target
EOF
    if ! replace_activation_config service "$service_temp" 644; then
      return 1
    fi
    SERVICE_KIND="systemd-user"
  elif [[ "$OS_NAME" == "Darwin" ]]; then
    LAUNCH_AGENTS="$HOME/Library/LaunchAgents"
    mkdir -p "$LAUNCH_AGENTS" "$HOME/Library/Logs/AgentsServer"
    service_temp="$LAUNCH_AGENTS/.com.agentsdock.server.plist.activation-$ACTIVATION_TRANSACTION_ID-service.source"
    (umask 077; set -o noclobber; : > "$service_temp") 2>/dev/null || return 1
    chmod 600 "$service_temp" || return 1
    cat > "$service_temp" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array>
    <string>$CURRENT_LINK/.venv/bin/python</string>
    <string>$CURRENT_LINK/agent_server.py</string>
    <string>serve</string><string>--bind</string><string>$BIND_ADDRESS</string>
    <string>--port</string><string>$PORT</string>
  </array>
  <key>WorkingDirectory</key><string>$CURRENT_LINK</string>
  <key>EnvironmentVariables</key><dict>
    <key>AGENTSDOCK_STATE_DIR</key><string>$STATE_ROOT</string>
    <key>AGENTSDOCK_AGENT_CWD</key><string>$HOME</string>
    <key>AGENTSDOCK_AGENT_BIND</key><string>$BIND_ADDRESS</string>
    <key>AGENTSDOCK_AGENT_PORT</key><string>$PORT</string>
    <key>AGENTSDOCK_AGENT_TOKEN</key><string>$TOKEN</string>
    <key>AGENTSDOCK_TEAM_HUB_MODE</key><string>$TEAM_HUB_MODE</string>
    <key>AGENTSDOCK_TEAM_HUB_TRANSPORT</key><string>$TEAM_HUB_TRANSPORT</string>
    <key>AGENTSDOCK_TEAM_HUB_URL</key><string>$TEAM_HUB_URL</string>
    <key>AGENTSDOCK_TEAM_HUB_DIRECT_IP_URL</key><string>$TEAM_HUB_DIRECT_IP_URL</string>
    <key>AGENTS_SERVER_INSTALL_DIR</key><string>$INSTALL_ROOT</string>
    <key>PATH</key><string>$SERVER_PATH</string>
  </dict>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$HOME/Library/Logs/AgentsServer/server.log</string>
  <key>StandardErrorPath</key><string>$HOME/Library/Logs/AgentsServer/server-error.log</string>
</dict></plist>
EOF
    if ! replace_activation_config service "$service_temp" 600; then
      return 1
    fi
    SERVICE_KIND="launch-agent"
  else
    echo "Unsupported host OS: $OS_NAME" >&2
    exit 1
  fi
}

HEALTH_CHECK_HEARTBEAT_ATTEMPTS=5

health_host_for_bind() {
  local selected_bind="${1:-$BIND_ADDRESS}"
  case "$selected_bind" in
    0.0.0.0|localhost) printf '%s\n' "127.0.0.1" ;;
    ::|"[::]"|::1|"[::1]") printf '%s\n' "::1" ;;
    *) printf '%s\n' "$selected_bind" ;;
  esac
}

health_origin() {
  local port="$1"
  local host=""
  host="$(health_host_for_bind)" || return 1
  if [[ "$host" == *:* ]]; then
    printf 'http://[%s]:%s\n' "$host" "$port"
  else
    printf 'http://%s:%s\n' "$host" "$port"
  fi
}

service_manager_main_pid() {
  local service="$1"
  local value=""
  if [[ "$OS_NAME" == "Darwin" ]]; then
    value="$(launchctl print "gui/$(id -u)/$service" 2>/dev/null \
      | sed -n 's/^[[:space:]]*pid = \([0-9][0-9]*\);*$/\1/p' \
      | tail -n 1)" || return 1
  else
    value="$(systemctl --user show "$service.service" \
      --property=MainPID --value 2>/dev/null)" || return 1
  fi
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || return 1
  printf '%s\n' "$value"
}

process_owns_listener() {
  local pid="$1"
  local port="$2"
  local runtime_root="$3"
  local host=""
  host="$(health_host_for_bind)" || return 1
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -a -p "$pid" -iTCP:"$port" -sTCP:LISTEN 2>/dev/null \
      | awk -v expected="$pid" -v host="$host" -v port="$port" '
          NR > 1 && $2 == expected {
            endpoint = $(NF - 1)
            if (endpoint == "*:" port || endpoint == host ":" port \
                || endpoint == "[" host "]:" port) found = 1
          }
          END { exit !found }
        '
    return
  fi
  [[ "$OS_NAME" == "Linux" && -x "$runtime_root/.venv/bin/python" ]] || return 1
  run_without_server_secrets "$runtime_root/.venv/bin/python" - \
    "$pid" "$port" "$host" <<'PY'
import os
from pathlib import Path
import ipaddress
import socket
import sys

pid = int(sys.argv[1])
port = int(sys.argv[2])
expected_host = ipaddress.ip_address(sys.argv[3])
socket_inodes = set()
for entry in (Path("/proc") / str(pid) / "fd").iterdir():
    try:
        target = os.readlink(entry)
    except OSError:
        continue
    if target.startswith("socket:[") and target.endswith("]"):
        socket_inodes.add(target[8:-1])
if not socket_inodes:
    raise SystemExit(1)
for table in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
    try:
        lines = table.read_text(encoding="ascii").splitlines()[1:]
    except OSError:
        continue
    for line in lines:
        fields = line.split()
        if len(fields) < 10 or fields[3] != "0A":
            continue
        try:
            raw_address, raw_port = fields[1].rsplit(":", 1)
            local_port = int(raw_port, 16)
            packed = bytes.fromhex(raw_address)
            if table.name == "tcp":
                local_address = ipaddress.ip_address(packed[::-1])
            else:
                # /proc/net/tcp6 stores four little-endian 32-bit words.
                packed = b"".join(
                    packed[offset : offset + 4][::-1]
                    for offset in range(0, 16, 4)
                )
                local_address = ipaddress.ip_address(packed)
        except (IndexError, ValueError):
            continue
        if (
            local_port == port
            and fields[9] in socket_inodes
            and (local_address.is_unspecified or local_address == expected_host)
        ):
            raise SystemExit(0)
raise SystemExit(1)
PY
}

service_manager_owns_listener() {
  local port="$1"
  local runtime_root="$2"
  local service=""
  local pid=""
  local -a services=()
  if [[ "$OS_NAME" == "Darwin" ]]; then
    services=("$LABEL")
  else
    services=("$SERVICE_NAME" "${LEGACY_SERVICE_NAME:-}")
  fi
  for service in "${services[@]}"; do
    [[ -n "$service" ]] || continue
    pid="$(service_manager_main_pid "$service")" || continue
    if process_owns_listener "$pid" "$port" "$runtime_root"; then
      return 0
    fi
  done
  return 1
}

# Open the local HTTP connection first, prove that the exact accepted socket
# belongs to the service-manager MainPID while that connection remains open,
# and only then read/send the administrator token.  A separate LISTEN check is
# insufficient: the managed process could exit and an unrelated process could
# bind the port before a separate HTTP client transmits the token.
pinned_managed_http_get() {
  local port="$1"
  local path="$2"
  local authorization_kind="$3"
  local output_file="$4"
  local runtime_root="$5"
  local selected_bind="${6:-$BIND_ADDRESS}"
  local host=""
  local service=""
  local pid=""
  local -a services=()
  host="$(health_host_for_bind "$selected_bind")" || return 1
  [[ "$path" == /* && "$path" != *$'\n'* && "$path" != *$'\r'* ]] || return 1
  case "$authorization_kind" in
    core|secure-peer) ;;
    *) return 1 ;;
  esac
  [[ -x "$runtime_root/.venv/bin/python" ]] || return 1
  if [[ "$OS_NAME" == "Darwin" ]]; then
    services=("$LABEL")
  else
    services=("$SERVICE_NAME" "${LEGACY_SERVICE_NAME:-}")
  fi
  for service in "${services[@]}"; do
    [[ -n "$service" ]] || continue
    pid="$(service_manager_main_pid "$service")" || continue
    if run_without_server_secrets "$runtime_root/.venv/bin/python" - \
        "$OS_NAME" "$pid" "$host" "$port" "$path" \
        "$authorization_kind" "$output_file" 3<<<"$TOKEN" <<'PY'
import ipaddress
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import time


MAXIMUM_BODY = 1024 * 1024
MAXIMUM_HEADERS = 64 * 1024
DEADLINE_SECONDS = 2.0


def fail():
    raise SystemExit(1)


def address_from_proc(raw, ipv6):
    packed = bytes.fromhex(raw)
    if not ipv6:
        packed = packed[::-1]
    else:
        packed = b"".join(
            packed[offset : offset + 4][::-1]
            for offset in range(0, 16, 4)
        )
    return ipaddress.ip_address(packed)


def linux_connection_owned(pid, server, client):
    inodes = set()
    try:
        entries = (Path("/proc") / str(pid) / "fd").iterdir()
        for entry in entries:
            try:
                target = os.readlink(entry)
            except OSError:
                continue
            if target.startswith("socket:[") and target.endswith("]"):
                inodes.add(target[8:-1])
    except OSError:
        return False
    if not inodes:
        return False
    expected_server = (ipaddress.ip_address(server[0]), int(server[1]))
    expected_client = (ipaddress.ip_address(client[0]), int(client[1]))
    for table, ipv6 in ((Path("/proc/net/tcp"), False), (Path("/proc/net/tcp6"), True)):
        try:
            lines = table.read_text(encoding="ascii").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 10 or fields[3] != "01" or fields[9] not in inodes:
                continue
            try:
                local_address, local_port = fields[1].rsplit(":", 1)
                remote_address, remote_port = fields[2].rsplit(":", 1)
                observed_server = (
                    address_from_proc(local_address, ipv6),
                    int(local_port, 16),
                )
                observed_client = (
                    address_from_proc(remote_address, ipv6),
                    int(remote_port, 16),
                )
            except (IndexError, ValueError):
                continue
            if observed_server == expected_server and observed_client == expected_client:
                return True
    return False


def parse_lsof_endpoint(value):
    value = value.strip().split(None, 1)[0]
    if value.startswith("["):
        closing = value.find("]:")
        if closing < 0:
            raise ValueError
        host = value[1:closing]
        port = value[closing + 2 :]
    else:
        host, port = value.rsplit(":", 1)
    return ipaddress.ip_address(host), int(port)


def darwin_connection_owned(pid, server, client, timeout):
    try:
        result = subprocess.run(
            [
                "/usr/sbin/lsof",
                "-nP",
                "-a",
                "-p",
                str(pid),
                "-iTCP",
                "-sTCP:ESTABLISHED",
                "-Fn",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=max(0.05, timeout),
            check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if result.returncode != 0:
        return False
    expected_server = (ipaddress.ip_address(server[0]), int(server[1]))
    expected_client = (ipaddress.ip_address(client[0]), int(client[1]))
    for raw_line in result.stdout.decode("ascii", "strict").splitlines():
        if not raw_line.startswith("n") or "->" not in raw_line:
            continue
        try:
            local, remote = raw_line[1:].split("->", 1)
            if (
                parse_lsof_endpoint(local) == expected_server
                and parse_lsof_endpoint(remote) == expected_client
            ):
                return True
        except (UnicodeError, ValueError):
            continue
    return False


def receive_response(connection, deadline):
    payload = bytearray()
    header_end = -1
    while header_end < 0:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            fail()
        connection.settimeout(remaining)
        chunk = connection.recv(min(64 * 1024, MAXIMUM_HEADERS + 4 - len(payload)))
        if not chunk:
            fail()
        payload.extend(chunk)
        if len(payload) > MAXIMUM_HEADERS:
            fail()
        header_end = payload.find(b"\r\n\r\n")
    raw_headers = bytes(payload[:header_end])
    body = bytearray(payload[header_end + 4 :])
    try:
        lines = raw_headers.decode("latin-1").split("\r\n")
    except UnicodeError:
        fail()
    status_parts = lines[0].split(" ", 2) if lines else []
    if (
        len(status_parts) < 2
        or status_parts[0] not in ("HTTP/1.0", "HTTP/1.1")
        or status_parts[1] != "200"
    ):
        fail()
    headers = {}
    for line in lines[1:]:
        if not line or line[:1] in " \t" or ":" not in line:
            fail()
        name, value = line.split(":", 1)
        name = name.strip().lower()
        value = value.strip()
        if not name or name in headers:
            fail()
        headers[name] = value
    if "transfer-encoding" in headers:
        fail()
    content_length = None
    if "content-length" in headers:
        try:
            content_length = int(headers["content-length"], 10)
        except ValueError:
            fail()
        if content_length < 0 or content_length > MAXIMUM_BODY:
            fail()
    if len(body) > MAXIMUM_BODY or (
        content_length is not None and len(body) > content_length
    ):
        fail()
    while content_length is None or len(body) < content_length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            fail()
        connection.settimeout(remaining)
        chunk = connection.recv(min(64 * 1024, MAXIMUM_BODY + 1 - len(body)))
        if not chunk:
            break
        body.extend(chunk)
        if len(body) > MAXIMUM_BODY:
            fail()
    if content_length is not None and len(body) != content_length:
        fail()
    return bytes(body)


def write_output(path, payload):
    flags = os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        linked = Path(path).lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o077
            or (before.st_dev, before.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            fail()
        os.ftruncate(descriptor, 0)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                fail()
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main():
    os_name, raw_pid, host, raw_port, path, authorization_kind, output = sys.argv[1:]
    pid = int(raw_pid)
    port = int(raw_port)
    if pid <= 0 or not 1 <= port <= 65535:
        fail()
    deadline = time.monotonic() + DEADLINE_SECONDS
    remaining = deadline - time.monotonic()
    connection = socket.create_connection((host, port), timeout=remaining)
    try:
        server = connection.getpeername()[:2]
        client = connection.getsockname()[:2]
        owned = False
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if os_name == "Linux":
                owned = linux_connection_owned(pid, server, client)
            elif os_name == "Darwin":
                owned = darwin_connection_owned(pid, server, client, remaining)
            else:
                fail()
            if owned:
                break
            time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
        if not owned:
            fail()
        token_parts = []
        token_size = 0
        while token_size <= 4096:
            chunk = os.read(3, min(4097 - token_size, 4096))
            if not chunk:
                break
            token_parts.append(chunk)
            token_size += len(chunk)
        token = b"".join(token_parts)
        if token.endswith(b"\n"):
            token = token[:-1]
        if (
            len(token) < 32
            or len(token) > 4096
            or any(character not in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" for character in token)
        ):
            fail()
        if authorization_kind == "core":
            header_name = b"Authorization"
            header_value = b"Bearer " + token
        else:
            header_name = b"X-AgentsDock-Token"
            header_value = token
        host_header = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        request = (
            b"GET "
            + path.encode("ascii", "strict")
            + b" HTTP/1.1\r\nHost: "
            + host_header.encode("ascii", "strict")
            + b"\r\n"
            + header_name
            + b": "
            + header_value
            + b"\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
        )
        connection.settimeout(max(0.001, deadline - time.monotonic()))
        connection.sendall(request)
        response = receive_response(connection, deadline)
    finally:
        connection.close()
    write_output(output, response)


try:
    main()
except (Exception, OSError, UnicodeError, ValueError):
    raise SystemExit(1)
PY
    then
      return 0
    fi
  done
  return 1
}

health_check_once() {
  local port="$1"
  local origin=""
  origin="$(health_origin "$port")" || return 1
  if command -v curl >/dev/null 2>&1 && curl --version >/dev/null 2>&1; then
    # This probe may be talking to an unrelated occupied port. Never disclose
    # the preserved administrator token until service-manager/socket ownership
    # has been proven by the exact health path below.
    if curl -q --fail --silent --show-error --connect-timeout 1 --max-time 2 \
      --noproxy '*' --proto '=http' --max-redirs 0 \
      "$origin/api/health" >/dev/null 2>&1; then
      return 0
    fi
  fi
  return 1
}

fetch_managed_json() {
  local port="$1"
  local path="$2"
  local authorization_kind="$3"
  local output_file="$4"
  local runtime_root="$5"
  local selected_bind="${6:-$BIND_ADDRESS}"
  pinned_managed_http_get \
    "$port" "$path" "$authorization_kind" "$output_file" "$runtime_root" \
    "$selected_bind"
}

managed_secure_peer_binding_from_responses() {
  local runtime_root="$1"
  local health_file="$2"
  local status_file="$3"
  local expected_server="$4"
  local allow_legacy="${5:-false}"
  local health_size=""
  local status_size=""
  health_size="$(wc -c < "$health_file" 2>/dev/null || true)"
  health_size="${health_size//[[:space:]]/}"
  status_size="$(wc -c < "$status_file" 2>/dev/null || true)"
  status_size="${status_size//[[:space:]]/}"
  if [[ ! "$health_size" =~ ^[0-9]+$ ]] || ((health_size < 2 || health_size > 1048576)); then
    return 1
  fi
  if [[ ! "$status_size" =~ ^[0-9]+$ ]] || ((status_size > 1048576)); then
    return 1
  fi
  run_without_server_secrets "$runtime_root/.venv/bin/python" - \
    "$health_file" \
    "$status_file" \
    "$expected_server" \
    "$allow_legacy" <<'PY'
import json
import re
import sys
import uuid

health_path, status_path, expected_server, allow_legacy = sys.argv[1:]


def load_json(path):
    try:
        with open(path, "rb") as stream:
            return json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise SystemExit(1)


def exact_values(value, expected):
    return isinstance(value, dict) and all(
        value.get(key) == item for key, item in expected.items()
    )


def valid_identifier(value):
    return (
        isinstance(value, str)
        and re.fullmatch(r"[A-Za-z0-9_.:-]{8,240}", value) is not None
    )


def valid_uuid4(value):
    if not isinstance(value, str):
        return False
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return False
    return parsed.version == 4 and str(parsed) == value


disabled_capability = {
    "available": False,
    "designated_host": False,
    "version": 1,
    "base_path": None,
    "hub_id": None,
    "host_server_identity": None,
    "transport": None,
    "hub_url": None,
}
health = load_json(health_path)
if not isinstance(health, dict) or health.get("ok") is not True:
    raise SystemExit(1)
if health.get("server_identity") != expected_server:
    raise SystemExit(1)
capabilities = health.get("capabilities")
team_hub = capabilities.get("team_hub_v1") if isinstance(capabilities, dict) else None
if not isinstance(team_hub, dict) or team_hub.get("designated_host") is not False:
    raise SystemExit(1)
secure_peer = capabilities.get("secure_peer_v1")
if secure_peer is None:
    if allow_legacy != "true" or not exact_values(team_hub, disabled_capability):
        raise SystemExit(1)
    print('{"kind":"disabled"}')
    raise SystemExit(0)
secure_required = {
    "available": True,
    "state_available": True,
    "state_error_code": None,
    "required": False,
    "version": 1,
    "control_path": "/api/admin/secure-peers/v1/status",
    "proxy_prefix": "/api/team-hub-secure",
}
if not exact_values(secure_peer, secure_required):
    raise SystemExit(1)

status = load_json(status_path)
status_version = status.get("version") if isinstance(status, dict) else None
if (
    not isinstance(status, dict)
    or status_version not in {1, 2}
    or status.get("server_identity") != expected_server
    or "active_connection_id" not in status
    or not isinstance(status.get("pairings"), list)
):
    raise SystemExit(1)
active_connection_id = status.get("active_connection_id")
if active_connection_id is not None and not valid_uuid4(active_connection_id):
    raise SystemExit(1)
fingerprint = re.compile(r"sha256:[0-9a-f]{64}")
known_statuses = {
    "requesting",
    "pending_approval",
    "approved",
    "connected",
    "rejected",
    "revoked",
    "expired",
    "error",
}
trust_statuses = {
    "pending": {"requesting", "pending_approval"},
    "approved": {"approved", "connected"},
    "rejected": {"rejected"},
    "cancelled": {"rejected"},
    "revoked": {"revoked"},
    "expired": {"expired"},
    "error": {"error"},
}
known_transport_states = {"online", "reconnecting", "offline", "disconnected", "revoked"}
durable_pairings = []
seen_pairing_ids = set()
seen_connection_ids = set()
for pairing in status["pairings"]:
    if not isinstance(pairing, dict) or pairing.get("direction") not in {"incoming", "outgoing"}:
        raise SystemExit(1)
    if pairing["direction"] != "outgoing":
        continue
    pairing_id = pairing.get("id")
    connection_id = pairing.get("connection_id")
    pairing_status = pairing.get("status")
    if (
        not valid_uuid4(pairing_id)
        or not valid_uuid4(connection_id)
        or pairing_id in seen_pairing_ids
        or connection_id in seen_connection_ids
        or pairing_status not in known_statuses
    ):
        raise SystemExit(1)
    seen_pairing_ids.add(pairing_id)
    seen_connection_ids.add(connection_id)
    if status_version == 1:
        if pairing_status in {"requesting", "pending_approval"}:
            raise SystemExit(1)
        durable = pairing_status in {"approved", "connected"}
    else:
        trust_state = pairing.get("trust_state")
        transport_state = pairing.get("transport_state")
        if (
            trust_state not in trust_statuses
            or pairing_status not in trust_statuses[trust_state]
            or transport_state not in known_transport_states
        ):
            raise SystemExit(1)
        if trust_state == "pending":
            raise SystemExit(1)
        durable = trust_state == "approved"
    if not durable:
        continue

    host_server_identity = pairing.get("host_server_identity")
    hub_id = pairing.get("hub_id")
    team_id = pairing.get("team_id")
    host_ca_fingerprint = pairing.get("host_ca_fingerprint")
    peer_public_key_fingerprint = pairing.get("peer_public_key_fingerprint")
    certificate_fingerprint = pairing.get("certificate_fingerprint")
    transcript_hash = pairing.get("transcript_hash")
    requested_scopes = pairing.get("requested_scopes")
    granted_scopes = pairing.get("granted_scopes")
    is_active = connection_id == active_connection_id
    expected_base_path = (
        f"/api/team-hub-secure/{connection_id}" if is_active else None
    )
    if (
        pairing_status != ("connected" if is_active else "approved")
        or (
            status_version == 2
            and pairing.get("transport_state")
            not in ({"online", "reconnecting", "offline"} if is_active else {"disconnected"})
        )
        or pairing.get("peer_server_identity") != host_server_identity
        or not valid_identifier(host_server_identity)
        or not valid_identifier(hub_id)
        or not valid_identifier(team_id)
        or not all(
            isinstance(value, str) and fingerprint.fullmatch(value) is not None
            for value in (
                host_ca_fingerprint,
                peer_public_key_fingerprint,
                certificate_fingerprint,
            )
        )
        or not isinstance(transcript_hash, str)
        or re.fullmatch(r"[0-9a-f]{64}", transcript_hash) is None
        or not isinstance(requested_scopes, list)
        or not 1 <= len(requested_scopes) <= 4
        or len(set(requested_scopes)) != len(requested_scopes)
        or not all(isinstance(scope, str) and scope for scope in requested_scopes)
        or not isinstance(granted_scopes, list)
        or not 1 <= len(granted_scopes) <= 4
        or len(set(granted_scopes)) != len(granted_scopes)
        or not all(isinstance(scope, str) and scope for scope in granted_scopes)
        or not set(granted_scopes).issubset(requested_scopes)
        or pairing.get("local_proxy_base_path") != expected_base_path
    ):
        raise SystemExit(1)
    durable_pairings.append(
        {
            "id": pairing_id,
            "connection_id": connection_id,
            "host_server_identity": host_server_identity,
            "hub_id": hub_id,
            "team_id": team_id,
            "host_ca_fingerprint": host_ca_fingerprint,
            "peer_public_key_fingerprint": peer_public_key_fingerprint,
            "transcript_hash": transcript_hash,
            # The leaf certificate is intentionally not a continuity key:
            # startup may renew it while retaining the durable trust anchors.
            "requested_scopes": sorted(requested_scopes),
            "granted_scopes": sorted(granted_scopes),
        }
    )

if active_connection_id is not None and active_connection_id not in {
    item["connection_id"] for item in durable_pairings
}:
    raise SystemExit(1)
if not durable_pairings:
    if active_connection_id is not None or not exact_values(team_hub, disabled_capability):
        raise SystemExit(1)
    print('{"kind":"disabled"}')
    raise SystemExit(0)

binding = {
    "kind": "secure_peer_client",
    "active_connection_id": active_connection_id,
    "pairings": sorted(durable_pairings, key=lambda item: item["connection_id"]),
}
if active_connection_id is None:
    if not exact_values(team_hub, disabled_capability):
        raise SystemExit(1)
else:
    active_pairing = next(
        item for item in durable_pairings
        if item["connection_id"] == active_connection_id
    )
    base_path = f"/api/team-hub-secure/{active_connection_id}"
    route = {
        "transport": "secure_peer",
        "hub_url": None,
        "base_path": base_path,
        "connection_id": active_connection_id,
        "host_server_identity": active_pairing["host_server_identity"],
        "hub_id": active_pairing["hub_id"],
    }
    active_capability = {
        "available": True,
        "designated_host": False,
        "version": 1,
        "base_path": base_path,
        "transport": "secure_peer",
        "hub_url": None,
        "connection_id": active_connection_id,
        "hub_id": active_pairing["hub_id"],
        "host_server_identity": active_pairing["host_server_identity"],
        "routes": [route],
    }
    # The health projection intentionally disappears while the active client
    # is offline or stale. Durable status remains authoritative in that case.
    if not (
        exact_values(team_hub, disabled_capability)
        or exact_values(team_hub, active_capability)
    ):
        raise SystemExit(1)
print(json.dumps(binding, sort_keys=True, separators=(",", ":")))
PY
}

capture_managed_team_hub_client_binding() {
  local port="$1"
  local runtime_root="$2"
  local expected_server="$3"
  local selected_bind="${4:-$BIND_ADDRESS}"
  local health_file=""
  local status_file=""
  local binding_file=""
  health_file="$(mktemp "$STATE_ROOT/admin/.install-pre-health.XXXXXX")" || return 1
  status_file="$(mktemp "$STATE_ROOT/admin/.install-pre-peer-status.XXXXXX")" || {
    rm -f "$health_file"
    return 1
  }
  binding_file="$(mktemp "$STATE_ROOT/admin/.install-client-binding.XXXXXX")" || {
    rm -f "$health_file" "$status_file"
    return 1
  }
  chmod 600 "$health_file" "$status_file" "$binding_file"
  if ! fetch_managed_json \
      "$port" "/api/health" core "$health_file" "$runtime_root" \
      "$selected_bind"; then
    rm -f "$health_file" "$status_file" "$binding_file"
    return 1
  fi
  # Legacy sources predate the control endpoint. The projection below accepts
  # a missing status response only when the health capability is also absent.
  if ! fetch_managed_json \
      "$port" \
      "/api/admin/secure-peers/v1/status" \
      secure-peer \
      "$status_file" \
      "$runtime_root" \
      "$selected_bind"; then
    : > "$status_file"
  fi
  if ! managed_secure_peer_binding_from_responses \
      "$runtime_root" \
      "$health_file" \
      "$status_file" \
      "$expected_server" \
      "true" > "$binding_file"; then
    rm -f "$health_file" "$status_file" "$binding_file"
    return 1
  fi
  EXPECTED_TEAM_HUB_CLIENT_BINDING="$(tr -d '\r\n' < "$binding_file")"
  rm -f "$health_file" "$status_file" "$binding_file"
  [[ -n "$EXPECTED_TEAM_HUB_CLIENT_BINDING" ]]
}

release_health_check_once() {
  local port="$1"
  local runtime_root="$2"
  local expected_version="$3"
  local expected_server="$4"
  local expected_hub_mode="$5"
  local expected_hub="$6"
  local expected_hub_transport="$7"
  local expected_hub_url="$8"
  local allow_legacy_transport="${9:-false}"
  local selected_bind="${10:-$BIND_ADDRESS}"
  local expected_direct_ip_url="${11:-$TEAM_HUB_DIRECT_IP_URL}"
  local response_file=""
  local status_file=""
  local observed_binding_file=""
  response_file="$(mktemp "$STATE_ROOT/admin/.install-health.XXXXXX")" || return 1
  status_file="$(mktemp "$STATE_ROOT/admin/.install-peer-status.XXXXXX")" || {
    rm -f "$response_file"
    return 1
  }
  observed_binding_file="$(mktemp "$STATE_ROOT/admin/.install-observed-binding.XXXXXX")" || {
    rm -f "$response_file" "$status_file"
    return 1
  }
  chmod 600 "$response_file" "$status_file" "$observed_binding_file"
  if ! fetch_managed_json \
      "$port" "/api/health" core "$response_file" "$runtime_root" \
      "$selected_bind"; then
    rm -f "$response_file" "$status_file" "$observed_binding_file"
    return 1
  fi
  local response_size=""
  response_size="$(wc -c < "$response_file" 2>/dev/null || true)"
  response_size="${response_size//[[:space:]]/}"
  if [[ ! "$response_size" =~ ^[0-9]+$ ]] || ((response_size > 1048576)); then
    rm -f "$response_file" "$status_file" "$observed_binding_file"
    return 1
  fi
  local result=1
  if run_without_server_secrets "$runtime_root/.venv/bin/python" - \
    "$response_file" \
    "$expected_version" \
    "$expected_server" \
    "$expected_hub_mode" \
    "$expected_hub" \
    "$expected_hub_transport" \
    "$expected_hub_url" \
    "$expected_direct_ip_url" \
    "$allow_legacy_transport" \
    "$EXPECTED_TEAM_HUB_CLIENT_BINDING" <<'PY'
import json
import re
import sys

(
    path,
    expected_version,
    expected_server,
    hub_mode,
    expected_hub,
    expected_transport,
    expected_hub_url,
    expected_direct_ip_url,
    allow_legacy_transport,
    expected_client_binding_json,
) = sys.argv[1:]
try:
    with open(path, "rb") as stream:
        health = json.load(stream)
except (OSError, UnicodeError, json.JSONDecodeError):
    raise SystemExit(1)
if not isinstance(health, dict) or health.get("ok") is not True:
    raise SystemExit(1)
if health.get("server_version") != expected_version:
    raise SystemExit(1)
server_identity = health.get("server_identity")
if not isinstance(server_identity, str) or re.fullmatch(r"[A-Za-z0-9_.:-]{8,240}", server_identity) is None:
    raise SystemExit(1)
if expected_server and server_identity != expected_server:
    raise SystemExit(1)
capabilities = health.get("capabilities")
capability = capabilities.get("team_hub_v1") if isinstance(capabilities, dict) else None
if not isinstance(capability, dict):
    raise SystemExit(1)
try:
    expected_client_binding = (
        json.loads(expected_client_binding_json)
        if expected_client_binding_json
        else None
    )
except json.JSONDecodeError:
    raise SystemExit(1)
if expected_client_binding is not None and not isinstance(expected_client_binding, dict):
    raise SystemExit(1)
if hub_mode == "host":
    required = {
        "available": True,
        "designated_host": True,
        "version": 1,
        "base_path": "/api/team-hub",
        "host_server_identity": server_identity,
    }
    if any(capability.get(key) != value for key, value in required.items()):
        raise SystemExit(1)
    hub_id = capability.get("hub_id")
    if not isinstance(hub_id, str) or re.fullmatch(r"[A-Za-z0-9_.:-]{8,240}", hub_id) is None:
        raise SystemExit(1)
    if expected_hub and hub_id != expected_hub:
        raise SystemExit(1)
    transport = capability.get("transport")
    hub_url = capability.get("hub_url")
    if (
        allow_legacy_transport == "true"
        and transport is None
        and expected_transport == "loopback"
        and not expected_hub_url
    ):
        transport = "loopback"
    if transport != expected_transport or hub_url != (expected_hub_url or None):
        raise SystemExit(1)
    routes = capability.get("routes")
    expected_routes = [{
        "transport": expected_transport,
        "hub_url": expected_hub_url or None,
    }]
    if expected_direct_ip_url and expected_transport != "direct_ip":
        expected_routes.append({
            "transport": "direct_ip",
            "hub_url": expected_direct_ip_url,
        })
    if routes != expected_routes:
        if not (allow_legacy_transport == "true" and routes is None):
            raise SystemExit(1)
elif hub_mode == "disabled":
    binding_kind = (
        expected_client_binding.get("kind")
        if expected_client_binding is not None
        else "disabled"
    )
    disabled_required = {
        "available": False,
        "designated_host": False,
        "version": 1,
        "base_path": None,
        "hub_id": None,
        "host_server_identity": None,
        "transport": None,
        "hub_url": None,
    }
    if binding_kind == "disabled":
        required = disabled_required
    elif binding_kind == "secure_peer_client":
        connection_id = expected_client_binding.get("active_connection_id")
        pairings = expected_client_binding.get("pairings")
        if not isinstance(pairings, list) or not pairings:
            raise SystemExit(1)
        if connection_id is None:
            required = disabled_required
        else:
            active = [
                item
                for item in pairings
                if isinstance(item, dict)
                and item.get("connection_id") == connection_id
            ]
            if len(active) != 1:
                raise SystemExit(1)
            hub_id = active[0].get("hub_id")
            host_server_identity = active[0].get("host_server_identity")
            identifier = re.compile(r"[A-Za-z0-9_.:-]{8,240}")
            if not all(
                isinstance(value, str) and identifier.fullmatch(value) is not None
                for value in (connection_id, hub_id, host_server_identity)
            ):
                raise SystemExit(1)
            expected_base_path = f"/api/team-hub-secure/{connection_id}"
            expected_route = {
                "transport": "secure_peer",
                "hub_url": None,
                "base_path": expected_base_path,
                "connection_id": connection_id,
                "host_server_identity": host_server_identity,
                "hub_id": hub_id,
            }
            active_required = {
                "available": True,
                "designated_host": False,
                "version": 1,
                "base_path": expected_base_path,
                "hub_id": hub_id,
                "host_server_identity": host_server_identity,
                "transport": "secure_peer",
                "hub_url": None,
                "connection_id": connection_id,
                "routes": [expected_route],
            }
            # A paired client is intentionally omitted from health while its
            # heartbeat is stale/offline. The authenticated status endpoint
            # below remains the durable continuity proof.
            required = (
                disabled_required
                if capability.get("available") is False
                else active_required
            )
    else:
        raise SystemExit(1)
    if any(capability.get(key) != value for key, value in required.items()):
        raise SystemExit(1)
elif hub_mode == "failed_host":
    required = {
        "available": False,
        "designated_host": True,
        "version": 1,
        "base_path": "/api/team-hub",
        "hub_id": None,
        "host_server_identity": server_identity,
        "transport": expected_transport,
        "hub_url": expected_hub_url or None,
    }
    if any(capability.get(key) != value for key, value in required.items()):
        raise SystemExit(1)
else:
    raise SystemExit(1)
secure_capability = capabilities.get("secure_peer_v1")
if secure_capability is None and allow_legacy_transport == "true":
    pass
else:
    secure_required = {
        "available": True,
        "state_available": True,
        "state_error_code": None,
        "required": False,
        "version": 1,
        "control_path": "/api/admin/secure-peers/v1/status",
        "proxy_prefix": "/api/team-hub-secure",
    }
    if not isinstance(secure_capability, dict) or any(
        secure_capability.get(key) != value
        for key, value in secure_required.items()
    ):
        raise SystemExit(1)
PY
  then
    result=0
    if [[ -n "$EXPECTED_TEAM_HUB_CLIENT_BINDING" ]]; then
      if ! fetch_managed_json \
          "$port" \
          "/api/admin/secure-peers/v1/status" \
          secure-peer \
          "$status_file" \
          "$runtime_root" \
          "$selected_bind"; then
        : > "$status_file"
      fi
      if ! managed_secure_peer_binding_from_responses \
          "$runtime_root" \
          "$response_file" \
          "$status_file" \
          "$expected_server" \
          "$allow_legacy_transport" > "$observed_binding_file"; then
        result=1
      elif [[ "$(tr -d '\r\n' < "$observed_binding_file")" != "$EXPECTED_TEAM_HUB_CLIENT_BINDING" ]]; then
        result=1
      fi
    fi
  fi
  rm -f "$response_file" "$status_file" "$observed_binding_file"
  return "$result"
}

wait_for_health() {
  local attempt
  for ((attempt = 1; attempt <= HEALTH_CHECK_ATTEMPTS; attempt++)); do
    if health_check_once "$PORT"; then
      return 0
    fi
    if ((attempt < HEALTH_CHECK_ATTEMPTS)) && ((attempt % HEALTH_CHECK_HEARTBEAT_ATTEMPTS == 0)); then
      echo "      Still waiting for health (${attempt}s elapsed, timeout ${HEALTH_CHECK_ATTEMPTS}s)"
    fi
    ((attempt == HEALTH_CHECK_ATTEMPTS)) || sleep 1
  done
  return 1
}

legacy_release_health_check_once() {
  local runtime_root="${1:-$CANDIDATE_RUNTIME_ROOT}"
  local response_file=""
  response_file="$(mktemp "$STATE_ROOT/admin/.install-legacy-health.XXXXXX")" \
    || return 1
  chmod 600 "$response_file" || {
    rm -f "$response_file"
    return 1
  }
  if ! fetch_managed_json \
      "$PRIOR_PORT" "/api/health" core "$response_file" \
      "$runtime_root" "$PRIOR_BIND_ADDRESS"; then
    rm -f "$response_file"
    return 1
  fi
  local result=1
  if run_without_server_secrets "$runtime_root/.venv/bin/python" - \
      "$response_file" <<'PY'
import json
import re
import sys

try:
    with open(sys.argv[1], "rb") as stream:
        value = json.load(stream)
except (OSError, UnicodeError, json.JSONDecodeError):
    raise SystemExit(1)
if not isinstance(value, dict) or value.get("ok") is not True:
    raise SystemExit(1)
if not isinstance(value.get("server_version"), str) or re.fullmatch(
    r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?",
    value["server_version"],
) is None:
    raise SystemExit(1)
if not isinstance(value.get("server_identity"), str) or re.fullmatch(
    r"[A-Za-z0-9_.:-]{8,240}", value["server_identity"]
) is None:
    raise SystemExit(1)
PY
  then
    result=0
  fi
  rm -f "$response_file"
  return "$result"
}

wait_for_legacy_release_health() {
  local runtime_root="${1:-$CANDIDATE_RUNTIME_ROOT}"
  local attempt=1
  local attempt_limit="$HEALTH_CHECK_ATTEMPTS"
  ((attempt_limit <= ROLLBACK_HEALTH_CHECK_MAX_ATTEMPTS)) \
    || attempt_limit="$ROLLBACK_HEALTH_CHECK_MAX_ATTEMPTS"
  for ((attempt = 1; attempt <= attempt_limit; attempt++)); do
    if legacy_release_health_check_once "$runtime_root"; then
      return 0
    fi
    ((attempt == attempt_limit)) || sleep 1
  done
  return 1
}

wait_for_exact_release_health() {
  local runtime_root="$1"
  local expected_version="$2"
  local expected_server="$3"
  local expected_hub_mode="$4"
  local expected_hub="$5"
  local expected_hub_transport="$6"
  local expected_hub_url="$7"
  local health_label="$8"
  local attempt_limit="${9:-$HEALTH_CHECK_ATTEMPTS}"
  local allow_legacy_transport="${10:-false}"
  local health_port="${11:-$PORT}"
  local health_bind="${12:-$BIND_ADDRESS}"
  local expected_direct_ip_url="${13:-$TEAM_HUB_DIRECT_IP_URL}"
  local attempt
  for ((attempt = 1; attempt <= attempt_limit; attempt++)); do
    if release_health_check_once \
      "$health_port" \
      "$runtime_root" \
      "$expected_version" \
      "$expected_server" \
      "$expected_hub_mode" \
      "$expected_hub" \
      "$expected_hub_transport" \
      "$expected_hub_url" \
      "$allow_legacy_transport" \
      "$health_bind" \
      "$expected_direct_ip_url"; then
      return 0
    fi
    if ((attempt < attempt_limit)) && ((attempt % HEALTH_CHECK_HEARTBEAT_ATTEMPTS == 0)); then
      echo "      Still waiting for exact $health_label health (${attempt}s elapsed, timeout ${attempt_limit}s)"
    fi
    ((attempt == attempt_limit)) || sleep 1
  done
  return 1
}

wait_for_release_health() {
  wait_for_exact_release_health \
    "$RELEASE_DIR" \
    "$RELEASE_VERSION" \
    "$EXPECTED_SERVER_IDENTITY" \
    "$TEAM_HUB_MODE" \
    "${EXPECTED_TEAM_HUB_ID:-$TEAM_HUB_REACTIVATION_HUB_ID}" \
    "$TEAM_HUB_TRANSPORT" \
    "$TEAM_HUB_URL" \
    "candidate release"
}

secure_peer_host_attachment_check_once() {
  [[ "$TEAM_HUB_MODE" == "host" ]] || return 0
  local runtime_root="$1"
  local status_file=""
  local health_file=""
  local observed_identity=""
  status_file="$(mktemp "$STATE_ROOT/admin/.install-host-peer-status.XXXXXX")" || return 1
  health_file="$(mktemp "$STATE_ROOT/admin/.install-host-health.XXXXXX")" || {
    rm -f "$status_file"
    return 1
  }
  chmod 600 "$status_file" "$health_file"
  if ! fetch_managed_json \
      "$PORT" \
      "/api/admin/secure-peers/v1/status" \
      secure-peer \
      "$status_file" \
      "$runtime_root"; then
    rm -f "$status_file" "$health_file"
    return 1
  fi
  if [[ -z "$EXPECTED_SERVER_IDENTITY" ]] \
    && ! fetch_managed_json \
      "$PORT" "/api/health" core "$health_file" "$runtime_root"; then
    rm -f "$status_file" "$health_file"
    return 1
  fi
  local result=1
  if observed_identity="$(run_without_server_secrets "$runtime_root/.venv/bin/python" - \
      "$status_file" "$health_file" "$EXPECTED_SERVER_IDENTITY" <<'PY'
import json
import re
import sys

try:
    with open(sys.argv[1], "rb") as stream:
        value = json.load(stream)
except (OSError, UnicodeError, json.JSONDecodeError):
    raise SystemExit(1)
expected_identity = sys.argv[3]
status_identity = value.get("server_identity") if isinstance(value, dict) else None
if (
    not isinstance(status_identity, str)
    or re.fullmatch(r"[A-Za-z0-9_.:-]{8,240}", status_identity) is None
):
    raise SystemExit(1)
if expected_identity:
    if status_identity != expected_identity:
        raise SystemExit(1)
else:
    try:
        with open(sys.argv[2], "rb") as stream:
            health = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise SystemExit(1)
    if (
        not isinstance(health, dict)
        or health.get("ok") is not True
        or health.get("server_identity") != status_identity
    ):
        raise SystemExit(1)
host = value.get("host") if isinstance(value, dict) else None
if (
    not isinstance(host, dict)
    or host.get("available") is not True
    or host.get("error") is not None
    or host.get("error_code") is not None
):
    raise SystemExit(1)
print(status_identity)
PY
  )"; then
    if [[ -n "$EXPECTED_SERVER_IDENTITY" ]]; then
      result=0
    elif run_without_server_secrets env PYTHONPATH="$runtime_root" \
        "$runtime_root/.venv/bin/python" -m agentsdock_team_hub.cli \
        verify-server-identity \
        --server-state-dir "$STATE_ROOT" \
        --expected-identity "$observed_identity" >/dev/null; then
      result=0
    fi
  fi
  rm -f "$status_file" "$health_file"
  return "$result"
}

wait_for_final_release_health() {
  local attempt
  for ((attempt = 1; attempt <= HEALTH_CHECK_ATTEMPTS; attempt++)); do
    if release_health_check_once \
        "$PORT" \
        "$RELEASE_DIR" \
        "$RELEASE_VERSION" \
        "$EXPECTED_SERVER_IDENTITY" \
        "$TEAM_HUB_MODE" \
        "${EXPECTED_TEAM_HUB_ID:-$TEAM_HUB_REACTIVATION_HUB_ID}" \
        "$TEAM_HUB_TRANSPORT" \
        "$TEAM_HUB_URL" \
        false \
      && secure_peer_host_attachment_check_once "$RELEASE_DIR"; then
      return 0
    fi
    ((attempt == HEALTH_CHECK_ATTEMPTS)) || sleep 1
  done
  return 1
}

wait_for_previous_release_health() {
  local previous_version=""
  local previous_release_root="${ROLLBACK_RELEASE_ROOT:-$OLD_TARGET}"
  local rollback_attempts="$HEALTH_CHECK_ATTEMPTS"
  local previous_hub_mode="${PREVIOUS_TEAM_HUB_MODE:-disabled}"
  local previous_hub_id="$EXPECTED_TEAM_HUB_ID"
  local previous_hub_transport="$PREVIOUS_TEAM_HUB_TRANSPORT"
  local previous_hub_url="$PREVIOUS_TEAM_HUB_URL"
  [[ -n "$previous_release_root" && -f "$previous_release_root/VERSION" ]] || {
    echo "The previous release version cannot be verified." >&2
    return 1
  }
  previous_version="$(tr -d '[:space:]' < "$previous_release_root/VERSION")"
  if [[ ! "$previous_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.-]+)?$ ]]; then
    echo "The previous release version is invalid." >&2
    return 1
  fi
  if ((rollback_attempts > ROLLBACK_HEALTH_CHECK_MAX_ATTEMPTS)); then
    rollback_attempts="$ROLLBACK_HEALTH_CHECK_MAX_ATTEMPTS"
  fi
  if [[ "$TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED" == "true" ]]; then
    previous_hub_mode="failed_host"
    previous_hub_id=""
    previous_hub_transport="$PREVIOUS_TEAM_HUB_TRANSPORT"
    previous_hub_url="$PREVIOUS_TEAM_HUB_URL"
  elif [[ "$ACTIVATION_HUB_KIND" == "host-reactivation" ]]; then
    previous_hub_mode="disabled"
    previous_hub_id=""
    previous_hub_transport="loopback"
    previous_hub_url=""
  fi
  wait_for_exact_release_health \
    "$previous_release_root" \
    "$previous_version" \
    "$EXPECTED_SERVER_IDENTITY" \
    "$previous_hub_mode" \
    "$previous_hub_id" \
    "$previous_hub_transport" \
    "$previous_hub_url" \
    "restored release" \
    "$rollback_attempts" \
    "true" \
    "$PRIOR_PORT" \
    "$PRIOR_BIND_ADDRESS" \
    "$PREVIOUS_TEAM_HUB_DIRECT_IP_URL"
}

ensure_committed_candidate_service() {
  if wait_for_release_health; then
    return 0
  fi
  if [[ "$OS_NAME" == "Linux" ]]; then
    systemctl --user daemon-reload || return 1
    systemctl --user enable "$SERVICE_NAME.service" >/dev/null || return 1
    systemctl --user start --no-block "$SERVICE_NAME.service" || return 1
  else
    local domain="gui/$(id -u)"
    local service_target="$domain/$LABEL"
    if launchctl print "$service_target" >/dev/null 2>&1; then
      launchctl kickstart -k "$service_target" >/dev/null || return 1
    else
      bootstrap_launch_agent "$domain" "$service_target" false || return 1
    fi
  fi
  wait_for_release_health
}

resume_settlement_signals() {
  [[ "$IN_EXIT_CLEANUP" == "true" ]] || resume_install_signals
}

complete_activation_commit() {
  [[ "$ACTIVATION_TRANSACTION_PHASE" == "committing" \
    || "$ACTIVATION_TRANSACTION_PHASE" == "committed" ]] || return 1
  if ! ensure_committed_candidate_service; then
    echo "The committed candidate service could not be restored to authenticated health." >&2
    return 1
  fi
  if [[ "$ACTIVATION_TRANSACTION_PHASE" == "committing" ]]; then
    mask_install_signals
    if [[ "$TEAM_HUB_OPERATION_PENDING" == "true" ]]; then
      if ! clear_team_hub_operation_fence "$CANDIDATE_RUNTIME_ROOT" true; then
        echo "The committed candidate could not consume its exact Team Hub update fence." >&2
        resume_settlement_signals
        return 1
      fi
    elif [[ "$TEAM_HUB_REACTIVATION_FENCE_PENDING" == "true" ]]; then
      if ! clear_team_hub_reactivation_fence "$CANDIDATE_RUNTIME_ROOT" true; then
        echo "The committed candidate could not consume its exact Team Hub reactivation fence." >&2
        resume_settlement_signals
        return 1
      fi
    fi
    if ! clear_team_hub_startup_authority "$CANDIDATE_RUNTIME_ROOT" true; then
      echo "The committed candidate could not retire its exact startup authority." >&2
      resume_settlement_signals
      return 1
    fi
    TEAM_HUB_OPERATION_FINALIZED="true"
    TEAM_HUB_REACTIVATION_FINALIZED="true"
    TEAM_HUB_OPERATION_PENDING="false"
    TEAM_HUB_REACTIVATION_FENCE_PENDING="false"
    TEAM_HUB_STARTUP_AUTHORITY_PENDING="false"
    if [[ "$TEAM_HUB_COLD_GUARD_PENDING" == "true" ]] \
      && ! clear_team_hub_cold_guard "$CANDIDATE_RUNTIME_ROOT" true; then
      echo "The committed candidate could not retire its startup guard." >&2
      resume_settlement_signals
      return 1
    fi
    if ! wait_for_final_release_health; then
      echo "The committed candidate did not restore full Hub and secure-peer health." >&2
      resume_settlement_signals
      return 1
    fi
    if ! record_activation_phase committed "$CANDIDATE_RUNTIME_ROOT"; then
      echo "The candidate committed, but its terminal activation state was not persisted." >&2
      resume_settlement_signals
      return 1
    fi
  elif ! wait_for_final_release_health; then
    echo "The terminal candidate no longer has authenticated final health." >&2
    return 1
  fi
  resume_settlement_signals
  finish_activation_transaction "$CANDIDATE_RUNTIME_ROOT"
}

load_pending_activation_transaction() {
  [[ "$ACTIVATION_TRANSACTION_RESUMED" == "true" ]] || return 0
  local load_file=""
  local line=""
  local loaded_state_root=""
  local loaded_port=""
  local -a fields=()
  load_file="$(mktemp "$INSTALL_ROOT/.activation-load.XXXXXXXX")" || return 1
  chmod 600 "$load_file" || {
    rm -f "$load_file"
    return 1
  }
  if ! activation_transaction_command "$STAGE_DIR" load \
      --root "$INSTALL_ROOT" \
      --current "$CURRENT_LINK" \
      --previous "$PREVIOUS_LINK" \
      --env "$ENV_FILE" \
      --service "$(activation_service_config_path)" > "$load_file"; then
    rm -f "$load_file"
    return 1
  fi
  while IFS= read -r line; do
    fields[${#fields[@]}]="$line"
  done < "$load_file"
  rm -f "$load_file"
  if (( ${#fields[@]} != 38 )) \
    || [[ "${fields[37]}" != "activation-end" ]] \
    || [[ ! "${fields[0]}" =~ ^activation-[0-9a-f]{24}$ ]] \
    || [[ ! "${fields[1]}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.-]+)?$ ]] \
    || [[ "${fields[2]}" != "$RELEASES_ROOT/${fields[1]}" ]] \
    || [[ "${fields[3]}" != "prepared" \
      && "${fields[3]}" != "guarded" \
      && "${fields[3]}" != "linking" \
      && "${fields[3]}" != "linked" \
      && "${fields[3]}" != "stopping" \
      && "${fields[3]}" != "stopped" \
      && "${fields[3]}" != "fencing" \
      && "${fields[3]}" != "fenced" \
      && "${fields[3]}" != "authorizing" \
      && "${fields[3]}" != "authority" \
      && "${fields[3]}" != "candidate-starting" \
      && "${fields[3]}" != "candidate-healthy" \
      && "${fields[3]}" != "committing" \
      && "${fields[3]}" != "committed" \
      && "${fields[3]}" != "rolling-back" \
      && "${fields[3]}" != "rolled-back" \
      && "${fields[3]}" != "rollback-healthy" ]] \
    || [[ "${fields[11]}" != "true" && "${fields[11]}" != "false" ]] \
    || [[ "${fields[13]}" != "true" && "${fields[13]}" != "false" ]] \
    || [[ "${fields[15]}" != "absent" \
      && "${fields[15]}" != "stopped" \
      && "${fields[15]}" != "running" ]] \
    || [[ "${fields[16]}" != "true" && "${fields[16]}" != "false" ]] \
    || [[ "${fields[17]}" != "absent" \
      && "${fields[17]}" != "stopped" \
      && "${fields[17]}" != "running" ]] \
    || [[ "${fields[18]}" != "true" && "${fields[18]}" != "false" ]] \
    || [[ "${fields[19]}" != "ordinary" \
      && "${fields[19]}" != "server-update" \
      && "${fields[19]}" != "host-reactivation" \
      && "${fields[19]}" != "failed-host-repair" ]] \
    || [[ "${fields[32]}" != "true" && "${fields[32]}" != "false" ]] \
    || [[ "${fields[33]}" != "true" && "${fields[33]}" != "false" ]] \
    || [[ ! "${fields[35]}" =~ ^[0-9]+$ ]] \
    || (( 10#${fields[35]} < 1 || 10#${fields[35]} > 65535 )); then
    echo "The pending activation transaction returned an invalid recovery record." >&2
    return 1
  fi

  ACTIVATION_TRANSACTION_ID="${fields[0]}"
  RELEASE_VERSION="${fields[1]}"
  RELEASE_DIR="${fields[2]}"
  ACTIVATION_TRANSACTION_PHASE="${fields[3]}"
  ACTIVATION_ROLLBACK_FROM="${fields[4]}"
  OLD_TARGET="${fields[5]}"
  ORIGINAL_OLD_SOURCE="${fields[6]}"
  ROLLBACK_RELEASE_ROOT="$ORIGINAL_OLD_SOURCE"
  CURRENT_LINK_STATE_CAPTURED="true"
  CURRENT_LINK_WAS_SYMLINK="false"
  CURRENT_LINK_WAS_DIRECTORY="false"
  CURRENT_LINK_TARGET="${fields[8]}"
  [[ "${fields[7]}" != "symlink" ]] || CURRENT_LINK_WAS_SYMLINK="true"
  [[ "${fields[7]}" != "directory" ]] || CURRENT_LINK_WAS_DIRECTORY="true"
  PREVIOUS_LINK_STATE_CAPTURED="true"
  PREVIOUS_LINK_WAS_SYMLINK="false"
  PREVIOUS_LINK_TARGET="${fields[10]}"
  [[ "${fields[9]}" != "symlink" ]] || PREVIOUS_LINK_WAS_SYMLINK="true"
  ENV_CONFIG_EXISTED="${fields[11]}"
  ENV_CONFIG_BACKUP="${fields[12]}"
  ENV_CONFIG_CAPTURED="true"
  SERVICE_CONFIG_EXISTED="${fields[13]}"
  SERVICE_CONFIG_BACKUP="${fields[14]}"
  SERVICE_CONFIG_CAPTURED="true"
  PRIOR_SERVICE_STATE="${fields[15]}"
  PRIOR_SERVICE_ENABLED="${fields[16]}"
  PRIOR_LEGACY_SERVICE_STATE="${fields[17]}"
  PRIOR_LEGACY_SERVICE_ENABLED="${fields[18]}"
  ACTIVATION_INTENT="${fields[19]}"
  ACTIVATION_HUB_KIND="${fields[21]}"
  EXPECTED_TEAM_HUB_CLIENT_BINDING="${fields[20]}"
  TEAM_HUB_OPERATION_PENDING="false"
  TEAM_HUB_REACTIVATION_FENCE_PENDING="false"
  TEAM_HUB_OPERATION_FINALIZED="false"
  TEAM_HUB_REACTIVATION_FINALIZED="false"
  TEAM_HUB_REACTIVATION_REQUESTED="false"
  TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED="false"

  case "$ACTIVATION_INTENT" in
    server-update) ;;
    host-reactivation) TEAM_HUB_REACTIVATION_REQUESTED="true" ;;
    failed-host-repair) TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED="true" ;;
  esac
  case "${fields[21]}" in
    "") ;;
    server-update)
      [[ "$ACTIVATION_INTENT" == "server-update" ]] || return 1
      TEAM_HUB_DATA_DIR="${fields[22]}"
      EXPECTED_TEAM_HUB_ID="${fields[23]}"
      EXPECTED_SERVER_IDENTITY="${fields[24]}"
      TEAM_HUB_OPERATION_ID="${fields[25]}"
      TEAM_HUB_SNAPSHOT="${fields[26]}"
      TEAM_HUB_OPERATION_FENCE_DEVICE="${fields[27]}"
      TEAM_HUB_OPERATION_FENCE_INODE="${fields[28]}"
      TEAM_HUB_OPERATION_PENDING="true"
      ;;
    host-reactivation)
      [[ "$ACTIVATION_INTENT" == "host-reactivation" \
        || "$ACTIVATION_INTENT" == "failed-host-repair" ]] || return 1
      TEAM_HUB_CANONICAL_DATA_DIR="${fields[22]}"
      TEAM_HUB_REACTIVATION_HUB_ID="${fields[23]}"
      EXPECTED_SERVER_IDENTITY="${fields[24]}"
      TEAM_HUB_REACTIVATION_OPERATION_ID="${fields[25]}"
      TEAM_HUB_REACTIVATION_SNAPSHOT="${fields[26]}"
      TEAM_HUB_REACTIVATION_FENCE_DEVICE="${fields[27]}"
      TEAM_HUB_REACTIVATION_FENCE_INODE="${fields[28]}"
      TEAM_HUB_REACTIVATION_FENCE_PENDING="true"
      ;;
    *) return 1 ;;
  esac
  TEAM_HUB_COLD_GUARD_ID="${fields[29]}"
  TEAM_HUB_COLD_GUARD_DEVICE="${fields[30]}"
  TEAM_HUB_COLD_GUARD_INODE="${fields[31]}"
  TEAM_HUB_COLD_GUARD_PENDING="false"
  [[ -z "$TEAM_HUB_COLD_GUARD_ID" ]] || TEAM_HUB_COLD_GUARD_PENDING="true"
  TEAM_HUB_STARTUP_AUTHORITY_PENDING="${fields[32]}"
  CANDIDATE_SERVICE_MAY_HAVE_STARTED="${fields[33]}"
  CANDIDATE_RUNTIME_ROOT="${fields[34]}"
  [[ -n "$CANDIDATE_RUNTIME_ROOT" ]] || CANDIDATE_RUNTIME_ROOT="$STAGE_DIR"
  PRIOR_PORT="${fields[35]}"
  PRIOR_BIND_ADDRESS="${fields[36]}"
  validate_bind_address "$PRIOR_BIND_ADDRESS" \
    "$CANDIDATE_RUNTIME_ROOT/.venv/bin/python" || return 1
  SERVICE_STOPPED_FOR_COLD_HANDOFF="$CANDIDATE_SERVICE_MAY_HAVE_STARTED"
  RELEASE_ACTIVATED="$CANDIDATE_SERVICE_MAY_HAVE_STARTED"

  loaded_state_root="$(read_env_value "$ENV_FILE" AGENTSDOCK_STATE_DIR 2>/dev/null || true)"
  if [[ -n "$loaded_state_root" && "$loaded_state_root" == /* \
    && "$loaded_state_root" != *$'\n'* ]]; then
    STATE_ROOT="$loaded_state_root"
    TEAM_HUB_CANONICAL_DATA_DIR="$STATE_ROOT/team-hub"
  fi
  loaded_port="$(read_env_value "$ENV_FILE" AGENTSDOCK_AGENT_PORT 2>/dev/null || true)"
  [[ ! "$loaded_port" =~ ^[0-9]+$ ]] || PORT="$loaded_port"
  local loaded_value=""
  loaded_value="$(read_env_value "$ENV_FILE" AGENTSDOCK_AGENT_BIND 2>/dev/null || true)"
  if [[ -n "$loaded_value" ]]; then
    validate_bind_address "$loaded_value" || return 1
    BIND_ADDRESS="$loaded_value"
  fi
  loaded_value="$(read_env_value "$ENV_FILE" AGENTSDOCK_AGENT_TOKEN 2>/dev/null || true)"
  [[ -z "$loaded_value" ]] || TOKEN="$loaded_value"
  loaded_value="$(read_env_value "$ENV_FILE" AGENTSDOCK_TEAM_HUB_MODE 2>/dev/null || true)"
  [[ -z "$loaded_value" ]] || TEAM_HUB_MODE="$loaded_value"
  loaded_value="$(read_env_value "$ENV_FILE" AGENTSDOCK_TEAM_HUB_TRANSPORT 2>/dev/null || true)"
  [[ -z "$loaded_value" ]] || TEAM_HUB_TRANSPORT="$loaded_value"
  TEAM_HUB_URL="$(read_env_value "$ENV_FILE" AGENTSDOCK_TEAM_HUB_URL 2>/dev/null || true)"
  TEAM_HUB_DIRECT_IP_URL="$(read_env_value "$ENV_FILE" AGENTSDOCK_TEAM_HUB_DIRECT_IP_URL 2>/dev/null || true)"
  PREVIOUS_TEAM_HUB_TRANSPORT="$(read_env_value "$ENV_CONFIG_BACKUP" AGENTSDOCK_TEAM_HUB_TRANSPORT 2>/dev/null || true)"
  [[ -n "$PREVIOUS_TEAM_HUB_TRANSPORT" ]] || PREVIOUS_TEAM_HUB_TRANSPORT="loopback"
  PREVIOUS_TEAM_HUB_MODE="$(read_env_value "$ENV_CONFIG_BACKUP" AGENTSDOCK_TEAM_HUB_MODE 2>/dev/null || true)"
  [[ -n "$PREVIOUS_TEAM_HUB_MODE" ]] || PREVIOUS_TEAM_HUB_MODE="disabled"
  PREVIOUS_TEAM_HUB_URL="$(read_env_value "$ENV_CONFIG_BACKUP" AGENTSDOCK_TEAM_HUB_URL 2>/dev/null || true)"
  PREVIOUS_TEAM_HUB_DIRECT_IP_URL="$(read_env_value "$ENV_CONFIG_BACKUP" AGENTSDOCK_TEAM_HUB_DIRECT_IP_URL 2>/dev/null || true)"
  PRESERVE_SOURCE="$ENV_FILE"
  echo "      Recovering pending activation $ACTIVATION_TRANSACTION_ID ($ACTIVATION_TRANSACTION_PHASE)"
}

recover_pending_activation_transaction() {
  [[ "$ACTIVATION_TRANSACTION_RESUMED" == "true" ]] || return 0
  case "$ACTIVATION_TRANSACTION_PHASE" in
    committing|committed)
      if ! complete_activation_commit; then
        echo "The irreversible activation commit remains pending and fail-closed." >&2
        return 1
      fi
      if [[ "$REQUESTED_RELEASE_VERSION" == "$RELEASE_VERSION" ]]; then
        echo "Recovered and verified the previously committed AgentsServer $RELEASE_VERSION activation."
        return 0
      fi
      echo "Recovered AgentsServer $RELEASE_VERSION. Run the installer again for requested $REQUESTED_RELEASE_VERSION." >&2
      return 75
      ;;
    rollback-healthy)
      if ! finish_activation_transaction "$STAGE_DIR"; then
        return 1
      fi
      echo "Retired the previously verified rollback. Run the installer again." >&2
      return 75
      ;;
    rolled-back)
      if ! restore_previous_release; then
        echo "The pending rollback could not restore its prior service state; its journal remains for retry." >&2
        return 1
      fi
      echo "Recovered the exact pre-activation release and service state. Run the installer again." >&2
      return 75
      ;;
    *)
      if ! restore_previous_release; then
        echo "The pending activation could not be rolled back safely; its journal remains for retry." >&2
        return 1
      fi
      echo "Recovered the exact pre-activation release and service state. Run the installer again." >&2
      return 75
      ;;
  esac
}

if [[ "$ACTIVATION_TRANSACTION_RESUMED" == "true" ]]; then
  if ! load_pending_activation_transaction; then
    echo "The pending activation transaction could not be verified for recovery." >&2
    exit 1
  fi
  if recover_pending_activation_transaction; then
    exit 0
  else
    recovery_status=$?
    exit "$recovery_status"
  fi
fi

if [[ "$TEAM_HUB_OPERATION_PENDING" == "true" ]]; then
  if ! verify_team_hub_rollback_snapshot "$STAGE_DIR"; then
    echo "Candidate Team Hub rollback verifier rejected the exact snapshot before activation." >&2
    exit 1
  fi
fi

echo "[3/7] Activating release $RELEASE_VERSION"
CURRENT_LINK_WAS_DIRECTORY="false"
if [[ -L "$CURRENT_LINK" ]]; then
  OLD_TARGET="$(readlink "$CURRENT_LINK")"
  [[ "$OLD_TARGET" == /* ]] || OLD_TARGET="$INSTALL_ROOT/$OLD_TARGET"
elif [[ -d "$CURRENT_LINK" ]]; then
  CURRENT_LINK_WAS_DIRECTORY="true"
  OLD_TARGET="$RELEASES_ROOT/legacy-$(date -u +%Y%m%d%H%M%S)"
elif [[ -e "$CURRENT_LINK" ]]; then
  echo "$CURRENT_LINK is not a supported release link or directory." >&2
  exit 1
fi
if [[ "$TEAM_HUB_OPERATION_PENDING" == "true" && "$CURRENT_LINK_WAS_DIRECTORY" == "true" ]]; then
  echo "Managed Team Hub update requires a versioned current-release symlink; legacy directory takeover is not supported." >&2
  exit 1
fi
if [[ "$TEAM_HUB_OPERATION_PENDING" == "true" && ( -z "$OLD_TARGET" || ! -d "$OLD_TARGET" ) ]]; then
  echo "Managed Team Hub update requires an existing installed release for verified rollback." >&2
  exit 1
fi
if [[ "$CURRENT_LINK_WAS_DIRECTORY" == "true" ]]; then
  ORIGINAL_OLD_SOURCE="$CURRENT_LINK"
else
  ORIGINAL_OLD_SOURCE="$OLD_TARGET"
fi
ROLLBACK_RELEASE_ROOT="$ORIGINAL_OLD_SOURCE"
if [[ -n "$OLD_TARGET" && "$OLD_TARGET" == "$RELEASE_DIR" ]]; then
  REPLACED_DIR="$RELEASES_ROOT/$RELEASE_VERSION-replaced-$(date -u +%Y%m%d%H%M%S)-$$"
  OLD_TARGET="$REPLACED_DIR"
fi
if ! validate_managed_team_hub_inputs "$CURRENT_LINK"; then
  echo "Managed Team Hub inputs changed before candidate activation." >&2
  exit 1
fi
if [[ -z "$EXPECTED_SERVER_IDENTITY" \
  && -n "$OLD_TARGET" \
  && -e "$OLD_TARGET" ]]; then
  EXPECTED_SERVER_IDENTITY="$(read_owned_config_file \
    "$STATE_ROOT/server-identity")" || {
    echo "The existing release has no safely readable durable server identity." >&2
    exit 1
  }
  if [[ ! "$EXPECTED_SERVER_IDENTITY" =~ ^[A-Za-z0-9_.:-]{8,240}$ ]]; then
    echo "The existing release has an invalid durable server identity." >&2
    exit 1
  fi
fi

backup_runtime_configuration
if [[ -n "$EXPECTED_SERVER_IDENTITY" \
  && "$PREVIOUS_TEAM_HUB_MODE" == "disabled" \
  && "$TEAM_HUB_MODE" == "disabled" \
  && -n "$OLD_TARGET" \
  && -e "$OLD_TARGET" ]]; then
  echo "      Binding current Teamspace client state before takeover"
  if ! capture_managed_team_hub_client_binding \
      "$PRIOR_PORT" \
      "$STAGE_DIR" \
      "$EXPECTED_SERVER_IDENTITY" \
      "$PRIOR_BIND_ADDRESS"; then
    echo "Could not bind the current authenticated Teamspace client before candidate activation." >&2
    exit 1
  fi
fi
if [[ "$TEAM_HUB_OPERATION_PENDING" == "true" ]]; then
  # Bind the externally-created update fence before the first link/service
  # mutation. A restart can then recover the exact operation without relying
  # on a fresh runner invocation carrying the original arguments.
  if ! record_activation_phase prepared "$STAGE_DIR"; then
    echo "The activation transaction could not bind the managed Team Hub update." >&2
    exit 1
  fi
fi
if ! assert_team_hub_config_unchanged \
  || ! assert_env_backup_team_hub_config; then
  echo "Team Hub configuration changed while its rollback image was captured." >&2
  exit 1
fi
COLD_TEAM_HUB_HANDOFF="false"
if [[ "$TEAM_HUB_REACTIVATION_REQUESTED" == "true" \
  || "$TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED" == "true" \
  || "$TEAM_HUB_OPERATION_PENDING" == "true" ]]; then
  COLD_TEAM_HUB_HANDOFF="true"
  mask_install_signals
  if [[ "$TEAM_HUB_REACTIVATION_REQUESTED" == "true" \
    || "$TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED" == "true" ]]; then
    if ! begin_team_hub_cold_guard; then
      resume_install_signals
      echo "The managed Team Hub could not establish its pre-takeover startup guard." >&2
      exit 1
    fi
    if ! record_activation_phase guarded "$STAGE_DIR"; then
      resume_install_signals
      echo "The activation transaction could not persist the Team Hub guard." >&2
      exit 1
    fi
  fi
fi

# Materialize and link the new runtime before asking the service manager to
# stop the old process. The already-published server-update fence or explicit
# startup guard means every manager/manual restart through the installed
# `current` path executes new fail-closed code; legacy beta.31 can never
# reacquire the Hub lease in the stop-to-snapshot handoff window.
if ! record_activation_phase linking "$STAGE_DIR"; then
  [[ "$COLD_TEAM_HUB_HANDOFF" != "true" ]] || resume_install_signals
  echo "The activation transaction could not enter link takeover." >&2
  exit 1
fi
RELEASE_ACTIVATED="true"
if ! activate_transaction_files "$STAGE_DIR"; then
  [[ "$COLD_TEAM_HUB_HANDOFF" != "true" ]] || resume_install_signals
  echo "The activation transaction could not complete the exact release/link takeover." >&2
  exit 1
fi
CANDIDATE_RUNTIME_ROOT="$RELEASE_DIR"
if ! record_activation_phase linked "$CANDIDATE_RUNTIME_ROOT"; then
  [[ "$COLD_TEAM_HUB_HANDOFF" != "true" ]] || resume_install_signals
  echo "The activation transaction could not prove the candidate link." >&2
  exit 1
fi

if [[ "$COLD_TEAM_HUB_HANDOFF" == "true" ]]; then
  # Mark the stop transaction before invoking the manager: bootout/stop may
  # commit even when its final acknowledgement fails.
  SERVICE_STOPPED_FOR_COLD_HANDOFF="true"
  if ! record_activation_phase stopping "$CANDIDATE_RUNTIME_ROOT"; then
    resume_install_signals
    echo "The activation transaction could not enter service stop." >&2
    exit 1
  fi
  if ! stop_service; then
    resume_install_signals
    echo "The managed Team Hub service stop could not be confirmed for its cold handoff." >&2
    exit 1
  fi
  if ! record_activation_phase stopped "$CANDIDATE_RUNTIME_ROOT"; then
    resume_install_signals
    echo "The activation transaction could not prove the service stop." >&2
    exit 1
  fi
fi

if [[ "$TEAM_HUB_REACTIVATION_REQUESTED" == "true" \
  || "$TEAM_HUB_FAILED_HOST_REPAIR_REQUESTED" == "true" ]]; then
  if ! record_activation_phase fencing "$CANDIDATE_RUNTIME_ROOT"; then
    resume_install_signals
    echo "The activation transaction could not enter Team Hub fencing." >&2
    exit 1
  fi
  if ! prepare_team_hub_reactivation; then
    resume_install_signals
    echo "The managed Team Hub could not establish its cold reactivation snapshot." >&2
    exit 1
  fi
fi
if ! validate_team_hub_reactivation_inputs "$CANDIDATE_RUNTIME_ROOT"; then
  [[ "$COLD_TEAM_HUB_HANDOFF" != "true" ]] || resume_install_signals
  echo "Team Hub reactivation inputs changed before candidate activation." >&2
  exit 1
fi
if [[ "$TEAM_HUB_OPERATION_PENDING" == "true" ]]; then
  if ! record_activation_phase fencing "$CANDIDATE_RUNTIME_ROOT"; then
    resume_install_signals
    echo "The activation transaction could not enter Team Hub snapshot rebase." >&2
    exit 1
  fi
  if ! rebase_team_hub_rollback_snapshot \
    || ! validate_managed_team_hub_inputs "$CANDIDATE_RUNTIME_ROOT"; then
    resume_install_signals
    echo "The managed Team Hub cold update handoff could not refresh and verify its rollback generation." >&2
    exit 1
  fi
fi
if [[ "$COLD_TEAM_HUB_HANDOFF" == "true" ]]; then
  if [[ "$TEAM_HUB_OPERATION_PENDING" == "true" ]]; then
    # Snapshot rebase atomically replaces the fence. Re-read and journal the
    # exact new inode rather than carrying the pre-rebase identity forward.
    TEAM_HUB_OPERATION_FENCE_DEVICE=""
    TEAM_HUB_OPERATION_FENCE_INODE=""
  fi
  if ! record_activation_phase fenced "$CANDIDATE_RUNTIME_ROOT"; then
    resume_install_signals
    echo "The activation transaction could not bind the exact Team Hub fence." >&2
    exit 1
  fi
fi
write_runtime_env
if [[ "$TEAM_HUB_OPERATION_PENDING" == "true" \
  || "$TEAM_HUB_REACTIVATION_FENCE_PENDING" == "true" ]]; then
  # Journal cleanup ownership before publishing the authority file. A crash
  # after file publication but before the next phase can then clear it
  # idempotently instead of leaking stale one-shot authorization.
  TEAM_HUB_STARTUP_AUTHORITY_PENDING="true"
  if ! record_activation_phase authorizing "$CANDIDATE_RUNTIME_ROOT"; then
    [[ "$COLD_TEAM_HUB_HANDOFF" != "true" ]] || resume_install_signals
    echo "The activation transaction could not enter candidate authorization." >&2
    exit 1
  fi
  if ! team_hub_startup_authority_control \
      publish "$CANDIDATE_RUNTIME_ROOT"; then
    [[ "$COLD_TEAM_HUB_HANDOFF" != "true" ]] || resume_install_signals
    echo "The exact Team Hub candidate startup authority could not be persisted." >&2
    exit 1
  fi
  if ! record_activation_phase authority "$CANDIDATE_RUNTIME_ROOT"; then
    [[ "$COLD_TEAM_HUB_HANDOFF" != "true" ]] || resume_install_signals
    echo "The activation transaction could not persist candidate authorization." >&2
    exit 1
  fi
fi
if [[ "$TEAM_HUB_COLD_GUARD_PENDING" == "true" ]]; then
  if ! clear_team_hub_cold_guard "$CANDIDATE_RUNTIME_ROOT"; then
    resume_install_signals
    echo "The managed Team Hub startup guard could not be cleared after exact candidate authority was persisted." >&2
    exit 1
  fi
fi
if [[ "$COLD_TEAM_HUB_HANDOFF" == "true" ]]; then
  resume_install_signals
fi

# A requested port held by an authenticated AgentsServer is the service being
# replaced and will be released by restart_service. A listener that is present
# before restart and rejects the preserved token is treated as a conflict.
ORIGINAL_PORT="$PORT"
PORT_AUTO_SELECTED="false"
PORT_FALLBACK_BLOCKED="false"
port_fallback_attempt=0

while true; do
  # Select a fallback only for a listener that was present before this service
  # is restarted and does not authenticate with the preserved AgentsServer
  # token. A newly started but unhealthy AgentsServer must be rolled back, not
  # mistaken for a port conflict and silently moved to another port.
  if [[ "$PORT_FALLBACK" == "true" ]] \
    && port_has_listener "$PORT" \
    && ! service_manager_owns_listener "$PORT" "$CANDIDATE_RUNTIME_ROOT"; then
    echo "Port $PORT is already held by another process:" >&2
    describe_port_listener "$PORT" >&2
    if [[ "$TEAM_HUB_MODE" == "host" \
      && ( "$TEAM_HUB_TRANSPORT" != "loopback" \
        || -n "$TEAM_HUB_URL" \
        || -n "$TEAM_HUB_DIRECT_IP_URL" ) ]]; then
      echo "Automatic port fallback is unsafe while an external Team Hub route is configured." >&2
      PORT_FALLBACK_BLOCKED="true"
      break
    fi
    port_fallback_attempt=$((port_fallback_attempt + 1))
    candidate=$((ORIGINAL_PORT + port_fallback_attempt))
    while ((port_fallback_attempt <= PORT_FALLBACK_ATTEMPTS)) && ((candidate <= 65535)) && port_has_listener "$candidate"; do
      port_fallback_attempt=$((port_fallback_attempt + 1))
      candidate=$((ORIGINAL_PORT + port_fallback_attempt))
    done
    if ((port_fallback_attempt <= PORT_FALLBACK_ATTEMPTS)) && ((candidate <= 65535)); then
      PORT="$candidate"
      PORT_AUTO_SELECTED="true"
      write_runtime_env
      echo "Selecting port $PORT instead (attempt $port_fallback_attempt/$PORT_FALLBACK_ATTEMPTS)." >&2
      continue
    fi
    echo "Ran out of nearby free ports to try." >&2
  fi

  echo "[4/7] Installing the user service (port $PORT)"
  write_service_files
  if ! record_activation_phase candidate-starting "$CANDIDATE_RUNTIME_ROOT"; then
    echo "The activation transaction could not enter candidate startup." >&2
    exit 1
  fi
  CANDIDATE_SERVICE_MAY_HAVE_STARTED="true"
  if ! restart_service; then
    echo "AgentsServer $RELEASE_VERSION could not start; restoring the previous service when possible." >&2
    if restore_previous_release; then
      echo "The previous release and service were restored." >&2
    fi
    exit 1
  fi

  echo "[5/7] Waiting for authenticated health"
  if wait_for_release_health; then
    if ! record_activation_phase candidate-healthy "$CANDIDATE_RUNTIME_ROOT"; then
      echo "The healthy candidate could not persist its recoverable activation state." >&2
      exit 1
    fi
    # This phase is the irreversible boundary. Any failure after it must
    # complete the candidate commit on retry; it must never restore a snapshot
    # whose fence may already have been consumed.
    if ! record_activation_phase committing "$CANDIDATE_RUNTIME_ROOT"; then
      echo "The healthy candidate could not enter its exact commit boundary." >&2
      exit 1
    fi
    if ! complete_activation_commit; then
      echo "AgentsServer $RELEASE_VERSION passed its commit boundary but finalization remains pending." >&2
      exit 1
    fi
    break
  fi

  echo "AgentsServer $RELEASE_VERSION did not become healthy; rolling back." >&2
  PORT="$ORIGINAL_PORT"
  if restore_previous_release; then
    echo "The previous release was restored." >&2
  fi
  if [[ "$OS_NAME" == "Linux" ]]; then
    systemctl --user status "$SERVICE_NAME.service" --no-pager -l >&2 || true
  fi
  exit 1
done
if [[ "$PORT_FALLBACK_BLOCKED" == "true" ]]; then
  PORT="$ORIGINAL_PORT"
  return 1 2>/dev/null || exit 1
fi

echo "[6/7] Checking optional agent runtimes"
check_runtime_cli() {
  local name="$1"
  local install_hint="$2"
  if command -v "$name" >/dev/null 2>&1; then
    echo "      $CHECK_MARK $name found"
    return 0
  fi
  echo "      $CROSS_MARK $name not found - $install_hint"
  return 1
}
CLAUDE_READY="false"
CODEX_READY="false"
check_runtime_cli claude "npm install -g @anthropic-ai/claude-code, then run: claude" && CLAUDE_READY="true"
check_runtime_cli codex "npm install -g @openai/codex, then run: codex login" && CODEX_READY="true"
if [[ "$CLAUDE_READY" == "false" && "$CODEX_READY" == "false" ]]; then
  echo "      Sign in to at least one before starting a chat."
fi

TAILSCALE_IP=""
if command -v tailscale >/dev/null 2>&1; then
  TAILSCALE_IP="$(tailscale ip -4 2>/dev/null | head -n 1 || true)"
fi
SERVER_URL="$(health_origin "$PORT")"
if [[ "$BIND_ADDRESS" == "0.0.0.0" && -n "$TAILSCALE_IP" ]]; then
  SERVER_URL="http://$TAILSCALE_IP:$PORT"
fi

echo "[7/7] AgentsServer $RELEASE_VERSION is ready"
echo
echo "  ${COLOR_BOLD}Server URL${COLOR_RESET}    $SERVER_URL"
echo
echo "  ${COLOR_BOLD}Next steps${COLOR_RESET}"
if [[ "$PORT_AUTO_SELECTED" == "true" ]]; then
  echo "  $DOT_MARK port $ORIGINAL_PORT was already in use, installed on $PORT instead (--port pins an exact port unless --allow-port-fallback is supplied)"
fi
if [[ "$CLAUDE_READY" == "false" && "$CODEX_READY" == "false" ]]; then
  echo "  $CROSS_MARK install and sign in to Claude Code or Codex (see [6/7] above) before starting a chat"
fi
if [[ -n "$TMUX_WARNING" ]]; then
  echo "  $CROSS_MARK tmux unavailable: persistent terminal, pane inspection, and in-app updates won't work - $TMUX_WARNING"
else
  echo "  $CHECK_MARK tmux available"
fi
if [[ -n "$TAILSCALE_IP" ]]; then
  echo "  $CHECK_MARK reachable via Tailscale at $TAILSCALE_IP"
else
  echo "  $DOT_MARK optional: install and connect Tailscale to reach this server from another device or WiFi network: https://tailscale.com/download"
fi
if [[ "$TEAM_HUB_MODE" == "host" ]]; then
  echo
  if [[ "$TEAM_HUB_TRANSPORT" == "tailscale_serve" ]]; then
    echo "  ${COLOR_BOLD}Teamspace host${COLOR_RESET} $TEAM_HUB_URL"
    echo "  $CHECK_MARK server bound to the expected private Tailscale Serve URL"
    echo "  $DOT_MARK verify the separately managed Serve listener with: tailscale serve status --json"
  fi
  if [[ -n "$TEAM_HUB_DIRECT_IP_URL" ]]; then
    echo "  ${COLOR_BOLD}Teamspace Direct IP (unencrypted, advanced)${COLOR_RESET} $TEAM_HUB_DIRECT_IP_URL"
    echo "  $CROSS_MARK plaintext route: IP address is routing only, not identity or Tailscale attestation"
  fi
  echo "  ${COLOR_BOLD}Team Hub host operator commands${COLOR_RESET}"
  printf '  Bootstrap proof: PYTHONPATH='
  printf '%q ' "$CURRENT_LINK"
  printf '%q ' "$CURRENT_LINK/.venv/bin/python"
  printf '%s ' -m agentsdock_team_hub.cli bootstrap-proof --data-dir
  printf '%q\n' "$STATE_ROOT/team-hub"
  printf '  Device recovery: PYTHONPATH='
  printf '%q ' "$CURRENT_LINK"
  printf '%q ' "$CURRENT_LINK/.venv/bin/python"
  printf '%s ' -m agentsdock_team_hub.cli device-recovery --data-dir
  printf '%q ' "$STATE_ROOT/team-hub"
  printf '%s\n' '--email EMAIL --device-label LABEL'
fi
echo
if [[ -z "$EXPECTED_SERVER_IDENTITY" ]]; then
  printf 'AGENTSDOCK_SETUP_RESULT={"server_url":"%s","access_token":"%s","service":"%s","tailscale_ip":"%s","server_version":"%s"}\n' \
    "$SERVER_URL" "$TOKEN" "$SERVICE_KIND" "$TAILSCALE_IP" "$RELEASE_VERSION"
fi
