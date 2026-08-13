#!/usr/bin/env bash
set -euo pipefail

readonly EXIT_SKIP=77
readonly SOCKET_WAIT_ATTEMPTS=500
readonly SOCKET_WAIT_INTERVAL=0.01

fail() {
  printf 'linux-service-lifecycle: %s\n' "$*" >&2
  exit 1
}

skip() {
  printf 'linux-service-lifecycle: SKIP: %s\n' "$*" >&2
  exit "$EXIT_SKIP"
}

usage() {
  printf 'usage: %s --daemon /absolute/action-brokerd --client /absolute/lifecycletestclient --issuer /absolute/issue_lifecycle_approval\n' "$0" >&2
}

daemon_source=''
client_source=''
issuer_source=''
while (($# > 0)); do
  case "$1" in
    --daemon)
      (($# >= 2)) || { usage; exit 2; }
      daemon_source=$2
      shift 2
      ;;
    --client)
      (($# >= 2)) || { usage; exit 2; }
      client_source=$2
      shift 2
      ;;
    --issuer)
      (($# >= 2)) || { usage; exit 2; }
      issuer_source=$2
      shift 2
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

[[ $(uname -s) == Linux ]] || skip 'requires Linux kernel peer credentials and privilege evidence'
((EUID == 0)) || skip 'requires root only to establish isolated numeric test identities'
[[ $daemon_source == /* && -f $daemon_source && ! -L $daemon_source ]] || fail 'daemon must be an absolute regular non-symlink file'
[[ $client_source == /* && -f $client_source && ! -L $client_source ]] || fail 'client must be an absolute regular non-symlink file'
[[ $issuer_source == /* && -f $issuer_source && ! -L $issuer_source ]] || fail 'approval issuer must be an absolute regular non-symlink file'

for required_command in bwrap env getent install jq pgrep prlimit setpriv sha256sum stat; do
  command -v "$required_command" >/dev/null 2>&1 || skip "missing required command: $required_command"
done

test_root=$(mktemp -d /tmp/action-broker-lifecycle.XXXXXX)
case "$test_root" in
  /tmp/action-broker-lifecycle.*) ;;
  *) fail 'mktemp returned an unexpected path' ;;
esac
readonly test_root
chmod 0755 "$test_root"

daemon_pid=''
hold_pid=''
command_client_pid=''
cleanup() {
  if [[ -n $command_client_pid ]] && kill -0 "$command_client_pid" 2>/dev/null; then
    kill -TERM "$command_client_pid" 2>/dev/null || true
    wait "$command_client_pid" 2>/dev/null || true
  fi
  if [[ -n $hold_pid ]] && kill -0 "$hold_pid" 2>/dev/null; then
    kill -TERM "$hold_pid" 2>/dev/null || true
    wait "$hold_pid" 2>/dev/null || true
  fi
  if [[ -n $daemon_pid ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    kill -TERM "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  if [[ ${ACTION_BROKER_LIFECYCLE_PRESERVE_ON_FAILURE:-0} != 1 ]]; then
    find "$test_root" -depth -delete 2>/dev/null || true
  else
    printf 'linux-service-lifecycle: preserving failed fixture at %s\n' "$test_root" >&2
  fi
}
trap cleanup EXIT HUP INT TERM

id_is_unused() {
  local candidate=$1
  ! getent passwd "$candidate" >/dev/null 2>&1 && ! getent group "$candidate" >/dev/null 2>&1
}

next_unused_id() {
  local candidate=$1
  while ! id_is_unused "$candidate"; do
    ((candidate += 1))
    ((candidate <= 65000)) || fail 'no unused numeric identity is available'
  done
  printf '%s\n' "$candidate"
}

broker_uid=$(next_unused_id 61001)
broker_gid=$broker_uid
platform_uid=$(next_unused_id $((broker_uid + 1)))
ipc_gid=$(next_unused_id $((platform_uid + 1)))
unauthorized_uid=$(next_unused_id $((ipc_gid + 1)))
readonly broker_uid broker_gid platform_uid ipc_gid unauthorized_uid

bin_dir="$test_root/bin"
config_dir="$test_root/config"
state_dir="$test_root/state"
socket_dir="$test_root/run"
action_root="$test_root/action-root"
control_dir="$test_root/control"
mkdir -p "$bin_dir" "$config_dir" "$state_dir" "$socket_dir" "$action_root" "$control_dir"
install -o 0 -g 0 -m 0755 "$daemon_source" "$bin_dir/action-brokerd"
install -o 0 -g 0 -m 0755 "$client_source" "$bin_dir/lifecycletestclient"
install -o 0 -g 0 -m 0755 "$issuer_source" "$bin_dir/issue-lifecycle-approval"
chown "$broker_uid:$broker_gid" "$state_dir"
chmod 0700 "$state_dir"
chown "$broker_uid:$ipc_gid" "$socket_dir"
chmod 2750 "$socket_dir"
chown "$platform_uid:$ipc_gid" "$control_dir"
chmod 0700 "$control_dir"
chown 0:0 "$action_root"
chmod 0755 "$action_root"
printf 'lifecycle-ok\n' >"$action_root/probe.txt"
chown 0:0 "$action_root/probe.txt"
chmod 0644 "$action_root/probe.txt"

readonly socket_path="$socket_dir/action-broker.sock"
readonly config_path="$config_dir/action-broker.json"
readonly key_path="$config_dir/approval-public-key.hex"
readonly audit_path="$state_dir/audit.jsonl"
readonly event_path="$state_dir/agent-green.jsonl"
readonly daemon_log="$test_root/daemon.log"
readonly hold_marker="$control_dir/hold-ready"
readonly command_request="$control_dir/command-request.json"
readonly expired_command_request="$control_dir/expired-command-request.json"
readonly future_command_request="$control_dir/future-command-request.json"
readonly tampered_command_request="$control_dir/tampered-command-request.json"
readonly normalized_command_request="$test_root/normalized-command-request.json"
readonly command_request_id='018f47d2-60d2-7af0-bc35-2a1f7f5a6d02'

# This public key belongs only to the example fixture issuer. Production must
# never trust it; the corresponding test seed is absent from daemon config.
"$bin_dir/issue-lifecycle-approval" public-key >"$key_path"
chmod 0644 "$key_path"
chown 0:0 "$key_path"

bwrap_path=$(realpath "$(command -v bwrap)")
prlimit_path=$(realpath "$(command -v prlimit)")
sleep_path=$(realpath "$(type -P sleep)")
read -r bwrap_hash _ < <(sha256sum "$bwrap_path")
read -r prlimit_hash _ < <(sha256sum "$prlimit_path")
read -r sleep_hash _ < <(sha256sum "$sleep_path")

jq -n \
  --arg socket "$socket_path" \
  --argjson socket_gid "$ipc_gid" \
  --argjson platform_uid "$platform_uid" \
  --argjson broker_uid "$broker_uid" \
  --argjson broker_gid "$broker_gid" \
  --arg replay "$state_dir/replay.sqlite3" \
  --arg audit "$audit_path" \
  --arg events "$event_path" \
  --arg key "$key_path" \
  --arg action_root "$action_root" \
  --arg bwrap "$bwrap_path" \
  --arg bwrap_hash "$bwrap_hash" \
  --arg prlimit "$prlimit_path" \
  --arg prlimit_hash "$prlimit_hash" \
  --arg sleep_path "$sleep_path" \
  --arg sleep_hash "$sleep_hash" \
  '{
    socket_path: $socket,
    socket_group_id: $socket_gid,
    platform_peers: [{uid: $platform_uid, user_id: "lifecycle-user", agent_id: "lifecycle-agent"}],
    privilege_profile: {
      expected_user_id: $broker_uid,
      expected_group_id: $broker_gid,
      allowed_supplementary_group_ids: []
    },
    replay_database_path: $replay,
    replay_ledger: {maximum_entries: 1024, retention_after_expiration_seconds: 3600},
    audit_log_path: $audit,
    audit_initial_previous_hash: null,
    agent_green_event_spool_path: $events,
    agent_green_event_spool_maximum_bytes: 1048576,
    approval_keys: [{
      key_id: "lifecycle-test-key",
      public_key_path: $key,
      active_from_unix_seconds: 0,
      retire_at_unix_seconds: null,
      revoke_at_unix_seconds: null
    }],
    approval_verifier: {maximum_ttl_seconds: 300, allowed_clock_skew_seconds: 5, maximum_payload_bytes: 16384},
    policy: {
      grants: [{user_id: "lifecycle-user", agent_id: "lifecycle-agent", permissions: ["filesystem_read", "command_execute_approved"]}],
      disabled_capabilities: []
    },
    filesystem: {roots: [{root_id: "lifecycle", path: $action_root, readable: true, writable: false, deletable: false}]},
    commands: {
      sandbox_backend: {
        type: "linux_bubblewrap",
        executable_path: $bwrap,
        executable_sha256: $bwrap_hash,
        resource_limiter_path: $prlimit,
        resource_limiter_sha256: $prlimit_hash
      },
      programs: [{
        program_id: "lifecycle-sleep",
        executable_path: $sleep_path,
        executable_sha256: $sleep_hash,
        argument_patterns: ["^[0-9]{1,2}$"],
        environment_patterns: {},
        working_directory_access: "read_only",
        maximum_timeout_milliseconds: 30000
      }]
    },
    network: {
      destinations: [{host: "example.com", schemes: ["https"], ports: [443], allow_private_addresses: false, allow_loopback: false}],
      maximum_redirects: 0
    },
    process_inspection: {enabled: false, allowed_user_ids: [], maximum_entries: 32},
    transport_limits: {
      maximum_open_connections: 8,
      maximum_open_connections_per_peer: 4,
      worker_threads: 2,
      maximum_queued_connections: 4,
      maximum_queue_wait_milliseconds: 1000,
      maximum_authentication_failures_per_window: 16,
      authentication_failure_window_milliseconds: 1000,
      maximum_protocol_failures_per_window: 16,
      protocol_failure_window_milliseconds: 1000,
      shutdown_grace_milliseconds: 3000,
      read_timeout_milliseconds: 1000,
      write_timeout_milliseconds: 1000
    },
    broker_limits: {
      maximum_concurrent_actions: 2,
      maximum_concurrent_actions_per_principal: 1,
      maximum_concurrent_actions_per_capability: 1,
      concurrency_wait_milliseconds: 1000
    }
  }' >"$config_path"
chmod 0644 "$config_path"
chown 0:0 "$config_path"

wait_for_socket() {
  local attempt
  for ((attempt = 0; attempt < SOCKET_WAIT_ATTEMPTS; attempt += 1)); do
    [[ -S $socket_path ]] && return 0
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
      sed -n '1,160p' "$daemon_log" >&2 || true
      fail 'daemon exited before creating its socket'
    fi
    sleep "$SOCKET_WAIT_INTERVAL"
  done
  fail 'daemon did not create its socket before the readiness deadline'
}

wait_for_file() {
  local path=$1
  local attempt
  for ((attempt = 0; attempt < SOCKET_WAIT_ATTEMPTS; attempt += 1)); do
    [[ -f $path ]] && return 0
    sleep "$SOCKET_WAIT_INTERVAL"
  done
  fail "timed out waiting for $path"
}

wait_for_command_start() {
  local attempt
  for ((attempt = 0; attempt < SOCKET_WAIT_ATTEMPTS; attempt += 1)); do
    if jq -e --arg request_id "$command_request_id" \
      'select(.event.request_id == $request_id and .event.phase == "started" and .event.capability == "ExecuteApprovedCommand")' \
      "$audit_path" >/dev/null 2>&1; then
      return 0
    fi
    sleep "$SOCKET_WAIT_INTERVAL"
  done
  fail 'approved command did not produce durable start audit evidence'
}

wait_for_sleep_process() {
  local attempt
  for ((attempt = 0; attempt < SOCKET_WAIT_ATTEMPTS; attempt += 1)); do
    if pgrep -u "$broker_uid" -x sleep >/dev/null 2>&1; then
      return 0
    fi
    sleep "$SOCKET_WAIT_INTERVAL"
  done
  fail 'sandboxed approved command did not become observable'
}

start_daemon() {
  : >"$daemon_log"
  setpriv \
    --reuid "$broker_uid" \
    --regid "$broker_gid" \
    --clear-groups \
    --no-new-privs \
    env -i "$bin_dir/action-brokerd" serve --config "$config_path" \
    >>"$daemon_log" 2>&1 &
  daemon_pid=$!
  wait_for_socket
  [[ $(stat -c '%u:%g:%a' "$socket_path") == "$broker_uid:$ipc_gid:660" ]] || fail 'socket owner, group, or mode is incorrect'
}

stop_daemon_cleanly() {
  kill -TERM "$daemon_pid"
  local status=0
  wait "$daemon_pid" || status=$?
  daemon_pid=''
  ((status == 0)) || {
    sed -n '1,160p' "$daemon_log" >&2 || true
    fail "daemon did not complete its first-signal drain (status $status)"
  }
  [[ ! -e $socket_path ]] || fail 'daemon left its socket pathname after clean drain'
}

start_daemon

# A process with IPC group access but no configured UID must be rejected before
# any frame bytes are parsed and must produce mandatory Agent Green evidence.
unauthorized_marker="$control_dir/unauthorized-ready"
chown "$unauthorized_uid:$ipc_gid" "$control_dir"
setpriv --reuid "$unauthorized_uid" --regid "$ipc_gid" --clear-groups \
  env -i "$bin_dir/lifecycletestclient" \
  --mode hold-incomplete-frame --socket "$socket_path" --broker-uid "$broker_uid" \
  --marker "$unauthorized_marker" --timeout 5s
chown "$platform_uid:$ipc_gid" "$control_dir"

setpriv --reuid "$platform_uid" --regid "$ipc_gid" --clear-groups \
  env -i "$bin_dir/lifecycletestclient" \
  --mode read --socket "$socket_path" --broker-uid "$broker_uid" \
  --root-id lifecycle --relative-path probe.txt --expected-content $'lifecycle-ok\n' --timeout 5s

# Submit a correctly signed approval whose validity window has not begun. The
# later requests deliberately reuse its ID and nonce, proving rejection did not
# consume the nonce.
setpriv --reuid "$platform_uid" --regid "$ipc_gid" --clear-groups \
  env -i "$bin_dir/issue-lifecycle-approval" future-request \
  "$command_request_id" lifecycle-sleep lifecycle . 30000 lifecycle-command-nonce-0001 \
  >"$future_command_request"
chown "$platform_uid:$ipc_gid" "$future_command_request"
chmod 0600 "$future_command_request"
setpriv --reuid "$platform_uid" --regid "$ipc_gid" --clear-groups \
  env -i "$bin_dir/lifecycletestclient" \
  --mode execute-and-expect-approval-expired --socket "$socket_path" --broker-uid "$broker_uid" \
  --request "$future_command_request" --timeout 5s
if pgrep -u "$broker_uid" -x sleep >/dev/null 2>&1; then
  fail 'not-yet-valid approval started a sandboxed command'
fi
audit_summary=$("$bin_dir/action-brokerd" verify-audit --path "$audit_path")
jq -e '.record_count == 2 and (.head_sha256 | length == 64)' <<<"$audit_summary" >/dev/null

# Submit a correctly signed but expired approval next. The valid request still
# reuses the same request ID and nonce, proving expiry also does not consume it.
setpriv --reuid "$platform_uid" --regid "$ipc_gid" --clear-groups \
  env -i "$bin_dir/issue-lifecycle-approval" expired-request \
  "$command_request_id" lifecycle-sleep lifecycle . 30000 lifecycle-command-nonce-0001 \
  >"$expired_command_request"
chown "$platform_uid:$ipc_gid" "$expired_command_request"
chmod 0600 "$expired_command_request"
setpriv --reuid "$platform_uid" --regid "$ipc_gid" --clear-groups \
  env -i "$bin_dir/lifecycletestclient" \
  --mode execute-and-expect-approval-expired --socket "$socket_path" --broker-uid "$broker_uid" \
  --request "$expired_command_request" --timeout 5s
if pgrep -u "$broker_uid" -x sleep >/dev/null 2>&1; then
  fail 'expired approval started a sandboxed command'
fi
jq -e -s --arg request_id "$command_request_id" '
  [.[] | select(.kind == "expired_approval" and .request_id == $request_id and
    .reason_code == "approval_expired" and .user_id == "lifecycle-user" and
    .agent_id == "lifecycle-agent" and .task_id == "lifecycle-command-cancellation" and
    .capability == "ExecuteApprovedCommand" and (.target_digest | length == 64))] | length == 2
' "$event_path" >/dev/null
audit_summary=$("$bin_dir/action-brokerd" verify-audit --path "$audit_path")
jq -e '.record_count == 2 and (.head_sha256 | length == 64)' <<<"$audit_summary" >/dev/null

# Issue an exact currently valid approval using the same Rust request and JCS
# model as the broker. The private test seed exists only in the fixture binary.
setpriv --reuid "$platform_uid" --regid "$ipc_gid" --clear-groups \
  env -i "$bin_dir/issue-lifecycle-approval" request \
  "$command_request_id" lifecycle-sleep lifecycle . 30000 lifecycle-command-nonce-0001 \
  >"$command_request"
chown "$platform_uid:$ipc_gid" "$command_request"
chmod 0600 "$command_request"
"$bin_dir/issue-lifecycle-approval" verify "$command_request"
setpriv --reuid "$platform_uid" --regid "$ipc_gid" --clear-groups \
  env -i "$bin_dir/lifecycletestclient" \
  --mode normalize-request --request "$command_request" \
  >"$normalized_command_request"
"$bin_dir/issue-lifecycle-approval" verify "$normalized_command_request"
jq '.action.arguments.arguments[0] = "29"' "$command_request" >"$tampered_command_request"
chown "$platform_uid:$ipc_gid" "$tampered_command_request"
chmod 0600 "$tampered_command_request"
if "$bin_dir/issue-lifecycle-approval" verify "$tampered_command_request" 2>/dev/null; then
  fail 'fixture verifier accepted arguments that do not match the signed approval'
fi
setpriv --reuid "$platform_uid" --regid "$ipc_gid" --clear-groups \
  env -i "$bin_dir/lifecycletestclient" \
  --mode execute-and-expect-approval-invalid --socket "$socket_path" --broker-uid "$broker_uid" \
  --request "$tampered_command_request" --timeout 5s
if pgrep -u "$broker_uid" -x sleep >/dev/null 2>&1; then
  fail 'approval-tampered request started a sandboxed command'
fi
jq -e -s --arg request_id "$command_request_id" '
  any(.[]; .kind == "approval_tampering" and .request_id == $request_id and
    .reason_code == "approval_invalid" and .user_id == "lifecycle-user" and
    .agent_id == "lifecycle-agent" and .task_id == "lifecycle-command-cancellation" and
    .capability == "ExecuteApprovedCommand" and (.target_digest | length == 64))
' "$event_path" >/dev/null
audit_summary=$("$bin_dir/action-brokerd" verify-audit --path "$audit_path")
jq -e '.record_count == 2 and (.head_sha256 | length == 64)' <<<"$audit_summary" >/dev/null
if pgrep -u "$broker_uid" -x sleep >/dev/null 2>&1; then
  fail 'broker test UID already owns a sleep process'
fi
setpriv --reuid "$platform_uid" --regid "$ipc_gid" --clear-groups \
  env -i "$bin_dir/lifecycletestclient" \
  --mode execute-and-expect-cancel --socket "$socket_path" --broker-uid "$broker_uid" \
  --request "$command_request" --timeout 10s &
command_client_pid=$!
wait_for_command_start
wait_for_sleep_process
stop_daemon_cleanly
wait "$command_client_pid"
command_client_pid=''
if pgrep -u "$broker_uid" -x sleep >/dev/null 2>&1; then
  fail 'sandboxed approved command survived broker shutdown'
fi
jq -e -s --arg request_id "$command_request_id" '
  any(.[]; .event.request_id == $request_id and .event.phase == "started" and
    .event.approval.required == true and .event.approval.approval_type == "ElevatedUser" and
    .event.approval.key_id == "lifecycle-test-key") and
  any(.[]; .event.request_id == $request_id and .event.phase == "finished" and
    .event.error_code == "cancelled")
' "$audit_path" >/dev/null

# Reopen the durable replay ledger, submit the exact consumed token again, and
# require a broker-confirmed denial before any second command or audit start.
start_daemon
setpriv --reuid "$platform_uid" --regid "$ipc_gid" --clear-groups \
  env -i "$bin_dir/lifecycletestclient" \
  --mode execute-and-expect-replay --socket "$socket_path" --broker-uid "$broker_uid" \
  --request "$command_request" --timeout 5s
if pgrep -u "$broker_uid" -x sleep >/dev/null 2>&1; then
  fail 'replayed approval started a sandboxed command'
fi
jq -e -s --arg request_id "$command_request_id" '
  any(.[]; .kind == "replayed_approval" and .request_id == $request_id and
    .reason_code == "approval_replayed" and .user_id == "lifecycle-user" and
    .agent_id == "lifecycle-agent" and .task_id == "lifecycle-command-cancellation" and
    .capability == "ExecuteApprovedCommand" and (.target_digest | length == 64))
' "$event_path" >/dev/null
audit_summary=$("$bin_dir/action-brokerd" verify-audit --path "$audit_path")
jq -e '.record_count == 4 and (.head_sha256 | length == 64)' <<<"$audit_summary" >/dev/null

# Hold one authenticated worker in the real framed-read path, then request a
# first-signal shutdown. The configured read deadline is shorter than the drain
# grace, so the connection is classified, recorded, and closed before exit.
setpriv --reuid "$platform_uid" --regid "$ipc_gid" --clear-groups \
  env -i "$bin_dir/lifecycletestclient" \
  --mode hold-incomplete-frame --socket "$socket_path" --broker-uid "$broker_uid" \
  --marker "$hold_marker" --timeout 5s &
hold_pid=$!
wait_for_file "$hold_marker"
stop_daemon_cleanly
wait "$hold_pid"
hold_pid=''

jq -e -s 'any(.[]; .kind == "permission_bypass_attempt" and .reason_code == "unauthorized_platform_peer")' "$event_path" >/dev/null
jq -e -s 'any(.[]; .kind == "resource_abuse_pattern" and .reason_code == "request_frame_incomplete")' "$event_path" >/dev/null
audit_summary=$("$bin_dir/action-brokerd" verify-audit --path "$audit_path")
jq -e '.record_count == 4 and (.head_sha256 | length == 64)' <<<"$audit_summary" >/dev/null

# Reopen the same replay ledger, audit chain, and Agent Green spool, then prove
# that a second clean lifecycle can bind and remove the same socket pathname.
start_daemon
stop_daemon_cleanly

printf 'linux-service-lifecycle: PASS\n'
