# fcp

`fcp` (**forward container ports**) is a small devcontainer bridge. Run the `fcp` binary on the host and inside a Linux container to:

- expose container TCP listeners on host `127.0.0.1` automatically;
- open URLs in the host browser from inside the container;
- mirror selected host Unix sockets into the container;
- inspect, restart, and stop the bridge from a CLI.

Originally inspired by [`devcontainer-bridge`](https://github.com/bradleybeddoes/devcontainer-bridge).

## Quick start

Build the binary on the host:

```bash
just build
```

Start the host daemon. This creates `~/.config/fcp/auth-token` if no token file is configured and the default file does not already exist.

```bash
./build/fcp-$(go env GOOS)-$(go env GOARCH) ensure
```

Build or copy a Linux `fcp` binary for the container, make the host auth token available there as a file, then start the container daemon:

```bash
# choose linux amd64 or linux arm64 to match the container
just build linux amd64

# copy build/fcp-linux-amd64 into the container as /usr/local/bin/fcp
# mount or copy ~/.config/fcp/auth-token from the host to /run/secrets/fcp-auth-token
# then, inside the container:
fcp container-daemon --host-addr host.docker.internal
```

Now start a service in the container, for example on port `3000`. `fcp` will bind the same port on host loopback when possible, or the next available port if that port is busy.

```bash
fcp status
# Container             Port   Host Port  Process      Since
# my-container          3000        3000  node         5s ago
```

Open a container URL in the host browser:

```bash
fcp open http://localhost:3000
```

If the host port differs from the container port, `fcp open` rewrites the URL before opening it.

## Build and install

```bash
just build              # build for the current OS/arch
just build linux arm64  # cross-compile one target
just build-all          # darwin-arm64, linux-arm64, linux-amd64
just test               # run tests
just check              # fmt + vet + test + lint
just install            # install as $(go env GOBIN)/fcp
```

Build artifacts are written to `build/fcp-<os>-<arch>`. Version, commit, and build date are embedded with Go ldflags.

## How it works

`fcp` has two long-running daemons:

1. **Host daemon**
   - listens on a control port (`19285`) and data port (`19286`);
   - accepts authenticated container registrations;
   - binds forwarded TCP ports on host loopback;
   - opens browser URLs with `open` on macOS, `xdg-open` on Linux, or `--browser-cmd`;
   - optionally scans and forwards host Unix sockets.

2. **Container daemon**
   - connects to the host daemon;
   - scans `/proc/net/tcp*` for listening TCP ports;
   - requests forwards for new listeners and removes them when listeners disappear;
   - carries proxied traffic back to the host daemon over the data port;
   - reconnects with exponential backoff if the host daemon restarts.

Data path for a forwarded TCP connection:

```text
host browser/client
  -> 127.0.0.1:<host-port>
  -> fcp host daemon
  -> fcp data connection
  -> fcp container daemon
  -> 127.0.0.1:<container-port>
```

## Common workflows

### Start, stop, and inspect the host daemon

```bash
fcp ensure          # start host daemon if needed
fcp status          # show active TCP and socket forwards
fcp status --json   # machine-readable status
fcp logs            # show ~/.config/fcp/daemon.log
fcp logs --follow   # follow daemon logs
fcp restart         # stop, then start again
fcp stop            # stop host daemon
```

Run the host daemon in the foreground for debugging:

```bash
fcp host-daemon --log-file /tmp/fcp-host.log
```

### Run inside a container

```bash
fcp container-daemon \
  --host-addr host.docker.internal \
  --exclude-ports 22,111,2049
```

Control and data ports are excluded automatically.

Useful flags:

| Flag | Default | Description |
|---|---:|---|
| `--host-addr` | auto | Host address or DNS name. Falls back to `host.docker.internal`, then the default gateway. |
| `--scan-interval` | `1000` | Port scan interval in milliseconds. Minimum effective interval is 100ms. |
| `--exclude-ports` | empty | Comma-separated container ports that should never be forwarded. |
| `--auth-token-file` | auto | File containing the shared token used to register with the host daemon. |
| `--log-file` | stderr | Write daemon logs to a file. |

### Open URLs on the host

From inside the container:

```bash
fcp open http://localhost:3000
```

For transparent `xdg-open` / `open` support inside the container, install shims into a directory that appears before system directories in `PATH`:

```bash
fcp install-open-shims --dir ~/.local/bin
export PATH="$HOME/.local/bin:$PATH"
export BROWSER=fcp-open # optional, for tools that use $BROWSER directly
```

This installs `fcp-open`, `xdg-open`, `open`, and `sensible-browser` symlinks to the `fcp` binary. When invoked with an HTTP(S) URL, the shim sends an open request to the host daemon.

Only `http://` and `https://` URLs are accepted. Standalone CLI open requests authenticate with the shared token, and open requests are rate-limited to 5 per second.

### Forward host Unix sockets into the container

Enable socket forwarding on the host daemon:

```bash
fcp host-daemon \
  --socket-forward /tmp/postgres/.s.PGSQL.5432:/run/fcp/postgres.sock
```

Prefer exact `--socket-forward host_path:container_path` rules. Forwarding Docker, containerd, Podman, BuildKit, Colima, Lima, Docker Desktop, or other runtime/admin sockets can grant container processes powerful host capabilities, including host filesystem access through the runtime. Those sockets require an explicit acknowledgment:

```bash
fcp host-daemon \
  --socket-forward /var/run/docker.sock:/run/fcp/docker.sock \
  --allow-sensitive-sockets
```

Legacy glob scanning remains available for advanced use. The host scans configured globs every 2 seconds and asks the container daemon to create mirror sockets under `--socket-container-path-prefix`. Derived mirror names include a stable short hash so sockets with the same basename do not collide:

| Host socket | Container prefix | Container mirror |
|---|---|---|
| `/tmp/a/api.sock` | `/run/fcp` | `/run/fcp/api.sock-<hash>` |
| `/tmp/b/api.sock` | `/run/fcp` | `/run/fcp/api.sock-<different-hash>` |

Recursive `**` globs require explicit acknowledgment:

```bash
fcp host-daemon \
  --socket-watch-paths "/run/**/*.sock" \
  --socket-container-path-prefix /run/fcp \
  --allow-recursive-socket-globs
```

Socket forwarding currently tracks up to 16 sockets. Use `--socket-scan-interval-ms` to change the scan interval, `--socket-scan-budget-ms` to bound recursive traversal time, or `--no-socket-forwarding` to disable it explicitly. Mirror socket permissions are `0600`; this does not sandbox other same-UID processes inside the container.

## Configuration

### Environment variables

| Variable | Default | Used by | Description |
|---|---:|---|---|
| `FCP_HOST` | auto | CLI, container daemon | Host address or DNS name. |
| `FCP_HOST_PORT` | `19285` | container daemon | Host control port. |
| `FCP_DATA_PORT` | `19286` | container daemon | Host data port. |
| `FCP_SCAN_INTERVAL_MS` | `1000` | container daemon | Port scan interval in milliseconds. |
| `FCP_AUTH_TOKEN_FILE` | empty | host, container, selected CLI commands | File containing the shared secret. |

### Authentication

Authentication uses a shared 32-byte random token encoded as 64 hex characters.

Host-side token resolution:

1. `--auth-token-file`
2. `FCP_AUTH_TOKEN_FILE`
3. `~/.config/fcp/auth-token` (auto-generated by `fcp ensure` or `fcp host-daemon`)

Container-side token resolution:

1. `--auth-token-file`
2. `FCP_AUTH_TOKEN_FILE`
3. `/run/secrets/fcp-auth-token`
4. `~/.config/fcp/auth-token`

Prefer token files, `FCP_AUTH_TOKEN_FILE`, or Docker-style secrets mounted at `/run/secrets/fcp-auth-token`. Token values are not accepted through CLI flags or environment variables because those surfaces are easier to expose through process inspection and diagnostics.

When `fcp ensure` or `fcp restart` starts the host daemon, token values are not placed in the child process argv. Auto-generated tokens are passed by token file path.

The token is required for container registration, daemon shutdown, and standalone control requests such as `status`, `open`, and `unforward`. Do not expose the control (`19285`) or data (`19286`) ports to untrusted networks.

### Host binding

By default, the host daemon binds control/data listeners to:

- `0.0.0.0` when Docker is detected, so containers can connect;
- `127.0.0.1` otherwise.

Override this with `--bind-addr`, or force loopback behavior with `--no-docker-detect`. Forwarded application ports are always bound on host loopback.

The daemon warns when listening on non-loopback addresses. `--no-auth` is refused on non-loopback binds unless `--unsafe-no-auth` is passed explicitly.

## Command reference

| Command | Purpose |
|---|---|
| `fcp ensure` | Start the host daemon in the background if it is not already reachable. |
| `fcp host-daemon` | Run the host daemon in the foreground. |
| `fcp container-daemon` | Run the container-side scanner and traffic proxy. |
| `fcp status [--json]` | List active TCP forwards and Unix socket mirrors. |
| `fcp open URL` | Ask the host daemon to open an HTTP(S) URL. |
| `fcp install-open-shims` | Install `fcp-open`, `xdg-open`, `open`, and `sensible-browser` shims. |
| `fcp logs [-f]` | Show or follow the default daemon log file. |
| `fcp restart` | Stop and then ensure the host daemon. |
| `fcp stop` | Stop the host daemon. |
| `fcp unforward PORT` | Remove an active forward by container port. |
| `fcp forward PORT` | Low-level manual forward request. It holds the registration until `Ctrl-C`, but does not replace `container-daemon` for real traffic proxying. |

Use `fcp <command> --help` for command-specific flags.

## Architecture

```text
fcp/
├── main.go              # entrypoint
├── internal/
│   ├── auth/            # token generation and resolution
│   ├── cli/             # cobra commands
│   ├── config/          # env and CLI configuration
│   ├── container/       # container daemon, port scanner, socket mirrors
│   ├── control/         # JSON-lines control connection
│   ├── host/            # host daemon, TCP forwards, browser and socket handling
│   ├── log/             # logging and log replay
│   └── protocol/        # wire message types
└── justfile             # build, test, lint recipes
```

The control protocol is JSON Lines over TCP. A separate data TCP connection is opened per proxied TCP or Unix-socket stream.

## License

This project is released under the Unlicense. See [`UNLICENSE`](UNLICENSE).
