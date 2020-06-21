# Usage

To install, run:
```bash
source <(curl -s https://masteryeti.com/toolbox/toolbox.sh)
```

To inspect the contents of a function, run:
```bash
type [function]
```

# Functions
`epoch-to-datetime [epoch]`
Convert epoch (in seconds or milliseconds) to datetime stamp.

`minify-css`
Simple minify CSS (CascadingStyleSheet) from stdin to stdout.

`rsync-dir [src] [dst]`
Copy whole directory from `src` to `dst` using rsync, possible to interrupt with CTRL+C and continue at any time later.

`rsync-file [src] [dst]`
Copy a single file from `src` to `dst` using rsync, possible to interrupt with CTRL+C and continue at any time later.

`ssh-tunnel-proxy-locally [remote-user@remote-host:port]`
Create a local SOCKS5 proxy using ssh.

`ssh-tunnel-access-remote-locally [remote port] [user@host:port] [local port]`
Create a forward ssh-tunnel.
Default listen host is `127.0.0.1`, but prepend port with `0.0.0.0:`, to make the port publicly available.

`ssh-tunnel-access-local-remotely [local port] [user@host:port] [remote port]`
Create a reverse ssh-tunnel.
Default listen host is `127.0.0.1`, but prepend port with `0.0.0.0:`, to make the port publicly available.

`unzip-autodetect-subfolder [--force,-f] [zip-file]`
Unzip a zip-file in a directory of the same name (without '.zip').
Directory is always placed next to the zip-file being unzipped.
Use `--force` or `-f` to overwrite any existing files.

`zip-directory` [--force,-f]`
Zip a directory into a zip-file of the same name (with '.zip').
Zip-file is always placed next to the directory being zipped.
Use `--force` or `-f` to overwrite any existing zip-file.

`exec-onchange '[regex]' [command]`
Wait until a file (that matches the regex) was stored or written, and consequently execute a command.
If only one parameter, then wait until an executable file (literal match) was stored or written, and then execute it.
Will keep running until terminated (i.e. CTRL+C).

`netstat-tcp-ipv4`
Simpler version of netstat using `/proc`.

`copy-to-gzip-base64`
Encode stdin to friendly compressed stdout.

`paste-from-base64-gzip`
Decode stdin to original uncompressed stdout.

`copy-to-clipboard`
Writes stdin to clipboard. Automatically finds the right tool.

`paste-from-clipboard`
Pastes clipboard to stdout. Automatically finds the right tool.

`ssh-setup-passwordless [-p port] [user@host]`
Interactively asks to run ssh-copy-id.
But only after a dummy ssh-connection failed to authenticate using only publickey and not password.
Automatically creates an RSA 4096-bit key with empty passphrase if not exists.

`ssh-with-toolbox [-p port] [user@host]`
Run ssh enhanced with toolbox.
Keeps a reverse connection open, to enable a bi-directional tunnel functionality using `tunnel-command`.
May be used over multiple connections, use `tunnel-trace` to view hops.

`tunnel-trace`
When connected through `ssh-with-toolbox`:
View the SSH connections path (list each hop).

`tunnel-command [-n #hops] [command] [arg1] [arg2...]`
When connected through `ssh-with-toolbox`:
Run a command on the client, possibly skipping over multiple hops using `-n`.
If `#hops` is zero, runs command with args directly in local shell.
If `#hops` is not given, runs command with args on original client (the first one that called `ssh-with-toolbox`).

`copy-to-tunnel-origin`
When connected through `ssh-with-toolbox`:
Copy stdin to origin clipboard.

`paste-from-tunnel-origin`
When connected through `ssh-with-toolbox`:
Paste origin clipboard to stdout.

`tunnel-open [user@host:port] [tunnel-identifier]`
Create an ssh-connection and keep it open in background (use with: tunnel-command, tunnel-close).
Tunnel-identifier is a unique string (no spaces or special characters), defaults to "`.toolbox-tunnel`".

`tunnel-close [tunnel-identifier]`
Close ssh-connection that is open in background.

`tunnel-command-at [tunnel-identifier] `

`toolbox-install [custom file]`
Install latest version of toolbox in /bin/toolbox.sh, for using `source /bin/toolbox.sh`.

`toolbox-version`
Gives datetime stamp of latest modification time of the toolbox shell script.
