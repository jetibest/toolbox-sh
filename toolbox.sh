#!/bin/bash

# convert epoch (in seconds or milliseconds) to datetime stamp
# Usage: epoch-to-datetime [epoch]
epoch-to-datetime()
{
	local epoch_to_datetime_code='{if($0 ~ /^[0-9]+\s+/){if(strftime("%Y", $1) > strftime("%Y") + 100){modifier=1000;}else{modifier=1;}print strftime("%Y-%m-%d %H:%M:%S", $1/modifier);$1="";print $0}else{print $0}}'
	if [[ "$1" != "" ]]
	then
		echo "$1" | awk "$epoch_to_datetime_code"
	else
		awk "$epoch_to_datetime_code"
	fi
}

# remove all newlines, comments, and whitespaces from css
# Usage: minify-css <file.css >file.min.css
minify-css()
{
	cat "$@" | tr -d '\r' | tr -d '\n' | perl -pe 's/\/\*.*?\*\///g' | perl -pe 's/(:)\s*(.*?)\s*(;)|\s*([,{}])\s*|([^\s])|(\s)\s+/\1\2\3\4\5/g'
}

# transfer whole directory, copies symlinks as symlinks etc
#  -> add --del to also delete missing files for an exact sync
#  -> add --port [number] for a custom ssh-port
# Usage: rsync-dir [src] [dst] [extra options]
rsync-dir()
{
	local src="$1"
	local dst="$2"
	shift 2
	local extra=()
	while test $# -gt 0
	do
		if [[ "$1" == "--port" ]]
		then
			extra+=("-e")
			extra+=("ssh -p $2")
			shift
		else
			extra+=("$1")
		fi
		shift
	done
	rsync -acvAX -P "${extra[@]}" --partial --progress --inplace --no-whole-file $sshportarg "$src" "$dst"
}

# transfer a single (big) file with ability to abort/resume freely
# Usage: rsync-file [src] [dst]
rsync-file()
{
	rsync -Pa --checksum --inplace --no-whole-file -e 'ssh -p 22' "$1" "$2"
}

# create local SOCKS5 proxy using ssh tunnel to remote host
# Usage: ssh-tunnel-proxy-locally [remote user@host:port]
ssh-tunnel-proxy-locally()
{
	local proxyport=1337
	local remoteport=22
	local remoteconn="${1%:*}"
	local remoteport="${1##*:}"
	if [[ "$remoteport" =~ ^[0-9]+$ ]]
	then
		remoteport=" -p $remoteport"
	else
		remoteport=""
	fi
	echo "Setting up local SOCKS5 port at localhost:$proxyport"
	ssh -D $proxyport -q -C -N $remoteport "$remoteconn"
}

# create ssh tunnel at local endpoint to access remote machine locally
# Usage: ssh-tunnel-access-remote-locally [remote listen host:port] [local user@host:port] [local listen host:port]
ssh-tunnel-access-remote-locally()
{
	local remoteport="$1"
	if [[ "$remoteport" =~ ^[0-9]+$ ]]
	then
		remoteport="127.0.0.1:$remoteport"
	fi
	local connhost="${2%:*}"
	local connport="${2##*:}"
	if [[ "$connport" =~ ^[0-9]+$ ]]
	then
		connport=" -p $connport"
	else
		connport=""
	fi
	local localport="$3"
	if [[ "$localport"  =~ ^[0-9]+$ ]]
	then
		localport="127.0.0.1:$localport"
	fi
	ssh -N -L "$localport":"$remoteport" "$connhost"$connport
}

# create ssh tunnel at remote endpoint to access local machine remotely
# Usage: ssh-tunnel-access-local-remotely [local listen host:port] [remote user@host:port] [remote listen host:port]
ssh-tunnel-access-local-remotely()
{
	local localport="$1"
	if [[ "$localport"  =~ ^[0-9]+$ ]]
	then
		localport="127.0.0.1:$localport"
	fi
	local connhost="${2%:*}"
	local connport="${2##*:}"
	if [[ "$connport" =~ ^[0-9]+$ ]]
	then
		connport=" -p $connport"
	else
		connport=""
	fi
	local remoteport="$3"
	if [[ "$remoteport" =~ ^[0-9]+$ ]]
	then
		remoteport="127.0.0.1:$remoteport"
	fi
	ssh -o "ExitOnForwardFailure yes" -v "$connhost"$connport -N -R "$remoteport":"$localport"
}

# unzip file always automatically in a subdirectory of the same name
# Use -f or --force to force overwrite existing files, by default does not overwrite
unzip-autodetect-subfolder()
{
	local force_overwrite="-n"
	if [[ "$1" == "-f" ]] || [[ "$1" == "--force" ]]
	then
		force_overwrite="-o"
		shift
	fi
	
	local path="$1"
	
	if ! [ -f "$path" ]
	then
		echo "error: (Zip-)File not found: $path" >&2
		return 1
	fi
	
	local filename="$(basename "$path")"
	local subdir="${filename%.zip}"
	local directories="$(unzip -l "$filename" | sed -E -e '1,/^-+/d' -e '/^-+/,$d' -e 's/^\s*([^[:space:]]*\s+){3}//' -e 's/^[^/]*$/\//' -e 's/^([^/]+)[/].*$/\1/' | sort -u)"
	if [ $? -ne 0 ]
	then
		return 1
	fi
	
	if [[ "$directories" == "$subdir" ]]
	then
	        unzip $force_overwrite "$path"
	else
	        unzip $force_overwrite "$path" -d "$subdir/"
	fi
}

# zip a directory into a zipfile of the same name that is automatically placed next to the directory being zipped
zip-directory()
{
	local force_overwrite=false
	if [[ "$1" == "-f" ]] || [[ "$1" == "--force" ]]
	then
		force_overwrite=true
		shift
	fi
	
	local directory="${1%%/}"
	if ! [ -d "$directory" ]
	then
		echo "error: Directory not found: $directory" >&2
		return 1
	fi
	
	target_zipfile="../${directory}.zip"
	
	if $force_overwrite
	then
		zip -r - "$directory/" > "$target_zipfile"
	elif ! [ -e "$target_zipfile" ]
	then
		zip -r "$target_zipfile" "$directory/"
	else
		echo "error: Target zip-file exists ($target_zipfile), use -f or --force to override"
		return 1
	fi
}

# Automatically execute command as soon as file changes (if no command given, execute the file itself).
# Example usage: exec-onchange 'src/.*\.cpp' 'echo "The file {} changed."; ./compile.sh' & exec-onchange build/main
exec-onchange()
{
    local file="$1"
    shift
    
    # strip path
    local filename="${file##*/}"
    
    # strip filename
    local path="${file%/*}"
    if [ -z "$path" ]; then path="."; fi
    
    # catch a custom command
    local cmd="$@"
    local literalFlag=""
    if [ -z "$cmd" ]; then cmd="$path/$filename"; literalFlag="-Fx"; fi
    
    inotifywait -q --format '%f' -e close_write,moved_to -m "$path" |
    grep --line-buffered $literalFlag "$filename" |
    xargs -l -i /bin/bash -c "$cmd"
}

# View list of tcp ipv4 connections
# Usage: netstat-tcp-ipv4
netstat-tcp-ipv4()
{
	local local_host local_port remote_host remote_port inode pid ignore_header c0 c1 c2 c3 c4 c5 c6 c7 c8 c9
	cd /proc && { read ignore_header && while read c0 c1 c2 c3 c4 c5 c6 c7 c8 c9
	do
		local_host="${c1%:*}"
		local_host="$((16#${local_host:6:2})).$((16#${local_host:4:2})).$((16#${local_host:2:2})).$((16#${local_host:0:2}))"
		local_port="${c1#*:}"
		local_port="$((16#$local_port))"
		remote_host="${c2%:*}"
		remote_host="$((16#${remote_host:6:2})).$((16#${remote_host:4:2})).$((16#${remote_host:2:2})).$((16#${remote_host:0:2}))"
		remote_port="${c2#*:}"
		remote_port="$((16#$remote_port))"
		inode="${c9%% *}"
		pid="$(find */fd -type l -ilname 'socket:\['$inode'\]' -printf '%h' 2>/dev/null)"
		pid="${pid%/*}"
		echo "$local_host:$local_port -> $remote_host:$remote_port pid=$pid exe=$(find $pid/exe -maxdepth 0 -printf '%l' 2>/dev/null)"
	done; } </proc/net/tcp
}

# Encode stdin to friendly compressed stdout
# Usage: cat binary.file | copy-to-gzip-base64
copy-to-gzip-base64()
{
	gzip -c | base64 -w 0 && echo
}

# Decode stdin to original uncompressed stdout
# Usage: cat <<EOF | paste-from-base64-gzip >binary.file
paste-from-base64-gzip()
{
	base64 -d | gzip -d
}

# Copy to local clipboard (careful on ssh-sessions)
# Usage: echo some text | copy-to-clipboard; copy-to-clipboard < some.file
copy-to-clipboard()
{
	if [ -e /dev/clipboard ]; then cat >/dev/clipboard
	elif command -v xclip >/dev/null 2>/dev/null; then DISPLAY=:0 xclip -selection c
	elif command -v wl-copy >/dev/null 2>/dev/null; then wl-copy
	elif command -v pbcopy >/dev/null 2>/dev/null; then pbcopy
	elif command -v wclip >/dev/null 2>/dev/null; then wclip i
	else
		echo "error: no clipboard utility found" >&2
	fi
}

# Paste from local clipboard (careful on ssh-sessions)
# Usage: paste-from-clipboard > some.file
paste-from-clipboard()
{
	if [ -e /dev/clipboard ]; then cat </dev/clipboard
	elif command -v xclip >/dev/null 2>/dev/null; then DISPLAY=:0 xclip -o
	elif command -v wl-paste >/dev/null 2>/dev/null; then wl-paste
	elif command -v pbpaste >/dev/null 2>/dev/null; then pbpaste
	elif command -v wclip >/dev/null 2>/dev/null; then wclip o
	else
		echo "error: no clipboard utility found" >&2
	fi
}

# Get user specific tmp-directory, but fallback to ~/.cache/ (returns 1 if fallback is used), fallback is typically not in RAM
tmpdir-user()
{
	local path="$XDG_RUNTIME_DIR/"
	if ! [ -d $path ]
	then
		path="~/.cache/"
		if ! [ -d "$path" ]; then mkdir "$path"; fi
		echo "$path"
		return 1
	fi
	echo "$path"
}

# Get fingerprint from host (host defaults to localhost)
# Usage: ssh-fingerprint-md5 [hostname]
ssh-fingerprint-md5()
{
	# ssh-keyscan fails due to ipv6 if sshd only listens on ipv4, so fallback to -4 for ipv4
	local hostname="$1"
	if [ -z "$hostname" ]; then hostname="localhost"; fi
	ssh-keygen -l -E md5 -f <(ssh-keyscan "$hostname" 2>/dev/null || ssh-keyscan -4 "$hostname" 2>/dev/null)
}

ssh-setup-passwordless()
{
	if ! [ "$(ssh -o PreferredAuthentications=publickey -o PasswordAuthentication=no "$@" 'echo ok' 2>/dev/null)" = "ok" ]
	then
		# ask if we want to set it up now
		local answer
		read -p $'Looks like you will be asked for a password.\nWould you like to setup passwordless login now? [y/N] ' answer
		if [ "${answer:0:1}" = "y" ] || [ "${answer:0:1}" = "Y" ]
		then
			# check if we need to run keygen
			local keys=(~/.ssh/*.pub)
			if ! [ -e "${keys[0]}" ]
			then
				# question to overwrite is not answered, hence if already exists, will not do anything (correct behavior)
				ssh-keygen -t rsa -b 4096 -N '' <<<$'\n'
			fi
			ssh-copy-id "$@"
		fi
	fi
}

# SSH with local clipboard options
# Usage: ssh-with-toolbox [--sshd-port=51022] [--tunnel-port=51099] user@host [-p port]
#  --sshd-port    Custom port that runs the sshd-service on the current system, defaults to automatically parsing port from /etc/ssh/sshd_config (or 22 if not exists).
#  --tunnel-port  Set custom listen port for the reverse tunnel (defaults to 51099).
ssh-with-toolbox()
{
	local local_sshport=""
	if [[ "$1" == "--sshd-port="* ]]
	then
		local_sshport="${1##*=}"
		shift
	elif [[ "$1" == "--sshd-port" ]]
	then
		local_sshport="$2"
		shift 2
	fi
	
	local remote_sshport="51099"
	if [[ "$1" == "--tunnel-port="* ]]
	then
		remote_sshport="${1##*=}"
	elif [[ "$1" == "--tunnel-port" ]]
	then
		remote_sshport="$2"
		shift 2
	fi
	
	# ensure sshd is running
	if command -v systemctl >/dev/null 2>/dev/null && ! systemctl is-active --quiet sshd >/dev/null 2>/dev/null; then systemctl start sshd;
	elif [ -e /etc/init.d/sshd ] && ! /etc/init.d/sshd status >/dev/null 2>/dev/null; then /etc/init.d/sshd start;
	elif command -v service >/dev/null 2>/dev/null && ! service sshd status >/dev/null 2>/dev/null; then service sshd start;
	fi
	
	# grab local sshd port
	if [ -z "$local_sshport" ]
	then
		local_sshport="$(grep -E '^Port\s+[0-9]+$' /etc/ssh/sshd_config 2>/dev/null || echo 22)"
		local_sshport="${local_sshport##* }"
	fi
	
	local hostkeyalias="$(whoami)@$(hostname)"
	
	# install toolbox temporarily in user temp dir
	toolbox-install "$(tmpdir-user)toolbox.sh"
	
	# check if we want to setup passwordless login upon connecting
	ssh-setup-passwordless "$@"
	
	# from the newly opened shell at remote machine, we should be able to call tunnel-open, enter password, and then keep the ssh in background with separate FD's
	# tunnel-command() { tunnel-command-at "'"'"'"$__toolbox_tunnel_name"'"'"'" "$*"; }; 
	local cmd='
	__toolbox_tunnel_name=(tunnel-$(date +'"'"'%s%N'"'"') '"${__toolbox_tunnel_name[@]}"')
	__toolbox_tunnel_port=('"$remote_sshport"' '"${__toolbox_tunnel_port[@]}"')
	source <(curl -s "https://masteryeti.com/toolbox/toolbox.sh") && 
	toolbox-install "$(tmpdir-user)toolbox.sh" &&
	echo "Connected to ssh server. Opening reverse toolbox tunnel..." &&
	tunnel-open "'"$(whoami)"'@127.0.0.1:${__toolbox_tunnel_port[0]}" "${__toolbox_tunnel_name[0]}" "'"$hostkeyalias"'" &&
	$SHELL --init-file <(echo '"'"'source '"'"'"$(tmpdir-user)toolbox.sh"'"'"' || echo "warning: Could not load toolbox."; __toolbox_tunnel_name=('"'"'${__toolbox_tunnel_name[@]}'"'"'); __toolbox_tunnel_port=('"'"'${__toolbox_tunnel_port[@]}'"'"'); source ~/.bashrc;'"'"') -i;
	tunnel-close "${__toolbox_tunnel_name[0]}"'
	ssh -t -R "127.0.0.1:$remote_sshport:127.0.0.1:$local_sshport" "$@" "$cmd"
}

tunnel-trace()
{
	echo "$(whoami)@$(hostname):$(pwd)"
	if [ -n "${__toolbox_tunnel_name[0]}" ]
	then
		tunnel-command "tunnel-trace" || echo "tunnel command failed, but name: '${__toolbox_tunnel_name[@]}'"
	fi
}

# Create an ssh-connection and keep open in background (use with: tunnel-command, tunnel-close)
# Usage: tunnel-open [user@host:port] [name]
tunnel-open()
{
	local host="${1%:*}"
	local port="${1##*:}"
	if [[ "$host" = "$1" && "$host" =~ ^[0-9]+$ ]]; then host=""; port="$1"; fi
	if [ -z "$host" ]; then host="$(whoami)"; fi
	if [ -n "${host/*@*/}" ]; then host="$host@127.0.0.1"; fi
	if ! [[ "$port" =~ ^[0-9]+$ ]]; then port="22"; fi
	local tmpdir="$(tmpdir-user)"
	local tmpfilename="$2"
	if [ -z "$tmpfilename" ]; then tmpfilename="${__toolbox_tunnel_name[0]}"; fi
	if [ -z "$tmpfilename" ]; then tmpfilename=".toolbox-tunnel"; fi
	if [ -e "$tmpfilename" ] && [ "${tmpfilename:0:1}" = "/" ]; then tmpdir=""; fi
	local tmpfile="${tmpdir}${tmpfilename}.ssh"
	echo "$host" >"${tmpdir}${tmpfilename}.host"
	echo "$port" >"${tmpdir}${tmpfilename}.port"
	
	local hostkeyalias="$3"
	
	# we may automatically detect that ssh is connecting using a password, and automatically ask to run ssh-copy-id
	ssh-setup-passwordless -o HostKeyAlias="$hostkeyalias" -p "$port" "$host"
	
	if ! [ -e "$tmpfile" ]
	then
		ssh -nNf -o HostKeyAlias="$hostkeyalias" -o "ControlMaster=yes" -o "ControlPath=$tmpfile" -p "$port" "$host"
	else
		echo "warning: tunnel-open: ControlPath ($tmpfile) already exists." >&2
	fi
}

tunnel-close()
{
	local tmpfilename="$1"
	local tmpdir="$(tmpdir-user)"
	if [ -z "$tmpfilename" ]; then tmpfilename="${__toolbox_tunnel_name[0]}"; fi
	if [ -z "$tmpfilename" ]; then tmpfilename=".toolbox-tunnel"; fi
	if [ -e "$tmpfilename" ] && [ "${tmpfilename:0:1}" = "/" ]; then tmpdir=""; fi
	local host="$(cat "${tmpdir}${tmpfilename}.host")"
	local port="$(cat "${tmpdir}${tmpfilename}.port")"
	local sshfile="${tmpdir}${tmpfilename}.ssh"
	ssh -O exit -o "ControlPath=$sshfile" -p "$port" "$user"
	rm -f "$sshfile" 2>/dev/null
	rm -f "${tmpdir}${tmpfilename}.host" 2>/dev/null
	rm -f "${tmpdir}${tmpfilename}.port" 2>/dev/null
}

tunnel-command-at()
{
	# TODO: we can also just get user/port/sshfile from the process-list
	local tmpfilename="$1"
	shift
	local tmpdir="$(tmpdir-user)"
	if [ -e "$tmpfilename" ] && [ "${tmpfilename:0:1}" = "/" ]; then tmpdir=""; fi
	local host="$(cat "${tmpdir}${tmpfilename}.host")"
	local port="$(cat "${tmpdir}${tmpfilename}.port")"
	local sshfile="${tmpdir}${tmpfilename}.ssh"
	if [ "$port" = "" ]; then return 1; fi
	local cmd='
		source "$XDG_RUNTIME_DIR/toolbox.sh" || source "~/.cache/toolbox.sh";
		__toolbox_tunnel_name=('"${__toolbox_tunnel_name[@]:1}"');
		__toolbox_tunnel_port=('"${__toolbox_tunnel_port[@]:1}"');
		 '"$*"
	ssh -o "ControlPath=$sshfile" -p "$port" "$host" "$cmd"
}

# 
# Usage: echo "hello" | tunnel-command [-n 1] 'cat >/tmp/test.txt'
#   -n [0-9]+   Number of recursive tunnel hops, defaults to 1.
tunnel-command()
{
	local n="1"
	if [[ "$1" == "-n" ]]
	then
		shift
		if [[ "$1" =~ ^[0-9]+$ ]]
		then
			n="$(($1 - 1))"
			shift
		else
			# no number of hops given, =infinite
			n=""
		fi
	fi
	if [ "$1" = "--" ]; then shift; fi
	
	local cmd="$*"
	if [ "$n" = "0" ]
	then
		eval "$cmd"
		return $?
	elif [ -z "$n" ]
	then
		# infinite hops, check if last hop
		if [ -z "${__toolbox_tunnel_name[0]}" ]
		then
			eval "$cmd"
			return $?
		else
			cmd="tunnel-command -n -- '$*'"
		fi
	elif [ $n -gt 1 ]
	then
		cmd="tunnel-command -n $n '$*'"
	fi
	local tmpfilename="${__toolbox_tunnel_name[0]}"
	if [ -z "$tmpfilename" ]; then tmpfilename=".toolbox-tunnel"; fi
	tunnel-command-at "$tmpfilename" "$cmd"
}

# Usage: echo some text | copy-to-clipboard-tunnel
copy-to-tunnel-origin()
{
	tunnel-command -n copy-to-clipboard
}

# Usage: paste-from-clipboard-tunnel > some.file
paste-from-tunnel-origin()
{
	tunnel-command -n paste-from-clipboard
}

# Install latest version of toolbox in /bin/toolbox.sh, for using source /bin/toolbox.sh
# Usage: toolbox-install [custom path]
toolbox-install()
{
	local install_path="$1"
	if [ -z "$install_path" ]; then install_path="/bin/"; fi
	if [ -d "$install_path" ]; then install_path="${install_path%/}/toolbox.sh"; fi
	if ! touch "$install_path" 2>/dev/null
	then
		su -c 'curl -s https://masteryeti.com/toolbox/toolbox.sh >"'"$install_path"'"' && source "$install_path"
	else
		curl -s https://masteryeti.com/toolbox/toolbox.sh >"$install_path" && source "$install_path"
	fi
}

toolbox-version()
{
	date -r "${BASH_SOURCE[0]}"
}
