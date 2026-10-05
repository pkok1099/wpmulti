#!/usr/bin/env bash
set -e

# Connect to demo.wireguard.com with retry (GitHub Actions runners
# sometimes have transient network issues reaching the demo server).
for i in 1 2 3; do
    if exec 3<>/dev/tcp/demo.wireguard.com/42912; then
        echo "connected to demo.wireguard.com (attempt $i)"
        break
    fi
    echo "connection attempt $i failed, retrying in 5s..."
    sleep 5
    if [ "$i" = 3 ]; then
        echo "ERROR: cannot reach demo.wireguard.com:42912 after 3 attempts" >&2
        exit 1
    fi
done

privatekey="$(wg genkey)"
wg pubkey <<<"$privatekey" >&3
IFS=: read -r status server_pubkey server_port internal_ip <&3
[[ $status == OK ]]
cat >test.conf <<EOL
[Interface]
Address = $internal_ip/32
PrivateKey = $privatekey
DNS = 8.8.8.8

[Peer]
PublicKey = $server_pubkey
Endpoint = demo.wireguard.com:$server_port

[Socks5]
BindAddress = 127.0.0.1:64423

[http]
BindAddress = 127.0.0.1:64424

[http]
BindAddress = 127.0.0.1:64425
Username = peter
Password=<redacted>
EOL
