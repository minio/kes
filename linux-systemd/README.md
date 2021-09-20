# Systemd service for MinIO KES server

Systemd script for MinIO KES server.

## Installation

1. Download KES binary from https://github.com/minio/kes/releases/ and store it under /usr/local/bin/. Systemd script expects from the binary name to be `kes`.

e.g.:
```
wget 'https://github.com/minio/kes/releases/download/v0.16.1/kes-linux-amd64'
sudo install kes-linux-amd64 /usr/local/bin/kes
```

2. Create a new user for KES service:

e.g.:

```
useradd kes-user -s /sbin/nologin
```

## Configuration

Download https://raw.githubusercontent.com/minio/kes/master/server-config.yaml under /etc/kes/config.yaml and edit it for your convenience. You can follow https://github.com/minio/kes/wiki/Configuration#config-file for more information about how to configure KES server.
 
## Systemctl

Download `kes.service` in  `/etc/systemd/system/`
```
( cd /etc/systemd/system/; curl -O https://raw.githubusercontent.com/minio/kes/master/linux-systemd/kes.service )

```
Note: If you want to bind to a port < 1024 with the service running as a regular user, you will need to add bind capability via the AmbientCapabilities directive in the kes.service file:

```
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

### Enable KES startup on boot
```
systemctl enable kes.service
```

### Disable KES service
```
systemctl disable kes.service
```

## Note

- Replace ``User=kes-user`` and ``Group=kes-user`` in kes.service file with the user name created in your local setup.
- `kes-user` needs to have read access to all files under /etc/kes/ directory.
