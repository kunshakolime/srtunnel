# Ssh tunneling 

A minimal setup for running Dropbear SSH server in an isolated Alpine Linux chroot environment for tunneling purposes.

## Setup and Start (you need to run these as root!!!)

```bash
# Create workspace
mkdir websocket && cd websocket
mkdir bin

# Download and extract Alpine minirootfs
curl -O https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/x86_64/alpine-minirootfs-3.23.2-x86_64.tar.gz
tar -xzf alpine-minirootfs-3.23.2-x86_64.tar.gz -C ./bin
rm -f alpine-minirootfs-3.23.2-x86_64.tar.gz
```
# Download Dropbear binaries
```bash
mkdir ./bin/etc/dropbear
curl -L https://raw.githubusercontent.com/kunshakolime/kunsh-tunnel/main/dropbear/2019.78/alpine/amd64/dropbear -o ./bin/usr/sbin/dropbear
curl -L https://raw.githubusercontent.com/kunshakolime/kunsh-tunnel/main/dropbear/2019.78/alpine/amd64/dropbearkey -o ./bin/usr/sbin/dropbearkey
curl -L https://raw.githubusercontent.com/kunshakolime/kunsh-tunnel/main/dropbear/2019.78/alpine/amd64/dropbearconvert -o ./bin/usr/sbin/dropbearconvert
curl -L https://raw.githubusercontent.com/kunshakolime/kunsh-tunnel/main/dropbear/2019.78/alpine/amd64/dbclient -o ./bin/usr/sbin/dbclient
chmod +x ./bin/usr/sbin/dropbear
chmod +x ./bin/usr/sbin/dropbearkey
chmod +x ./bin/usr/sbin/dropbearconvert
chmod +x ./bin/usr/sbin/dbclient
```
# Set up urandom and nologin shell
```bash
touch ./bin/dev/urandom
mount --bind /dev/urandom ./bin/dev/urandom
echo "/sbin/nologin" >> ./bin/etc/shells
```
# Create user and start server
```bash
chroot ./bin ./bin/sh -l
```
```bash
adduser -s /sbin/nologin -H sshfwd
```
```bash
dropbear -EFR -p 23 -W 65536
```

Connect with: `ssh sshfwd@localhost -p 23`
(you won't be let interactively but you can use an ssh tunneling app)

## Cleanup

```bash
umount ./bin/dev/urandom
cd ..
rm -rf websocket/
```
