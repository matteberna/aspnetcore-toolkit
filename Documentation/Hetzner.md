# Deployment Guide

## Assumptions

- You’re provisioning a VPS on **Hetzner**. Other providers may have different defaults.

- You're not changing the default port for SSH, which is 22.

- On **Windows**, you're using **MobaXTerm** for SSH and its convenient SFTP file browser.

- On **Linux/macOS**, you already have a recent OpenSSH client installed.

- Follow each step in order without skipping or reordering, because that might lead to configuration errors.

## Preparation

### Provision a VPS

- You're going to need a machine with at least 2 dedicated vCPUs and 8 GB RAM.

- Pick the most recent **Ubuntu LTS** distribution.

- You can optionally enable **IPv6** for free during creation.

- Enable **snapshot backups**, which give you easy rollback points in case something goes wrong.

###  Obtain & Secure SSH Credentials

- Download the SSH private key immediately after provisioning.

- On **Linux/macOS**, run:

  ```bash
  mkdir -p ~/.ssh
  chmod 700 ~/.ssh
  mv ~/Downloads/id_rsa ~/.ssh/hetzner_project_key
  mv ~/Downloads/id_rsa.pub ~/.ssh/hetzner_project_key.pub
  chmod 600 ~/.ssh/hetzner_project_key
  chmod 644 ~/.ssh/hetzner_project_key.pub
  ```

- On **Windows**, store the key  in an encrypted vault. If you don’t already use one, [KeePass](https://keepass.info/) and [Bitwarden](https://bitwarden.com/) both support storing files securely.

- On your first connection, verify the server’s host key fingerprint against the one shown in the Hetzner console, which is the string in the format `sha256:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`.

- Upload the `id_rsa.bak` to an off-site secure vault.

> **⚠️Caution:** This is a one-time download. Lose it, and you must contact Hetzner support or rebuild the server.

### Initialize Documentation Placeholders

- Before you run any scripts or generate config files, replace these everywhere:

| Placeholder      | Meaning                                                         | Example         |
|------------------|-----------------------------------------------------------------|-----------------|
| {{ProjectName}}  | The full project name in Pascal case (matches the C# solution)  | MyLatestProject |
| {{ProjectLabel}} | Short label for services and filenames (lowercase, single word) | project         |
| {{Domain}}       | Root domain (no protocols, www, or subdomains)                  | myproject.net   |
| {{SqlPassword}}  | A strong, randomly generated password for the database          | f7Hp!9Lk2$Qx    |
| {{IpAddress}}    | The server's public IPv4 address                                | 103.86.98.1     |

> **💡Tip:** Use your favorite editor’s "Find & Replace in Files" feature (typically Ctrl+Shift+F) for bulk swaps.

### Configure The SSH Client (Windows)

- Launch MobaXTerm.
- Add a new "Session → SSH" entry
- Remote Host: `{{IpAddress}}` , Specify username: `root`, Port: `22`
- Advanced SSH Settings → Use private key: point to your downloaded key

### Configure The SSH Client (macOS/Linux)

- Add to your `~/.ssh/config`:
  ```ssh
  Host {{ProjectLabel}}-prod
  HostName {{IpAddress}}
  User root
  ServerAliveInterval 60
  IdentitiesOnly yes
  StrictHostKeyChecking ask
  IdentityFile ~/.ssh/hetzner_project_key
  ```
-   Test the connection with `ssh {{ProjectLabel}}-prod`

## Initial System Configuration

### Create & Enable Swap

> **❓Why:** Swap prevents out-of-memory errors under load, but Ubuntu VPSes often ship without it.

- Run as root:
  ```bash
  fallocate -l 2G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
  echo 'vm.swappiness=10' >> /etc/sysctl.conf
  sysctl -p
  ```  
  This allocates a 2 GB swap file, restricts access, and sets the system to prefer RAM over swap.

### Set Hostname

- Set the machine's hostname to simplify logging and monitoring:
  ```bash
  hostnamectl set-hostname {{ProjectLabel}}-prod
  ```
- Edit the hosts file:
  ```bash
  nano /etc/hosts
  ```
  Update the `127.0.1.1` line to match `{{ProjectLabel}}-prod`

### Apply all updates

- Patch the system:
  ```bash
  apt update && apt full-upgrade -y
  ```

- Reboot and reconnect:
  ```bash
  reboot
  ```

- Verify that the swap is active after the reboot:
  ```bash
  free -m
  ```

### Configure UFW

- Run as root:
  ```bash
  apt-get install -y ufw
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow OpenSSH
  ufw allow 'Nginx Full'
  ufw reload
  ufw --force enable
  ```

- Enable IPv6 by editing the UFW configuration:
  ```bash
  nano /etc/ufw/ufw/conf
  ```

- Set `IPV6=yes`.

### Install and Configure Core Security Packages

- Install packages and enable periodic upgrades with automatic reboots:
  ```bash
  apt-get install -y unattended-upgrades
  dpkg-reconfigure --priority=low unattended-upgrades
  ```

- Edit the configuration with:
  ```bash
  nano /etc/apt/apt.conf.d/50unattended-upgrades
  ```
  Make sure these lines are present and uncommented:
  ```
  Unattended-Upgrade::Automatic-Reboot "true";
  Unattended-Upgrade::Automatic-Reboot-Time "02:00";
  Unattended-Upgrade::Remove-Unused-Dependencies "true";
  ```

- Verify the periodic settings with:
  ```bash
  cat /etc/apt/apt.conf.d/20auto-upgrades
  ```
  They should include, at least:
  ```
  APT::Periodic::Update-Package-Lists "1";
  APT::Periodic::Unattended-Upgrade "1";
  APT::Periodic::AutocleanInterval "7";
  ```

- Restart the service:
  ```bash
  systemctl restart unattended-upgrades
  ```

## SSH Hardening

### Configure Fail2Ban for SSH

- Create a custom jail so that SSH failures lock out bad actors for an hour:
  ```bash
  apt-get install -y fail2ban
  systemctl enable --now fail2ban
  
  tee /etc/fail2ban/jail.d/ssh-deploy.conf <<'EOF'
  [DEFAULT]
  bantime  = 1h
  findtime = 10m
  maxretry = 5

  [sshd]
  enabled = true port = ssh
  logpath = %(sshd_log)s
  EOF
  ```

- Apply and verify:
  ```bash
  systemctl restart fail2ban
  fail2ban-client status sshd
  ```
  The SSH jail should be active and monitoring port 22.

### Create the deploy user

> **❓Why:** Using a different user for day-to-day operations reduces risk if credentials are compromised.
>
- Create the **deploy** user with a strong password:
  ```bash
  useradd -m -s /bin/bash deploy
  usermod -aG sudo deploy
  chage -m 0 -M 99999 deploy
  passwd deploy
  ```
- Record the password in your secure vault.

- Copy the pre-authorized SSH Keys and set permissions:
  ```bash
  mkdir -p /home/deploy/.ssh
  cp /root/.ssh/authorized_keys /home/deploy/.ssh/
  chown -R deploy:deploy /home/deploy/.ssh
  chmod 700 /home/deploy/.ssh
  chmod 600 /home/deploy/.ssh/authorized_keys
  ```
- In a new session, verify you can SSH in as **deploy**:
  ```bash
  ssh deploy@{{IpAddress}}
  ```
### Lock Down SSHD
- Open the SSH daemon config:
  ```bash
  sudo nano /etc/ssh/sshd_config
  ```
  Ensure the following are uncommented and set exactly:
  ```
  PermitRootLogin no
  PasswordAuthentication no
  PermitEmptyPasswords no
  ChallengeResponseAuthentication no
  UsePAM yes
  X11Forwarding no
  ```
* For scripting purposes, allow **deploy** to run `pg_dump` without a password prompt:
  ```bash
  sudo visudo -f /etc/sudoers.d/deploy
  ```
  Add only this line:
  ```
  deploy ALL=(postgres) NOPASSWD: /usr/bin/pg_dump
  ```

* Restart the SSH service:
  ```bash
  sudo systemctl restart ssh
  ``` 
- From a fresh session, ensure that you can SSH back in as **deploy** and that root login is disabled.

## Build Upload

### Prepare the Self-Contained Build

- Open `{{ProjectName}}.csproj` and add under `<PropertyGroup>`:

  ```xml
  <PropertyGroup>
        <RuntimeIdentifier>linux-x64</RuntimeIdentifier>
        <SelfContained>true</SelfContained>
        <PublishSingleFile>true</PublishSingleFile>
        <EnableCompressionInSingleFile>true</EnableCompressionInSingleFile>
        <IncludeNativeLibrariesForSelfExtract>true</IncludeNativeLibrariesForSelfExtract>
        <DebugType>none</DebugType>
    </PropertyGroup>
  ```
- Adjust `RuntimeIdentifier` to `linux-arm64` for ARM instances.

- Publish in Release mode:
  ```
  dotnet publish -c Release
  ```
  The output appears in `bin/Release/net*/linux-*/publish/`.

### Configure Web Directory & Permissions

- Create a shared **web** group and add both users:
  ```bash
  sudo getent group web || sudo groupadd web
  sudo usermod -aG web deploy
  sudo usermod -aG web www-data
  ```
- Prepare the target directory:
  ```bash
  sudo mkdir -p /var/www/{{ProjectLabel}}
  sudo chgrp -R web /var/www/{{ProjectLabel}}
  sudo chmod -R g+rwXs /var/www/{{ProjectLabel}}
  sudo chown -R deploy:web /var/www/{{ProjectLabel}}
  sudo find /var/www/{{ProjectLabel}} -type d -exec chmod 2775 {} \;
  sudo find /var/www/{{ProjectLabel}} -type f -exec chmod 664 {} \;
  ```
  This ensures new files are also inheriting the web group.

### Upload the Build

- On **Windows**, use MobaXTerm's SFTP interface to transfer the published files to `/var/www/{{ProjectLabel}}`.

- On **Linux/macOS**, run:
  ```bash
  rsync -avz --delete \
  ./bin/Release/net*/linux-*/publish/ \
  deploy@{{IpAddress}}:/var/www/{{ProjectLabel}}/
  ```

## PostgreSQL Installation & Configuration

### Install & Enable Service

- Install PostgreSQL and contrib packages:
  ```bash
  sudo apt update
  sudo apt install -y postgresql postgresql-contrib
  ```
- Enable and start the service:
```bash
sudo systemctl enable --now postgresql
```

### Create Database Role & Schema

- Run this SQL command:
  ```bash
  sudo -u postgres psql -v ON_ERROR_STOP=1 << EOF
  CREATE ROLE {{ProjectLabel}} 
    LOGIN 
    PASSWORD '{{SqlPassword}}';
  CREATE DATABASE {{ProjectLabel}} 
    OWNER {{ProjectLabel}} 
    ENCODING 'UTF8';
  GRANT ALL PRIVILEGES ON DATABASE {{ProjectLabel}} TO {{ProjectLabel}};
  EOF
  ```
- Determine the PostgreSQL version and cluster name in variables:
  ```bash
  read PGVER CLUSTER <<< $(pg_lsclusters --no-header | awk 'NR==1{print $1, $2}')
  ```
- Open the host-based auth file:
  ```bash
  sudo nano /etc/postgresql/$PGVER/$CLUSTER/pg_hba.conf
  ```
- Replace values so that the local rules section reads exactly:
  ```ini
  # Allow only local connections, using SCRAM-SHA-256
  host    all     all     127.0.0.1/32    scram-sha-256
  host    all     all     ::1/128         scram-sha-256
  ```

### Lock Down Network Listeners

- Edit the main config to listen only on localhost and enforce SCRAM encryption:
  ```bash
  sudo nano /etc/postgresql/$PGVER/$CLUSTER/postgresql.conf
  ```

- Ensure these lines are uncommented and set exactly:
  ```ini
  listen_addresses = 'localhost'
  password_encryption = scram-sha-256
  ```
> ⚠️**Caution:** This assumes multiple clusters won't co-exist on the machine. In the case of a PostgreSQL upgrade, follow on-screen instructions to safely dispose of the old cluster with `pg_dropcluster` after the migration is successful.

- Reload PostgreSQL to pick up the edits:
  ```bash
  sudo systemctl reload postgresql
  ```

### PostgreSQL Backup Restoration

- Create a dedicated backups folder:
  ```bash
  sudo mkdir -p /home/deploy/backups
  sudo chown deploy:deploy /home/deploy/backups
  sudo chmod 750 /home/deploy/backups
  ```
- Upload your dump (named exactly `{{ProjectLabel}}.sql` or `.sql.gz`) into `/home/deploy/backups`.

- Import the dump:
  ```bash
  # Uncompressed .sql
  sudo chown postgres:postgres /home/deploy/backups/{{ProjectLabel}}.sql
  sudo -u postgres psql --single-transaction {{ProjectLabel}} \
    < /home/deploy/backups/{{ProjectLabel}}.sql

  # If compressed (.sql.gz)
  sudo chown postgres:postgres /home/deploy/backups/{{ProjectLabel}}.sql.gz
  gunzip -c /home/deploy/backups/{{ProjectLabel}}.sql.gz \
    | sudo -u postgres psql --single-transaction {{ProjectLabel}}
  ```
- Verify tables were created:
  ```bash
  sudo systemctl restart postgresql
  sudo -u postgres psql -d {{ProjectLabel}} -c "\dt" || exit 1
  ```
- Dispose of the unencrypted dump:
  ```bash
  # Simple deletetion
  sudo rm -f /home/deploy/backups/{{ProjectLabel}}.sql /home/deploy/backups/{{ProjectLabel}}.sql.gz
  
  # Advanced shred for very sensitive data
  # sudo apt-get install -y secure-delete
  # sudo srm -vz /home/deploy/backups/{{ProjectLabel}}.sql*
  ```

- Verify the project's `appsettings.Production.json` file has the correct connection string:
  ```json
  {
    "ConnectionStrings": {
      "DefaultConnection": "Host=localhost;Database={{ProjectLabel}};UserId={{ProjectLabel}};Password={{SqlPassword}};"
    }
  }
  ```