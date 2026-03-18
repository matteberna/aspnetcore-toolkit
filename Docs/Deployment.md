# Deployment Guide

## Assumptions

- You’re provisioning a VPS on **Netcup**. Other providers may have different defaults.

- You're not changing the default port for SSH, which is 22.

- On **Windows**, you're using **MobaXTerm** for SSH and its convenient SFTP file browser.

- On **Linux/macOS**, you already have a recent OpenSSH client installed.

- You're performing each step in order, with the exact commands and packages given.

### Initialize Documentation Placeholders

- Before you run any scripts or generate config files, replace these everywhere:

| Placeholder          | Meaning                                                         | Example                                      |
|:---------------------|:----------------------------------------------------------------|:---------------------------------------------|
| {{ProjectName}}      | The full project name in Pascal case (matches the C# solution)  | MyLatestProject                              |
| {{ProjectLabel}}     | Short label for services and filenames (lowercase, single word) | project                                      |
| {{Domain}}           | Root domain (no protocols, www, or subdomains)                  | myproject.net                                |
| {{WwwDomain}}        | Canonical host (www subdomain)                                  | www.myproject.net                            |
| {{ServerIp}}         | The server's public IPv4 address                                | 103.86.98.1                                  |
| {{DbPassword}}       | A strong, randomly generated password for the database          | f7Hp!9Lk2$Qx                                 |
| {{BackupPassphrase}} | A strong passphrase to use for encrypting backups               | Confound-Countdown-Browse-Shiny-Copper       |
| {{SesId}}            | Amazon SES access key ID                                        | AKIAIOSFODNN7EXAMPLE                         |
| {{SesSecret}}        | Amazon SES secret access key                                    | wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY     |
| {{SesRegion}}        | Amazon SES selected region                                      | eu-west-1                                    |
| {{SmtpEndpoint}}     | SMTP endpoint for the region specified above                    | email-smtp.eu-west-1.amazonaws.com           |
| {{SmtpEmail}}        | Sender address from a **verified** domain                       | mailer@myproject.net                         |
| {{SesSmtpUser}}      | SES SMTP username (created on Amazon SES)                       | AKIAIOSFODNN7EXAMPLE                         |
| {{SesSmtpPassword}}  | SES SMTP password for the account above                         | je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY |
| {{OpsEmail}}         | Mailbox receiving server alerts (disk, backups, etc.)           | ops@myproject.net                            |
| {{CertbotEmail}}     | Mailbox for Let's Encrypt renewal notices                       | certs@myproject.net                          |

> **💡Tip:** Use your favorite editor’s "Find & Replace in Files" feature (typically Ctrl+Shift+F) for bulk swaps.

## Preparation

### Generate & Secure SSH Credentials

- On **Windows**, using either Git Bash or WSL:
  ```bash
  mkdir -p ~/.ssh
  ssh-keygen.exe -t ed25519 -f ~/.ssh/{{ProjectLabel}}_key -C "deploy@{{ProjectLabel}}"
  ```

- On **Linux/macOS**:
  ```bash
  mkdir -p ~/.ssh && chmod 700 ~/.ssh
  ssh-keygen -t ed25519 -f ~/.ssh/{{ProjectLabel}}_key -C "deploy@{{ProjectLabel}}"
  chmod 600 ~/.ssh/{{ProjectLabel}}_key
  chmod 644 ~/.ssh/{{ProjectLabel}}_key.pub
  ```

- Upload `{{ProjectLabel}}_key` to an off-site secure vault (the public key can always be regenerated from it).

- Secure the SSH passphrase and both passwords you've generated in the previous section, as well.

### Provision a VPS

- You're going to need a machine with at least 2 dedicated vCPUs and 8 GB RAM.

> **Note:** The numbers in this documentation are optimized for a machine with 8GB of RAM. For more powerful servers,
> adjust them accordingly whenever recommended percentages are given.

- Choose the latest **Debian** stable release (**13 Trixie+**) or **Ubuntu LTS** (**24.04+**)

- Avoid enabling the **IPv6 address**, which the application won't support.

- If your provider supports it, select the public (.pub) key you just generated during provisioning. Otherwise, you’ll
  copy it manually after the first login (see [Create the deploy user](#create-the-deploy-user)).

> **Note:** Automatic backups give you easy rollback points in case something goes wrong, but they also increase the
> server's monthly cost by 20%. Since we're going to set up database backups, these aren't strictly necessary.

- On your first connection, verify the server’s host key fingerprint against the one shown in the provider's console,
  which is the string in the format `sha256:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`.

### Configure The SSH Client (Windows)

- Launch MobaXTerm.
- Add a new "Session → SSH" entry
- Remote Host: `{{ServerIp}}` , Specify username: `root`, Port: `22`
- Advanced SSH Settings → Use private key: point to your downloaded key

### Configure The SSH Client (macOS/Linux)

- Add to your `~/.ssh/config`:
  ```ssh
  Host {{ProjectLabel}}-prod
  HostName {{ServerIp}}
  User root
  ServerAliveInterval 60
  IdentitiesOnly yes
  StrictHostKeyChecking ask
  IdentityFile ~/.ssh/{{ProjectLabel}}_key
  ```

## Initial System Configuration

### Create & Enable Swap

> **❓Why:** Swap prevents out-of-memory errors under load, but Ubuntu VPSes often ship without it.

- Run as root:
  ```bash
  fallocate -l 4G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
  echo 'vm.swappiness=10' | sudo tee /etc/sysctl.d/99-swappiness.conf
  echo 'vm.vfs_cache_pressure=50' | sudo tee -a /etc/sysctl.d/99-swappiness.conf
  sysctl --system
  ```  

  This allocates a 4 GB swap file (~50% of the server's RAM), restricts access, and tweaks the kernel's memory
  management

### Set Hostname & Timezone

- Set the machine's hostname and timezone to simplify logging and monitoring:
  ```bash
  hostnamectl set-hostname {{ProjectLabel}}-prod
  timedatectl set-timezone UTC
  ```

- Edit the hosts file:
  ```bash
  nano /etc/hosts
  ```
  Update the `127.0.1.1` line to match `{{ProjectLabel}}-prod`

- Enable persistent journald logs
  ```bash
  mkdir -p /var/log/journal
  sed -i 's/#Storage=auto/Storage=persistent/' /etc/systemd/journald.conf
  systemctl restart systemd-journald
  ```

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
  apt install -y ufw
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow OpenSSH
  sed -i 's/^IPV6=.*/IPV6=no/' /etc/ufw/ufw.conf
  ufw reload
  ufw --force enable
  ufw status verbose
  ```

> **Note:** We're disabling IPv6 to simplify configuration, since the application won't use it.

### Install and Configure Core Security Packages

- Install packages and enable periodic upgrades with automatic reboots:
  ```bash
  apt install -y unattended-upgrades
  dpkg-reconfigure --priority=low unattended-upgrades
  ```

- Edit the configuration with:
  ```bash
  nano /etc/apt/apt.conf.d/50unattended-upgrades
  ```

  Make sure these lines are present and uncommented:
  ```
  Unattended-Upgrade::Automatic-Reboot "true";
  Unattended-Upgrade::Automatic-Reboot-Time "04:30";
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

### Configure Fail2Ban

- Create a custom jail so that SSH failures lock out bad actors for an hour:
  ```bash
  apt install -y fail2ban
  systemctl enable --now fail2ban
  
  tee /etc/fail2ban/jail.d/ssh-deploy.conf <<'EOF'
  [DEFAULT]
  bantime  = 1h
  findtime = 10m
  maxretry = 5

  [sshd]
  enabled = true
  port = ssh
  logpath = %(sshd_log)s
  EOF
  ```

- Add another jail to block clients hammering the site with 4xx/5xx errors:
  ```bash
  sudo tee /etc/fail2ban/filter.d/nginx-errors.conf << 'EOF'
  [Definition]
  failregex = ^<HOST> - - \[[^\]]+\] "(?:GET|POST) [^"]*" (?:404|429|444|500)
  ignoreregex =
  datepattern = ^%%d/%%b/%%Y:%%H:%%M:%%S
  EOF
  
  sudo tee /etc/fail2ban/jail.d/nginx-errors.conf << 'EOF'
  [nginx-errors]
  enabled  = true
  filter   = nginx-errors
  port     = http,https
  logpath  = /var/log/nginx/access.log
  maxretry = 30
  findtime = 60
  bantime  = 600
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

- Create the **deploy** user (you'll be prompted for a password):
  ```bash
  adduser deploy
  usermod -aG sudo deploy
  ```

- Record the password in your secure vault.

- Copy the SSH key to the new user. If the key was added during provisioning, copy it from root:
  ```bash
  mkdir -p /home/deploy/.ssh
  cp /root/.ssh/authorized_keys /home/deploy/.ssh/
  chown -R deploy:deploy /home/deploy/.ssh
  chmod 700 /home/deploy/.ssh
  chmod 600 /home/deploy/.ssh/authorized_keys
  ```

- If your provider didn't support key upload, paste your public key manually instead:
  ```bash
  mkdir -p /home/deploy/.ssh
  nano /home/deploy/.ssh/authorized_keys   # paste the .pub key contents
  chown -R deploy:deploy /home/deploy/.ssh
  chmod 700 /home/deploy/.ssh
  chmod 600 /home/deploy/.ssh/authorized_keys
  ```

- In a new session, verify you can SSH in as **deploy**:
  ```bash
  ssh deploy@{{ServerIp}}
  ```

### Lock Down SSHD

- Open the SSH daemon config:
  ```bash
  sudo nano /etc/ssh/sshd_config
  ```

  Ensure the following are uncommented and set exactly:

  > **💡Tip:** During a migration, you can temporarily use `PermitRootLogin prohibit-password` instead of `no` to keep
  > key-only root access as a fallback. Switch to `no` once everything is stable.

  ```
  AllowUsers deploy
  PermitRootLogin no
  PasswordAuthentication no
  PermitEmptyPasswords no
  KbdInteractiveAuthentication no
  MaxAuthTries 3
  MaxSessions 5
  UsePAM yes
  X11Forwarding no
  AllowTcpForwarding no
  PermitTunnel no
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

- Update your SSH client to connect as **deploy** going forward:
  - On **Windows**, edit your MobaXTerm session and change the username from `root` to `deploy`.
  - On **macOS/Linux**, change `User root` to `User deploy` in your `~/.ssh/config` entry.

- From a fresh session, verify that you can SSH in as **deploy** and that root login is rejected.

> **Note:** Moving forward, all commands will be prefixed with `sudo`.

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
      <PublishReadyToRun>true</PublishReadyToRun>
      <DebugType>none</DebugType>
  </PropertyGroup>
  ```

- Adjust `RuntimeIdentifier` to `linux-arm64` for ARM instances.

> **⚠️Caution:** If you publish as framework-dependent (DLL) instead of self-contained, the systemd `ExecStart` must
> use `dotnet {{ProjectName}}.dll` rather than the bare binary. Running a DLL directly will fail with "Exec format
> error". The instructions below assume a self-contained build.

- Publish in Release mode:
  ```
  dotnet publish -c Release
  ```

  The output will appear in `bin/Release/net*/linux-*/publish/`.

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
  sudo mkdir -p /var/www/{{ProjectLabel}}/logs
  sudo chown deploy:web /var/www/{{ProjectLabel}}/logs
  ```

  This ensures new files are also inheriting the web group.

### Upload the Build

- On **Windows**, use MobaXTerm's SFTP interface to transfer the published files to `/var/www/{{ProjectLabel}}`.

- On **Linux/macOS**, run:
  ```bash
  rsync -avz --delete \
  ./bin/Release/net*/linux-*/publish/ \
  deploy@{{ServerIp}}:/var/www/{{ProjectLabel}}/
  ```

## PostgreSQL Installation & Configuration

### Install & Enable Service

- Install PostgreSQL and contrib packages:
  ```bash
  sudo apt update
  sudo apt install -y postgresql postgresql-contrib
  sudo mkdir -p /var/log/postgresql
  sudo chown postgres:postgres /var/log/postgresql
  sudo chmod 750 /var/log/postgresql
  ```

- Enable and start the service:

```bash
sudo systemctl enable --now postgresql
```

### Enable Logging and Lock Down Network Listeners

- Determine the PostgreSQL version and cluster name in variables:
  ```bash
  read PGVER CLUSTER <<EOF
  $(pg_lsclusters --no-header | awk 'NR==1{print $1, $2}')
  EOF
  ```

> ⚠️**Caution:** This assumes multiple clusters won't co-exist on the machine. In the case of a PostgreSQL upgrade,
> follow on-screen instructions to safely dispose of the old cluster with `pg_dropcluster` after the migration is
> successful.

- Open the host-based auth file:
  ```bash
  sudo nano /etc/postgresql/$PGVER/$CLUSTER/pg_hba.conf
  ```

- Replace values so that the local rules section reads exactly:
  ```ini
  # Allow local peer auth for postgres
  local     all     postgres                    peer
  
  # Then require SCRAM for everyone else
  local     all     all                         scram-sha-256
  host      all     all         127.0.0.1/32    scram-sha-256
  host      all     all         ::1/128         scram-sha-256
  ```

- Edit the main config:
  ```bash
  sudo nano /etc/postgresql/$PGVER/$CLUSTER/postgresql.conf
  ```

- Uncomment and set all these values exactly:
  ```ini
  logging_collector = on
  
  log_destination = 'stderr'
  log_directory = '/var/log/postgresql'
  log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
  log_file_mode = 0640
  
  log_truncate_on_rotation = on
  log_rotation_age = 1d
  log_rotation_size = 0
  
  log_min_error_statement = error
  log_min_duration_statement = 500
  log_checkpoints = on
  log_connections = on
  log_disconnections = on
  log_line_prefix = '%m [%p] %q%u@%d '

  listen_addresses = 'localhost'
  password_encryption = scram-sha-256
  
  shared_buffers = 1GB  # Optimize as needed
  effective_cache_size = 6GB  # ~75% of RAM on an 8GB server
  maintenance_work_mem = 512MB
  ```

> **Note:** [PGTune](https://pgtune.leopard.in.ua/) is a great tool for fine-tuning your PostgreSQL configuration.

- Reload PostgreSQL to pick up the edits:
  ```bash
  sudo systemctl reload postgresql
  ```

### Create Database Role & Schema

- Run this SQL command:
  ```bash
  sudo -u postgres psql -v ON_ERROR_STOP=1 << EOF
  CREATE ROLE {{ProjectLabel}} 
    LOGIN 
    PASSWORD '{{DbPassword}}';
  CREATE DATABASE {{ProjectLabel}} 
    OWNER {{ProjectLabel}} 
    ENCODING 'UTF8';
  GRANT ALL PRIVILEGES ON DATABASE {{ProjectLabel}} TO {{ProjectLabel}};
  EOF
  
  history -c && history -w
  ```

### PostgreSQL Backup Restoration

- Upload your custom-format dump (`.dump`) to the server and move it to `/var/backups`:
  ```bash
  sudo mkdir -p /var/backups
  sudo mv /home/deploy/backups/{{ProjectLabel}}.dump /var/backups/
  sudo chown postgres:postgres /var/backups/{{ProjectLabel}}.dump
  ```

- Restore the dump. The `--role` flag ensures all objects are created as the app user, preventing
  ownership issues:
  ```bash
  sudo -u postgres dropdb --if-exists {{ProjectLabel}}
  sudo -u postgres createdb --owner={{ProjectLabel}} {{ProjectLabel}}

  sudo -u postgres pg_restore \
    --dbname={{ProjectLabel}} \
    --role={{ProjectLabel}} \
    --single-transaction \
    --clean --if-exists \
    /var/backups/{{ProjectLabel}}.dump
  ```

- Verify tables were created:
  ```bash
  sudo systemctl restart postgresql
  sudo -u postgres psql -d {{ProjectLabel}} -c "\dt" || exit 1
  ```

- Dispose of the unencrypted dump:
  ```bash
  # Simple deletion
  sudo rm -f /var/backups/{{ProjectLabel}}.dump

  # Advanced shred (optional, for sensitive data)
  # sudo apt install -y secure-delete
  # sudo srm -vz /var/backups/{{ProjectLabel}}.dump
  ```

### Fix Permissions After Restore

> **Note:** If you used `--role` above, this section shouldn't be necessary. It's here as a
> troubleshooting reference in case objects end up owned by `postgres` after a restore.

- Grant the app user access to all objects:
  ```bash
  sudo -u postgres psql {{ProjectLabel}}
  ```

  ```sql
  -- public schema
  GRANT ALL ON SCHEMA public TO {{ProjectLabel}};
  GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO {{ProjectLabel}};
  GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO {{ProjectLabel}};
  GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO {{ProjectLabel}};

  -- hangfire schema (if present)
  GRANT USAGE, CREATE ON SCHEMA hangfire TO {{ProjectLabel}};
  GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA hangfire TO {{ProjectLabel}};
  GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA hangfire TO {{ProjectLabel}};

  -- defaults for future objects
  ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO {{ProjectLabel}};
  ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO {{ProjectLabel}};
  ALTER DEFAULT PRIVILEGES IN SCHEMA hangfire GRANT ALL ON TABLES TO {{ProjectLabel}};
  ALTER DEFAULT PRIVILEGES IN SCHEMA hangfire GRANT ALL ON SEQUENCES TO {{ProjectLabel}};
  \q
  ```

- Verify the project's `appsettings.Production.json` file has the correct connection string:
  ```json
  {
    "ConnectionStrings": {
      "DefaultConnection": "Host=localhost;Database={{ProjectLabel}};UserId={{ProjectLabel}};Password={{DbPassword}};Pooling=true;Minimum Pool Size=3;Maximum Pool Size=20;"
    }
  }
  ```

## NGINX Installation & Configuration

### Install NGINX

- Install NGINX and create the site configuration:
  ```bash
  sudo apt install -y nginx
  sudo systemctl enable --now nginx
  sudo nano /etc/nginx/sites-available/{{ProjectLabel}}.conf
  ```

- Paste this content:
  ```nginx
  server {
      listen 80;
      server_name {{Domain}} www.{{Domain}};
      return 301 https://$host$request_uri;
  }

  server {
      listen 443 ssl http2;
      server_name {{Domain}} www.{{Domain}};

      root /var/www/{{ProjectLabel}}/wwwroot;
  
      ssl_stapling on;
      ssl_stapling_verify on;
      resolver 1.1.1.1 8.8.4.4 valid=300s;
      resolver_timeout 5s;
      ssl_certificate /etc/letsencrypt/live/{{Domain}}/fullchain.pem;
      ssl_certificate_key /etc/letsencrypt/live/{{Domain}}/privkey.pem;
      ssl_trusted_certificate /etc/letsencrypt/live/{{Domain}}/chain.pem;
  
      include /etc/letsencrypt/options-ssl-nginx.conf;

      add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
      add_header X-Content-Type-Options "nosniff" always;
      add_header X-Frame-Options "DENY" always;
      add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  
      client_max_body_size 10M;

      error_page 502 503 504 /maintenance.html;
  
      location = /maintenance.html {
          root /var/www/{{ProjectLabel}}/wwwroot;
          internal;
      }

      location / {
          limit_req zone=one burst=20 nodelay;
          proxy_pass http://localhost:5000;
          proxy_http_version 1.1;
          proxy_set_header Upgrade $http_upgrade;
          proxy_set_header Connection $connection_upgrade;
          proxy_set_header Host $host;
          proxy_cache_bypass $http_upgrade;
          proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
          proxy_set_header X-Forwarded-Proto $scheme;
          proxy_buffer_size 4k;
          proxy_buffers 4 32k;
          proxy_busy_buffers_size 64k;
          proxy_connect_timeout 10s;
          proxy_send_timeout 30s;
          proxy_read_timeout 30s;
      }
  
      location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
      }
  }
  ```

> **Note:** Strict-Transport-Security is a permanent commitment to HTTPS for your entire domain and all its subdomains.

- Add firewall rules for NGINX:
  ```bash
  sudo ufw allow 'Nginx Full'
  sudo ufw reload
  ```

- Generate a 2048-bit DH param file (takes a minute):
  ```bash
  sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
  ```

- Enable the new site, disable the default, and edit the main config:

  ```bash
  sudo ln -s /etc/nginx/sites-available/{{ProjectLabel}}.conf /etc/nginx/sites-enabled/
  sudo rm /etc/nginx/sites-enabled/default
  sudo nano /etc/nginx/nginx.conf
  ```

- At the very top, before the `http` block, add:

  ```nginx
  worker_processes auto;
  worker_rlimit_nofile 65536;
  
  events {
      worker_connections 1024;
      multi_accept on;
  }
  ```

- Inside the `http` block, add:

  ```nginx
  server_tokens off;

  set_real_ip_from   127.0.0.1;
  real_ip_header     X-Forwarded-For;
  real_ip_recursive  on;
  
  access_log /var/log/nginx/access.log;
  error_log /var/log/nginx/error.log warn;
  
  client_header_timeout 10s;
  client_body_timeout 10s;
  send_timeout 10s;
  keepalive_timeout 15s;
  ssl_dhparam /etc/ssl/certs/dhparam.pem;
  ssl_session_cache shared:SSL:10m;
  ssl_session_timeout 10m;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers HIGH:!aNULL:!MD5;
  ssl_prefer_server_ciphers on;
  
  client_body_buffer_size 128k;
  client_header_buffer_size 1k;
  large_client_header_buffers 4 4k;
  
  sendfile on;
  tcp_nopush on;
  tcp_nodelay on;
  
  map $http_upgrade $connection_upgrade {
      default   upgrade;
      ''        close;
  }

  limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;
  
  gzip on;
  gzip_vary on;
  gzip_proxied any;
  gzip_comp_level 6;
  gzip_buffers 16 8k;
  gzip_http_version 1.1;
  gzip_types
      text/plain
      text/css
      application/javascript
      application/json
      application/xml
      application/xml+rss
      text/javascript
      text/xml;
  ```

> **Note:** Place `limit_req_zone` and `ssl_session_*` directives at the top of the `http` block, before any `include`
> statements.

> **Note:** Don't run `nginx -t` yet — the SSL certificates referenced in the config don't exist until the Certbot
> step below.

## Semi-Daily Backups

### Define the PostgreSQL backup script

- Create a secure passphrase file:
  ```bash
  echo "{{BackupPassphrase}}" | sudo tee /home/deploy/.backup_passphrase > /dev/null
  sudo chown deploy:deploy /home/deploy/.backup_passphrase
  sudo chmod 600 /home/deploy/.backup_passphrase
  ```

- Edit or create the GPG agent config:
  ```bash
  mkdir -p /home/deploy/.gnupg
  chmod 700 /home/deploy/.gnupg
  nano /home/deploy/.gnupg/gpg-agent.conf
  ```
  Append the line `allow-loopback-pinentry` anywhere in the file.

- Reload the GPG agent:
  ```bash
  gpgconf --reload gpg-agent
  ```

- Create the script and set permissions:
  ```bash
  sudo tee /usr/local/bin/{{ProjectLabel}}_backup.sh << 'EOF'
  #!/usr/bin/env bash
  set -euo pipefail
  trap 'rm -f "$DB_PLAIN" "$KEYS_PLAIN"; echo "Backup failed at $(date)" | mail -s "{{ProjectLabel}} Backup Failed" {{OpsEmail}}' ERR
  
  # Read passphrase from secure file
  if [[ ! -f /home/deploy/.backup_passphrase ]]; then
  echo "$(date): ERROR - Backup passphrase file not found!" >&2
  exit 1
  fi
  BACKUP_GPG_PASSPHRASE=$(cat /home/deploy/.backup_passphrase)

  # Variables
  TIMESTAMP=$(date +%Y-%m-%dT%H%M)
  BACKUP_DIR=/home/deploy/backups
  AVATAR_DIR=/var/www/{{ProjectLabel}}/wwwroot/avatars
  KEY_DIR=/var/keys/{{ProjectLabel}}
  DB_PLAIN="$BACKUP_DIR/{{ProjectLabel}}_${TIMESTAMP}.sql.gz"
  DB_ENC="$DB_PLAIN.gpg"
  AVATAR_PLAIN="$BACKUP_DIR/avatars_${TIMESTAMP}.tar.gz"
  KEYS_PLAIN="$BACKUP_DIR/dataprotectionkeys_${TIMESTAMP}.tar.gz"
  KEYS_ENC="$KEYS_PLAIN.gpg"
  mkdir -p "$BACKUP_DIR"
  chmod 750 "$BACKUP_DIR"
  
  # Database dump (encrypted)
  sudo -u postgres pg_dump {{ProjectLabel}} | gzip > "$DB_PLAIN"
  gpg --batch --yes \
    --pinentry-mode loopback \
    --cipher-algo AES256 \
    --passphrase "$BACKUP_GPG_PASSPHRASE" \
    --output "$DB_ENC" \
    --symmetric "$DB_PLAIN"
  
  # Verification
  if gpg --batch --decrypt --pinentry-mode loopback \
    --passphrase "$BACKUP_GPG_PASSPHRASE" "$DB_ENC" 2>/dev/null \
    | gunzip 2>/dev/null | head -n 1 | grep -q "PostgreSQL";
  then
    echo "$(date): Database backup verified successfully" >&2
  else
    echo "$(date): ERROR - Database backup verification failed!" >&2
    exit 1
  fi
  
  rm -f "$DB_PLAIN"
  
  # Avatars (public)
  if [ -d "$AVATAR_DIR" ]; then
    tar -czf "$AVATAR_PLAIN" -C "$AVATAR_DIR" .
  fi
  
  # DataProtection keys (encrypted)
  tar -czf "$KEYS_PLAIN" -C "$KEY_DIR" .
  gpg --batch --yes \
    --pinentry-mode loopback \
    --cipher-algo AES256 \
    --passphrase "$BACKUP_GPG_PASSPHRASE" \
    --output "$KEYS_ENC" \
    --symmetric "$KEYS_PLAIN"
  rm -f "$KEYS_PLAIN"

  # Clear passphrase from memory
  unset BACKUP_GPG_PASSPHRASE

  # Pruning
  find "$BACKUP_DIR" -type f \( \
    -name "{{ProjectLabel}}_*.sql.gz.gpg" \
    -o -name "dataprotectionkeys_*.tar.gz.gpg" \
    \) -mtime +7 -delete
  
  find "$BACKUP_DIR" -type f -name "avatars_*.tar.gz" -mtime +7 -delete
  EOF
  
  sudo chmod +x /usr/local/bin/{{ProjectLabel}}_backup.sh
  ```

> **Note:** In this example, we're also saving the **/avatars** folder with user-generated content.

> **Note:** `-mtime +7` means a retention period of **7 days**. Adjust as needed.

- Open the crontab:
  ```bash
  crontab -e
  ```
- Add this line to run the backup at **00:00** and **12:00** UTC every day, with basic monitoring:
  ```
  0 0,12 * * * /usr/local/bin/{{ProjectLabel}}_backup.sh >> /home/deploy/backups/backup.log 2>&1
  0 3 * * * find /var/log/postgresql -name "postgresql-*.log" -mtime +7 -delete
  0 8 * * * df -h | grep -E '^/dev/' | awk '$5+0 > 80 {print "Disk usage warning: " $0}' | mail -s "Disk Space Alert" {{OpsEmail}}
  ```
- Save and exit; cron will pick up the new schedule immediately.

### Verify and monitor

- Manually run the script once to confirm it works:
  ```bash
  /usr/local/bin/{{ProjectLabel}}_backup.sh
  ls -l /home/deploy/backups/
  ```
- If backups don’t appear as expected, check the logs with:
  ```bash
  journalctl -u cron | grep '{{ProjectLabel}}_backup.sh'
  ```

## DNS and Certbot Setup

### Configure DNS Records

- In your DNS provider’s dashboard, create `A` records for both `{{Domain}}` and `www.{{Domain}}` pointing to your
  server’s public IPv4 address (optionally lower the TTL to accelerate propagation).

- Wait until `dig +short {{Domain}}` returns the correct IP.

### Obtain SSL Certificates

- Install the Certbot certificate plugin:
  ```bash
  sudo apt install -y certbot python3-certbot-nginx
  sudo certbot --nginx --email {{CertbotEmail}} --agree-tos
  ```

  This will show a few dialogs, choose to redirect HTTP → HTTPS when prompted.

- Check NGINX syntax and confirm that the site is serving valid TLS:
  ```bash
  sudo nginx -t
  sudo systemctl reload nginx
  curl -I https://{{Domain}}
  ```

> **Note:** We don't care about plain HTTP and this isn't a wildcard cert, which would need separate DNS verification.

- Verify that OCSP stapling, an SSL performance optimization we've configured above, is working:
  ```bash
  sudo openssl s_client -connect {{Domain}}:443 -servername {{Domain}} -status < /dev/null 2>/dev/null | grep -A1 'OCSP response:'
  ```

### Enable Automatic Renewal

* If the tests above succeeded, create a renewal hook:
  ```bash
  sudo tee /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh << 'EOF'
  #!/usr/bin/env bash
  systemctl reload nginx
  EOF
  sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
  ```

- Test the renewal process in dry-run mode:
  ```bash
  sudo certbot renew --dry-run
  ```

- If that succeeds, enable and start Certbot’s systemd timer:
  ```bash
  sudo systemctl enable --now certbot.timer
  ```

## Miscellaneous

### Time Synchronization

- Install and enable Chrony:

  ```bash  
  sudo apt update
  sudo apt install -y chrony
  sudo systemctl enable --now chrony
  chronyc tracking
  timedatectl status
  ```

  You should see "System clock synchronized: yes".

### Amazon SES Configuration

- AWS frequently updates the SES domain-validation process. For the latest instructions on setting up your TXT (for
  verification), CNAME (for DKIM), and SPF records, see the official AWS docs.

- In your .NET application, specify the region when instantiating the SES client:
  ```csharp
  using var client =
      new AmazonSimpleEmailServiceClient(RegionEndpoint.GetBySystemName("{{SesRegion}}"));
  ```

- Save SES credentials on the server:
  ```bash
  sudo mkdir -p /home/deploy/.aws
  
  sudo tee /home/deploy/.aws/credentials << 'EOF'
  [default]
  aws_access_key_id = {{SesId}}
  aws_secret_access_key = {{SesSecret}}
  EOF
  
  sudo tee /home/deploy/.aws/config << 'EOF'
  [default]
  region = {{SesRegion}}
  EOF
  
  sudo chmod 600 /home/deploy/.aws/config
  sudo chown -R deploy:deploy /home/deploy/.aws
  sudo chmod 600 /home/deploy/.aws/credentials
  ```

- Save identical `credentials` and `config` files locally under `%USERPROFILE%\.aws\`.

> 💡**Hint:** For improved security, consider storing your SES keys in AWS Secrets Manager.

### msmtp Configuration

- Install **msmtp**, a lightweight mail relay program:
  ```bash
  sudo apt update
  sudo apt install -y msmtp-mta mailutils
  ```

- Configure **msmtp** with the Amazon SES credentials:
  ```bash
  sudo tee /etc/msmtprc << 'EOF'
  # Global defaults
  defaults
  auth           on
  tls            on
  tls_trust_file /etc/ssl/certs/ca-certificates.crt
  logfile        /var/log/msmtp.log
  
  # System mail account (used by root + cron for backup alerts, etc.)
  account default
  host {{SmtpEndpoint}}
  port 587
  from {{SmtpEmail}}
  user {{SesSmtpUser}}
  password {{SesSmtpPassword}}
  
  account default: default
  EOF
  
  sudo chown root:root /etc/msmtprc
  sudo chmod 600 /etc/msmtprc
  ```

### Data Protection Configuration

- Create the key storage directory:
  ```bash
  sudo mkdir -p /var/keys/{{ProjectLabel}}
  sudo chown deploy:web /var/keys/{{ProjectLabel}}
  sudo chmod 770 /var/keys/{{ProjectLabel}}
  ```

- If available, manually upload the backup keys from the previous deployment in `/var/keys/{{ProjectLabel}}`.

- In `Program.cs`, add:
  ```csharp
  builder.Services.AddDataProtection()
      .PersistKeysToFileSystem(new DirectoryInfo("/var/keys/{{ProjectLabel}}"));
  ```

> **Note:** We’re using a single-server key store without certificate protection; for multi-server or high-security
> setups, add `.ProtectKeysWithCertificate(...)`

### Forwarded Headers

- In `Program.cs`, add the Forwarded Headers middleware after `WebApplication.CreateBuilder(args)`:

    ```csharp
    builder.Services.Configure<ForwardedHeadersOptions>(o =>
    {
        o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
        o.KnownProxies.Add(IPAddress.Parse("127.0.0.1")); // NGINX on same box
    });
    ```

- Then, enable their use after `app = builder.Build()`:
    ```csharp 
    var app = builder.Build();
    app.UseForwardedHeaders();
    ```

## Execution

### systemd Configuration

- Make the application binary executable:
  ```bash
  sudo chmod +x /var/www/{{ProjectLabel}}/{{ProjectName}}
  ```

- Create the systemd unit file:
  ```bash
  sudo tee /etc/systemd/system/{{ProjectLabel}}.service << 'EOF'
  [Unit]
  Description={{ProjectName}} ASP.NET Core application
  After=network.target
  StartLimitIntervalSec=60
  StartLimitBurst=5

  [Service]
  WorkingDirectory=/var/www/{{ProjectLabel}}
  ExecStart=/var/www/{{ProjectLabel}}/{{ProjectName}}
  ExecReload=/bin/kill -s HUP $MAINPID
  Environment=ASPNETCORE_URLS=http://localhost:5000
  Environment=ASPNETCORE_ENVIRONMENT=Production
  Environment=DOTNET_PRINT_TELEMETRY_MESSAGE=false
  CPUQuota=200%
  KillMode=mixed
  KillSignal=SIGTERM
  MemoryAccounting=yes
  ProtectSystem=full
  ProtectHome=read-only
  NoNewPrivileges=true
  PrivateDevices=true
  Restart=on-failure
  RestartSec=5
  TimeoutStartSec=20s
  TimeoutStopSec=20
  SuccessExitStatus=143
  SyslogIdentifier={{ProjectName}}
  User=deploy
  Group=web
  PrivateTmp=true
  LimitNOFILE=65536
  StandardOutput=journal
  StandardError=journal

  [Install]
  WantedBy=multi-user.target
  EOF
  
  sudo chmod 644 /etc/systemd/system/{{ProjectLabel}}.service
  ```

  > **Note:** `{{ProjectName}}` is the name of the self-contained binary in the `/www` folder, no extension.

- Verify the status:
  ```bash
  sudo systemctl daemon-reload
  sudo systemd-analyze verify /etc/systemd/system/{{ProjectLabel}}.service
  ```

- Start the application and keep an eye on live logs:
  ```bash
  sudo systemctl enable --now {{ProjectLabel}}
  sudo systemctl status {{ProjectLabel}}
  journalctl -u {{ProjectLabel}} --no-pager
  ```

## Log Rotation

This keeps log files from growing forever, rotating them daily and keeping 7 days of history.

### Create the config

- Run:

  ```bash
  sudo tee /etc/logrotate.d/{{ProjectLabel}}-serilog << 'EOF'
  /var/www/{{ProjectLabel}}/logs/*.log {
  daily
      missingok
      rotate 7
      compress
      delaycompress
      copytruncate
      notifempty
      create 640 deploy web
  }
  EOF

  sudo tee /etc/logrotate.d/{{ProjectLabel}}-backups << 'EOF'
  /home/deploy/backups/backup.log {
      daily
      missingok
      rotate 7
      compress
      delaycompress
      copytruncate
      notifempty
      create 640 deploy deploy
  }
  EOF

  sudo tee /etc/logrotate.d/fail2ban << 'EOF'
  /var/log/fail2ban.log {
      weekly
      missingok
      rotate 4
      compress
      delaycompress
      notifempty
      create 640 root adm
      copytruncate
  }
  EOF
  ```

> **Note:** NGINX ships with its own `logrotate` by default. You can customize it, but it's not necessary.

- Verify the whole lot with a dry:
  ```bash
  sudo logrotate --debug /etc/logrotate.conf
  ```
  Ensure newly created rotated files match the create lines you set.