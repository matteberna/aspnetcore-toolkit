# Deployment Guide

## Assumptions

- You’re provisioning a VPS on **Hetzner**. Other providers may have different defaults.

- You're not changing the default port for SSH, which is 22.

- On **Windows**, you're using **MobaXTerm** for SSH and its convenient SFTP file browser.

- On **Linux/macOS**, you already have a recent OpenSSH client installed.

- You're performing each step in order, with the exact commands and packages given.

## Preparation

### Generate & Secure SSH Credentials

- on **Windows**, using either Git Bash or WSL:
  ```bash
  mkdir -p ~/.ssh
  ssh-keygen.exe -t rsa -b 4096 -m PEM -f ~/.ssh/hetzner_project_key -N "" -C "deploy@windows"
  ```
- on **Linux/macOS**:
  ```bash
  mkdir -p ~/.ssh && chmod 700 ~/.ssh
  ssh-keygen -t rsa -b 4096 -m PEM -f ~/.ssh/hetzner_project_key -N '' -C "deploy@yourmachine"
  chmod 600 ~/.ssh/hetzner_project_key
  chmod 644 ~/.ssh/hetzner_project_key.pub
  ```
  
> **Note:** The -C parameter is just a human-readable label, and you’re free to change it later without breaking anything.

- Upload `hetzner_project_key` to an off-site secure vault (the public key can always be regenerated from it).

### Provision a VPS

- You're going to need a machine with at least 2 dedicated vCPUs and 8 GB RAM.

- Choose the latest **Ubuntu LTS** release.

- You can optionally enable **IPv6** for free during creation.

- Select the public (.pub) key you just generated.

> **Note:** Automatic backups give you easy rollback points in case something goes wrong, but they also increase the server's monthly cost by 20%. Since we're going to set up database backups, these aren't strictly necessary.

- On your first connection, verify the server’s host key fingerprint against the one shown in the Hetzner console, which is the string in the format `sha256:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`.

- Upload the `hetzner_project_key.bak` to an off-site secure vault.

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
  echo 'vm.swappiness=10' | sudo tee /etc/sysctl.d/99-swappiness.conf
  sysctl --system
  ```  
  This allocates a 2 GB swap file, restricts access, and sets the system to prefer RAM over swap.

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
  ufw allow 'Nginx Full'
  ufw reload
  ufw --force enable
  ufw status verbose
  ```

- Enable IPv6 by editing the UFW configuration:
  ```bash
  nano /etc/ufw/ufw.conf
  ```

- Set `IPV6=yes`.

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
  maxretry = 10
  findtime = 600
  bantime  = 3600
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
  AllowUsers deploy
  PermitRootLogin no
  PasswordAuthentication no
  PermitEmptyPasswords no
  ChallengeResponseAuthentication no
  MaxAuthTries 3
  MaxSessions 1
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
  sudo -u postgres psql -v ON_ERROR_STOP=1 << EOF
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
  local     all     all     scram-sha-256
  host      all     all     127.0.0.1/32 scram-sha-256
  host      all     all     ::1/128 scram-sha-256
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
  # sudo apt install -y secure-delete
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

## NGINX Installation & Configuration

### Install NGINX

- Install NGINX and create the site configuration:
  ```bash
  sudo apt install -y nginx brotli nginx-module-brotli
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
          limit_req zone=one burst=10 nodelay;
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
  }
  ```
> **Note:** The SSL directives referenced here are placeholders.

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
  load_module modules/ngx_http_brotli_filter_module.so;
  load_module modules/ngx_http_brotli_static_module.so;

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
  
  sendfile on;
  tcp_nopush on;
  tcp_nodelay on;
  
  map $http_upgrade $connection_upgrade {
      default   upgrade;
      ''        close;
  }

  limit_req_zone $binary_remote_addr zone=one:10m rate=5r/s;

  brotli on;
  brotli_comp_level 6;
  brotli_types
      text/plain
      text/css
      application/javascript
      application/json
      application/xml+rss
      text/javascript
      text/xml
      image/svg+xml;
  
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
> **Note:** Place `limit_req_zone` and `ssl_session_*` directives at the top, before any `include` statements.

- Validate the configuration:
  ```bash
  sudo nginx -t
  sudo systemctl reload nginx
  ```

## DNS and Certbot Setup

### Configure DNS Records

- In your DNS provider’s dashboard, create `A` records for both `{{Domain}}` and `www.{{Domain}}` pointing to your server’s public IPv4 address (optionally lower the TTL to accelerate propagation).

- Wait until `dig +short {{Domain}}` returns the correct IP.

### Obtain SSL Certificates

- Install the Certbot certificate plugin:
  ```bash
  sudo apt install -y certbot python3-certbot-nginx
  sudo certbot --nginx
  ```
  This will show a few dialogs, choose to redirect HTTP → HTTPS when prompted.

- Check NGINX syntax and confirm that the site is serving valid TLS:
  ```bash
  sudo nginx -t
  sudo systemctl reload nginx
  curl -I https://{{Domain}}
  ```
> **Note:** We don't care about plain HTTP and this isn't a wildcard cert, which would need separate DNS verification.

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

- AWS frequently updates the SES domain-validation process. For the latest instructions on setting up your TXT (for verification), CNAME (for DKIM), and SPF records, see the official AWS docs.

- In the AWS Console, generate an IAM access key for SES and note:

  **{{ses_id}}**: Access key ID
  **{{ses_secret}}**: Secret access key
  **{{ses_region}}**: SES region (e.g. `eu-west-1`)

- In your .NET application, specify the region when instantiating the SES client:
  ```csharp
  using var client =
      new AmazonSimpleEmailServiceClient(RegionEndpoint.GetBySystemName("{{ses_region}}")));
  ```
- Save SES credentials on the server:
  ```bash
  sudo mkdir -p /home/deploy/.aws
  
  sudo tee /home/deploy/.aws/credentials << 'EOF'
  [default]
  aws_access_key_id = {{ses_id}}
  aws_secret_access_key = {{ses_secret}}
  EOF
  
  sudo tee /home/deploy/.aws/config << 'EOF'
  [default]
  region = {{ses_region}}
  EOF
  
  sudo chmod 600 /home/deploy/.aws/config
  sudo chown -R deploy:deploy /home/deploy/.aws
  sudo chmod 600 /home/deploy/.aws/credentials
  ```
- Save identical `credentials` and `config` files locally under `%USERPROFILE%\.aws\`.

> 💡**Hint:** For improved security, consider storing your SES keys in AWS Secrets Manager.

### Data Protection Configuration

- Create the key storage directory:
  ```bash
  sudo mkdir -p /var/keys/{{ProjectLabel}}
  sudo chmod 750 /var/keys/{{ProjectLabel}}
  ```
- If available, manually upload the backup keys from the previous deployment in `/var/keys/{{ProjectLabel}}`.

- In `Program.cs`, add:
  ```csharp
  services.AddDataProtection()
      .PersistKeysToFileSystem(new DirectoryInfo("/var/keys/{{ProjectLabel}}"));
  ```
> **Note:** We’re using a single-server key store without certificate protection; for multi-server or high-security setups, add `.ProtectKeysWithCertificate(...)`

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

  [Service]
  WorkingDirectory=/var/www/{{ProjectLabel}}
  ExecStart=/var/www/{{ProjectLabel}}/{{ProjectName}}
  ExecReload=/bin/kill -s HUP $MAINPID
  Environment=ASPNETCORE_URLS=http://localhost:5000
  Environment=ASPNETCORE_ENVIRONMENT=Production
  Environment=DOTNET_PRINT_TELEMETRY_MESSAGE=false
  ProtectSystem=full
  ProtectHome=read-only
  NoNewPrivileges=true
  PrivateDevices=true
  Restart=on-failure
  RestartSec=5
  StartLimitIntervalSec=60
  StartLimitBurst=5
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
  ````