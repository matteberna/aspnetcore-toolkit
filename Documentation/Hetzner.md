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

### Harden SSH with Fail2Ban

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