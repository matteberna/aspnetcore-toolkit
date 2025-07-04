# Deployment Guide

## Assumptions

- You’re provisioning a VPS on **Hetzner**. Other providers may have different defaults.

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