# Installation Guide — Threat Detection Lab

## Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Kali Linux 2024+ | Kali Linux 2025.4 |
| RAM | 4 GB | 8 GB |
| Disk | 20 GB free | 40 GB free |
| Browser | Firefox | Firefox |

---

## Step 1 — Install Splunk Enterprise

### 1.1 Create a free Splunk account
Go to `https://splunk.com` and create a free account.
This is required to download Splunk Enterprise.

### 1.2 Download Splunk
```bash
cd ~/
mkdir SOC-Lab
cd SOC-Lab

wget -O splunk.deb \
"https://download.splunk.com/products/splunk/releases/9.2.0/linux/splunk-9.2.0-amd64.deb"
```

### 1.3 Install Splunk
```bash
sudo dpkg -i splunk.deb
```

### 1.4 Start Splunk for the first time
```bash
sudo /opt/splunk/bin/splunk start --accept-license --run-as-root
```

During first start, Splunk will ask you to create
an admin account. Choose :
```
Username : admin
Password : YourPassword123
```

### 1.5 Enable auto-start on boot
```bash
sudo /opt/splunk/bin/splunk enable boot-start --run-as-root
```

### 1.6 Access Splunk
Open Firefox and go to :
```
http://localhost:8000
```
Login with your admin credentials.

---

## Step 2 — Install Required Splunk Apps

### 2.1 Via Splunk interface (recommended)
1. Go to `http://localhost:8000`
2. Click **Apps → Find More Apps**
3. Login with your splunk.com credentials
4. Search and install these apps :

| App | Purpose |
|-----|---------|
| Splunk Add-on for Microsoft Windows | Parse Windows Event Logs |
| Splunk Add-on for Sysmon | Parse Sysmon logs |
| Splunk Security Essentials | Security detection content |

### 2.2 Via Splunkbase (if interface method fails)
Go to `https://splunkbase.splunk.com` and download
each app manually as `.tgz` file, then install via :

**Apps → Manage Apps → Install app from file**

### 2.3 Via terminal
```bash
sudo /opt/splunk/bin/splunk stop --run-as-root

sudo tar -xzf splunk-add-on-for-microsoft-sysmon*.tgz \
  -C /opt/splunk/etc/apps/

sudo tar -xzf splunk-add-on-for-windows*.tgz \
  -C /opt/splunk/etc/apps/

sudo /opt/splunk/bin/splunk start --run-as-root
```

---

## Step 3 — Load BOTS v3 Dataset

### 3.1 Download the dataset
```bash
cd ~/SOC-Lab

wget "https://botsdataset.s3.amazonaws.com/botsv3/botsv3_data_set.tgz"
```

The file is approximately 12 GB.
Download time depends on your connection speed.

### 3.2 Extract and install
```bash
tar -xzf botsv3_data_set.tgz -C /opt/splunk/etc/apps/
```

### 3.3 Fix permissions
```bash
sudo chown -R root:root /opt/splunk/etc/apps/botsv3_data_set/
```

### 3.4 Restart Splunk
```bash
sudo /opt/splunk/bin/splunk restart --run-as-root
```

### 3.5 Verify dataset is loaded

⚠️ **IMPORTANT — Time Range**
The BOTS v3 data is from **August 2018**.
You MUST set the time range to **"All time"** in Splunk
before running any query. Otherwise you will get 0 results.

In Splunk Search & Reporting :
1. Click the time picker (shows "Last 24 hours" by default)
2. Select **"All time"**
3. Run this query :

```spl
index=botsv3 | stats count by sourcetype | sort -count
```

You should see 300,000+ events across multiple sourcetypes.

---

## Step 4 — Verify All Data Sources

Run these queries to confirm each data source is available :

**Windows Security Logs** :
```spl
index=botsv3 sourcetype="WinEventLog" | head 5
```

**DNS Logs** : 
```spl
index=botsv3 sourcetype="stream:dns" | head 5
```

**AWS CloudTrail** :
```spl
index=botsv3 sourcetype="aws:cloudtrail" | head 5
```

**Network Logs** :
```spl
index=botsv3 sourcetype="stream:ip" | head 5
```

All queries should return results when time range
is set to **"All time"**.

---

## Troubleshooting

### Problem 1 — Splunk won't start
```bash
# Check status
sudo /opt/splunk/bin/splunk status --run-as-root

# Force restart
sudo /opt/splunk/bin/splunk restart --run-as-root
```

### Problem 2 — Permission denied errors
```bash
# Fix all Splunk permissions
sudo chown -R root:root /opt/splunk/

# Restart
sudo /opt/splunk/bin/splunk restart --run-as-root
```

### Problem 3 — Forgot admin password
```bash
sudo /opt/splunk/bin/splunk stop --run-as-root

sudo /opt/splunk/bin/splunk edit user admin \
  -password NewPassword123 --run-as-root

sudo /opt/splunk/bin/splunk start --run-as-root
```

### Problem 4 — Dataset shows 0 results
Two possible causes :

**Cause A — Time range not set to All time**
→ Click the time picker and select "All time"

**Cause B — Dataset not in correct location**
```bash
# Verify dataset is installed
ls /opt/splunk/etc/apps/ | grep bots

# Verify data files exist
ls /opt/splunk/etc/apps/botsv3_data_set/var/lib/splunk/botsv3/db/

# Fix permissions and restart
sudo chown -R root:root /opt/splunk/etc/apps/botsv3_data_set/
sudo /opt/splunk/bin/splunk restart --run-as-root
```

### Problem 5 — OpenSSL warning on Kali
You may see this warning :
```
systemctl: /opt/splunk/lib/libcrypto.so.3: 
version 'OPENSSL_3.4.0' not found
```
This is a **non-blocking warning** — Splunk still works
normally. You can safely ignore it.

Always use `--run-as-root` flag when running Splunk
commands on Kali Linux :
```bash
sudo /opt/splunk/bin/splunk start --run-as-root
sudo /opt/splunk/bin/splunk stop --run-as-root
sudo /opt/splunk/bin/splunk restart --run-as-root
```

---

## Quick Reference Commands

```bash
# Start Splunk
sudo /opt/splunk/bin/splunk start --run-as-root

# Stop Splunk
sudo /opt/splunk/bin/splunk stop --run-as-root

# Restart Splunk
sudo /opt/splunk/bin/splunk restart --run-as-root

# Check status
sudo /opt/splunk/bin/splunk status --run-as-root

# Access Splunk
http://localhost:8000
```