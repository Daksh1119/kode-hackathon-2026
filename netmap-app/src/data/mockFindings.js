export const DEMO_FINDINGS = [
  {
    id: "f1",
    severity: "high",
    title: "Public Admin Panel Detected",
    host: "webmail.hiranandani.com",
    source: "engine",
    port: null,
    status_label: "DNS exists — HTTP unreachable",
    description: "The subdomain 'webmail.hiranandani.com' exposes an administrative interface on the public internet. Admin panels provide access to backend controls, user management, and system configuration — they should never be reachable without strict access controls.",
    action: "Immediately restrict access behind a VPN or IP allowlist. Require MFA for all admin logins. Consider moving the admin interface off a public subdomain entirely.",
    timestamp: "2026-04-18T13:32:46",
    whatItIs: "An administrative webmail interface that is accessible from the public internet without VPN or network-level restrictions.",
    whyItMatters: "Admin panels are high-value targets. Without IP restrictions, attackers can attempt brute-force, credential stuffing, or exploit known webmail vulnerabilities to gain full access to corporate email.",
    attackerCan: [
      "Brute-force admin credentials with automated tools",
      "Attempt credential stuffing from leaked password databases",
      "Exploit known webmail vulnerabilities (e.g. Horde, Roundcube CVEs)",
      "Gain access to all corporate email communications",
    ],
    fixCode: `# Nginx — restrict admin by IP
location / {
    allow 203.0.113.0/24;   # Your office IP
    allow 10.0.0.0/8;       # VPN range
    deny all;
}

# Or use Cloudflare Zero Trust to gate access`,
  },
  {
    id: "f2",
    severity: "high",
    title: "Sensitive Port 21 Open — FTP",
    host: "hiranandani.com",
    source: "nmap",
    port: 21,
    description: "Port 21/tcp (FTP) is publicly accessible. FTP transfers files in cleartext — credentials and data are visible to anyone on the network path. This is a legacy protocol with no encryption.",
    action: "Restrict port 21 to internal network or VPN only via firewall rules. If FTP is not required, disable it entirely. Replace with SFTP (port 22) for secure file transfer.",
    timestamp: "2026-04-18T13:32:48",
    whatItIs: "FTP (File Transfer Protocol) on port 21 is a legacy file transfer service that transmits data and credentials in plaintext over the network.",
    whyItMatters: "Anyone on the network path between a user and this server can intercept FTP credentials and files. Attackers commonly scan for open FTP ports as an easy entry point.",
    attackerCan: [
      "Intercept FTP username and password in plaintext",
      "Download or modify files on the server",
      "Use captured credentials for lateral movement",
      "Brute-force FTP credentials if anonymous access is disabled",
    ],
    fixCode: `# Block FTP at firewall (iptables)
iptables -A INPUT -p tcp --dport 21 -j DROP

# AWS Security Group — remove FTP ingress rule
aws ec2 revoke-security-group-ingress \\
  --group-id sg-XXXXXXXX \\
  --protocol tcp \\
  --port 21 \\
  --cidr 0.0.0.0/0

# Use SFTP instead (port 22, encrypted)`,
  },
  {
    id: "f3",
    severity: "high",
    title: "Sensitive Port 3389 Open — RDP",
    host: "hiranandani.com",
    source: "nmap",
    port: 3389,
    description: "Port 3389 (Remote Desktop Protocol) is publicly accessible. RDP allows full remote control of a Windows machine — it is one of the most commonly brute-forced and exploited services on the internet.",
    action: "Restrict port 3389 to VPN-only access via firewall rules. Enable Network Level Authentication (NLA). Use account lockout policies to prevent brute-force.",
    timestamp: "2026-04-18T13:32:48",
    whatItIs: "RDP (Remote Desktop Protocol) on port 3389 allows full graphical remote control of a Windows machine. When exposed to the internet, it is a primary ransomware entry point.",
    whyItMatters: "Attackers continuously scan the internet for open RDP ports. A single weak password means complete control of your server — and by extension, your entire network.",
    attackerCan: [
      "Log in remotely if credentials are weak or default",
      "Deploy ransomware across your entire network",
      "Steal all files and data stored on the server",
      "Use your server as a launchpad for further attacks",
    ],
    fixCode: `# Block RDP at firewall (Windows Firewall)
netsh advfirewall firewall add rule \\
  name="Block RDP Public" \\
  dir=in action=block \\
  protocol=TCP localport=3389 \\
  remoteip=0.0.0.0/0

# Allow only VPN subnet
netsh advfirewall firewall add rule \\
  name="Allow RDP VPN" \\
  dir=in action=allow \\
  protocol=TCP localport=3389 \\
  remoteip=10.0.0.0/8`,
  },
  {
    id: "f4",
    severity: "high",
    title: "Sensitive Port 135 Open — MSRPC",
    host: "hiranandani.com",
    source: "nmap",
    port: 135,
    description: "Port 135 (Windows RPC / MSRPC) is publicly accessible. This service has a long history of critical vulnerabilities including remote code execution. It has no legitimate reason to be internet-facing.",
    action: "Block port 135 at the firewall for all external traffic immediately. This is a Windows-internal service only.",
    timestamp: "2026-04-18T13:32:48",
    whatItIs: "MSRPC (Microsoft Remote Procedure Call) on port 135 is a Windows service used for internal communication. When exposed to the internet, it becomes a major attack surface.",
    whyItMatters: "Port 135 was exploited by the Blaster worm and numerous ransomware variants. Several critical CVEs allow remote code execution without any authentication.",
    attackerCan: [
      "Exploit unpatched MSRPC vulnerabilities for remote code execution",
      "Enumerate Windows services and user accounts",
      "Use as a staging point for WannaCry-style ransomware attacks",
      "Perform DCOM-based attacks to escalate privileges",
    ],
    fixCode: `# Block immediately with Windows Firewall
netsh advfirewall firewall add rule \\
  name="Block MSRPC Internet" \\
  dir=in action=block \\
  protocol=TCP localport=135 \\
  remoteip=0.0.0.0/0

# AWS Security Group
aws ec2 revoke-security-group-ingress \\
  --group-id sg-XXXXXXXX \\
  --protocol tcp --port 135 --cidr 0.0.0.0/0`,
  },
  {
    id: "f5",
    severity: "high",
    title: "Sensitive Port 25 Open — SMTP",
    host: "hiranandani.com",
    source: "nmap",
    port: 25,
    description: "Port 25 (SMTP mail relay) is publicly accessible. Open SMTP relays can be abused to send spam and phishing emails on behalf of your domain, harming your brand reputation and deliverability.",
    action: "Restrict port 25 to authorised mail servers only. Configure SPF, DKIM, and DMARC records to protect your domain from spoofing.",
    timestamp: "2026-04-18T13:32:48",
    whatItIs: "SMTP (Simple Mail Transfer Protocol) on port 25 is used for sending email. An open relay allows anyone to send emails appearing to come from your domain.",
    whyItMatters: "Open SMTP relays are heavily abused for sending spam and phishing emails. This damages your domain's sending reputation and can get your domain blacklisted, destroying email deliverability.",
    attackerCan: [
      "Send phishing emails that appear to come from hiranandani.com",
      "Relay spam through your mail server at no cost",
      "Damage your email deliverability and brand trust",
      "Bypass spam filters at target organisations",
    ],
    fixCode: `# Postfix — restrict relay
smtpd_relay_restrictions =
  permit_mynetworks,
  permit_sasl_authenticated,
  reject_unauth_destination

# Add SPF record to DNS
hiranandani.com. IN TXT "v=spf1 include:_spf.google.com -all"

# Add DMARC record
_dmarc.hiranandani.com. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@hiranandani.com"`,
  },
  {
    id: "f6",
    severity: "high",
    title: "Public Cloud Bucket Exposed — S3",
    host: "hiranandani.com",
    source: "cloud",
    port: null,
    description: "The S3 bucket 'hiranandani' (hiranandani.s3.amazonaws.com) is publicly accessible (HTTP 200). Anyone on the internet can read its contents without authentication.",
    action: "Immediately set the bucket ACL/policy to private. Audit contents for sensitive data. Enable S3 access logging and block public access at the account level.",
    timestamp: "2026-04-18T13:34:33",
    whatItIs: "An AWS S3 storage bucket with public read/list access enabled. Anyone with the URL can enumerate and download every object in the bucket without credentials.",
    whyItMatters: "S3 bucket exposure is one of the most common and impactful cloud misconfigurations. Sensitive data including documents, images, and config files may be publicly readable.",
    attackerCan: [
      "List all files in the bucket via directory listing",
      "Download any stored file without authentication",
      "Find documents containing sensitive business information",
      "Use discovered data in targeted social engineering attacks",
    ],
    fixCode: `# Block all public access (recommended)
aws s3api put-public-access-block \\
  --bucket hiranandani \\
  --public-access-block-configuration \\
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Remove existing public ACL
aws s3api put-bucket-acl \\
  --bucket hiranandani \\
  --acl private`,
    exposedFiles: ["09augmiddle.jpg", "123.jpg", "12juneomr.jpg", "29may_deven.jpg", "29may_omr.jpg"],
  },
  {
    id: "f7",
    severity: "high",
    title: "Bucket Directory Listing Enabled — S3",
    host: "hiranandani.com",
    source: "cloud",
    port: null,
    description: "The S3 bucket 'hiranandani' has directory listing enabled — all stored files can be enumerated. Files found: 09augmiddle.jpg, 123.jpg, 12juneomr.jpg, 29may_deven.jpg, 29may_omr.jpg and more.",
    action: "Disable public listing on the bucket. Review all listed objects for sensitive data and rotate any exposed credentials immediately.",
    timestamp: "2026-04-18T13:34:33",
    whatItIs: "Directory listing on an S3 bucket exposes a complete index of all stored files, making it trivial to enumerate and download every object.",
    whyItMatters: "Even if individual files seem harmless, the complete listing reveals the organisational structure and may expose internal file naming conventions, project names, or sensitive documents.",
    attackerCan: [
      "Enumerate all stored files with a single HTTP request",
      "Systematically download every file in the bucket",
      "Identify naming patterns that reveal internal project structures",
      "Find backup files or configuration files accidentally uploaded",
    ],
    fixCode: `# Disable listing via bucket policy
aws s3api put-bucket-policy --bucket hiranandani --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:ListBucket",
    "Resource": "arn:aws:s3:::hiranandani"
  }]
}'`,
    exposedFiles: ["09augmiddle.jpg", "123.jpg", "12juneomr.jpg", "29may_deven.jpg", "29may_omr.jpg"],
  },
  {
    id: "f8",
    severity: "high",
    title: "Sensitive Port 53 Open — DNS",
    host: "hiranandani.com",
    source: "nmap",
    port: 53,
    description: "Port 53 (DNS) is publicly accessible via TCP. This may indicate an open DNS resolver, which can be abused for DNS amplification DDoS attacks targeting third parties.",
    action: "Restrict TCP/53 to authorised nameservers only. Disable recursive queries for external clients to prevent use as an open resolver.",
    timestamp: "2026-04-18T13:32:48",
    whatItIs: "DNS on port 53/TCP being accessible externally can indicate an open recursive resolver — a server that will answer DNS queries for any external party.",
    whyItMatters: "Open DNS resolvers are weaponised for DDoS amplification attacks — attackers use your server to flood victims with DNS traffic, causing legal and operational risk for your organisation.",
    attackerCan: [
      "Use your DNS server in DDoS amplification attacks",
      "Attempt DNS zone transfers to enumerate all records",
      "Conduct cache poisoning attacks",
      "Potentially use your infrastructure in illegal attacks",
    ],
    fixCode: `# BIND — disable recursion for external IPs
options {
    allow-recursion { 10.0.0.0/8; 127.0.0.1; }; // internal only
    allow-transfer  { none; };                    // disable zone transfer
    recursion yes;
};`,
  },
  {
    id: "f9",
    severity: "high",
    title: "Sensitive Port 139 Open — NetBIOS",
    host: "www.hiranandani.com",
    source: "nmap",
    port: 139,
    description: "Port 139 (NetBIOS Session Service) is publicly accessible. This Windows file-sharing protocol should never be exposed to the internet under any circumstances.",
    action: "Block port 139 at the firewall immediately. This service has no legitimate reason to be internet-facing.",
    timestamp: "2026-04-18T13:32:48",
    whatItIs: "NetBIOS on port 139 is a Windows network protocol used for file and printer sharing on local networks. It was never designed for internet exposure.",
    whyItMatters: "NetBIOS was exploited by the WannaCry and NotPetya ransomware outbreaks that caused billions in damages. It exposes Windows computer names, workgroup information, and can be used for NTLM relay attacks.",
    attackerCan: [
      "Enumerate Windows hostnames and workgroup information",
      "Perform NTLM credential capture and relay attacks",
      "Exploit unpatched NetBIOS vulnerabilities",
      "Use as a pivot point for ransomware deployment",
    ],
    fixCode: `# Block NetBIOS at firewall immediately
netsh advfirewall firewall add rule \\
  name="Block NetBIOS" \\
  dir=in action=block \\
  protocol=TCP localport=139

# Also block 445 (SMB) if exposed
netsh advfirewall firewall add rule \\
  name="Block SMB" \\
  dir=in action=block \\
  protocol=TCP localport=445`,
  },
  {
    id: "f10",
    severity: "medium",
    title: "Unencrypted HTTP Traffic — Port 80",
    host: "hiranandani.com",
    source: "nmap",
    port: 80,
    description: "Port 80 (HTTP) is open and serving unencrypted traffic. Data transmitted over HTTP can be intercepted by anyone on the network path between the user and the server.",
    action: "Redirect all HTTP traffic to HTTPS with a 301 redirect. Implement HSTS (Strict-Transport-Security) to enforce secure connections going forward.",
    timestamp: "2026-04-18T13:32:48",
    whatItIs: "HTTP (port 80) serves web content without encryption. All requests, responses, cookies, and form submissions are transmitted in plaintext.",
    whyItMatters: "On any network between the user and server — coffee shops, hotels, corporate networks — anyone can read or modify HTTP traffic. This enables account takeover and data theft.",
    attackerCan: [
      "Intercept login credentials and session cookies",
      "Inject malicious JavaScript into HTTP responses",
      "Perform man-in-the-middle attacks to modify page content",
      "Monitor user browsing behaviour on the site",
    ],
    fixCode: `# Nginx — force HTTPS redirect
server {
    listen 80;
    server_name hiranandani.com;
    return 301 https://$server_name$request_uri;
}

# Add HSTS header (in HTTPS server block)
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`,
  },
  {
    id: "f11",
    severity: "medium",
    title: "TLS Configuration Review Needed — Port 443",
    host: "hiranandani.com",
    source: "nmap",
    port: 443,
    description: "Port 443 (HTTPS) is open. This is expected for a public website, but the TLS configuration should be audited to ensure only modern protocols and cipher suites are in use.",
    action: "Ensure TLS 1.2+ is enforced. Disable SSLv3, TLS 1.0, and TLS 1.1. Use a strong cipher suite and enable HSTS.",
    timestamp: "2026-04-18T13:32:48",
    whatItIs: "HTTPS on port 443 uses TLS to encrypt web traffic. However, older TLS versions (1.0, 1.1) and weak cipher suites can still be negotiated if not explicitly disabled.",
    whyItMatters: "Outdated TLS protocols are vulnerable to BEAST, POODLE, and downgrade attacks. Modern browsers and PCI DSS require TLS 1.2 or higher.",
    attackerCan: [
      "Downgrade TLS to older, vulnerable versions",
      "Exploit weak cipher suites to decrypt traffic",
      "Perform BEAST or POODLE attacks on TLS 1.0 connections",
      "Intercept sensitive data if downgrade succeeds",
    ],
    fixCode: `# Nginx — modern TLS configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
ssl_prefer_server_ciphers off;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;`,
  },
  {
    id: "f12",
    severity: "medium",
    title: "Unencrypted HTTP Traffic — Port 80",
    host: "www.hiranandani.com",
    source: "nmap",
    port: 80,
    description: "Port 80 (HTTP) is open on www.hiranandani.com serving unencrypted traffic. All data between users and this subdomain is transmitted in plaintext.",
    action: "Redirect all HTTP to HTTPS with a 301 permanent redirect. Enable HSTS header on the HTTPS response.",
    timestamp: "2026-04-18T13:32:48",
    whatItIs: "The www subdomain is serving traffic over unencrypted HTTP in addition to (or instead of) HTTPS.",
    whyItMatters: "Users accessing www.hiranandani.com over HTTP have their traffic exposed. Attackers on shared networks can intercept all data including authentication tokens.",
    attackerCan: [
      "Intercept session cookies and hijack user sessions",
      "Inject ads, trackers, or malware into HTTP pages",
      "Observe all user activity on the site",
      "Perform SSL stripping to prevent HTTPS upgrade",
    ],
    fixCode: `# Nginx — add HTTPS redirect for www
server {
    listen 80;
    server_name www.hiranandani.com;
    return 301 https://www.hiranandani.com$request_uri;
}`,
  },
];

// Log entries matched to hiranandani.com scan data
export const DEMO_LOGS = [
  { type: "info",  message: "Initialising NetMap passive reconnaissance..." },
  { type: "info",  message: "Target: hiranandani.com" },
  { type: "info",  message: "Starting DNS enumeration..." },
  { type: "found", message: "Found subdomain: www.hiranandani.com" },
  { type: "found", message: "Found subdomain: webmail.hiranandani.com" },
  { type: "found", message: "Found subdomain: mail.hiranandani.com" },
  { type: "found", message: "Found subdomain: api.hiranandani.com" },
  { type: "found", message: "Found subdomain: dev.hiranandani.com" },
  { type: "info",  message: "DNS enumeration complete — 5 subdomains discovered" },
  { type: "info",  message: "Resolving DNS for 6 hosts..." },
  { type: "info",  message: "Starting TLS certificate analysis..." },
  { type: "warn",  message: "HTTP only (no TLS redirect): hiranandani.com" },
  { type: "warn",  message: "HTTP only (no TLS redirect): www.hiranandani.com" },
  { type: "info",  message: "Starting port scan (passive)..." },
  { type: "warn",  message: "Port 21 (FTP) open: hiranandani.com" },
  { type: "warn",  message: "Port 25 (SMTP) open: hiranandani.com" },
  { type: "warn",  message: "Port 53 (DNS/TCP) open: hiranandani.com" },
  { type: "warn",  message: "Port 80 (HTTP) open: hiranandani.com" },
  { type: "warn",  message: "Port 80 (HTTP) open: www.hiranandani.com" },
  { type: "warn",  message: "Port 135 (MSRPC) open: hiranandani.com" },
  { type: "warn",  message: "Port 139 (NetBIOS) open: www.hiranandani.com" },
  { type: "warn",  message: "Port 443 (HTTPS) open: hiranandani.com" },
  { type: "warn",  message: "Port 3389 (RDP) open: hiranandani.com" },
  { type: "info",  message: "Port scan complete — 9 open ports detected" },
  { type: "info",  message: "Checking admin interface exposure..." },
  { type: "error", message: "Admin panel detected: webmail.hiranandani.com (publicly accessible)" },
  { type: "info",  message: "Checking cloud storage buckets..." },
  { type: "error", message: "CRITICAL: S3 bucket 'hiranandani' is PUBLIC — HTTP 200" },
  { type: "error", message: "CRITICAL: Directory listing enabled on S3 bucket 'hiranandani'" },
  { type: "info",  message: "Checking security headers..." },
  { type: "warn",  message: "Missing HSTS header: hiranandani.com" },
  { type: "warn",  message: "Missing HSTS header: www.hiranandani.com" },
  { type: "info",  message: "Generating risk analysis..." },
  { type: "found", message: "Scan complete — 12 findings across 6 assets" },
];

// Scan stages for the stage tracker
export const SCAN_STAGES = [
  { id: "recon",   label: "DNS Recon",     description: "Subdomain enumeration" },
  { id: "tls",     label: "TLS Scan",      description: "Certificate & protocol" },
  { id: "ports",   label: "Port Scan",     description: "Open port detection" },
  { id: "cloud",   label: "Cloud Probe",   description: "Bucket & storage scan" },
  { id: "admin",   label: "Admin Check",   description: "Exposed panels & paths" },
  { id: "analysis",label: "Risk Analysis", description: "Scoring & reporting" },
];

export const MOCK_SUBDOMAINS = [
  "hiranandani.com",
  "www.hiranandani.com",
  "webmail.hiranandani.com",
  "mail.hiranandani.com",
  "api.hiranandani.com",
  "dev.hiranandani.com",
];
