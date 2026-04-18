export const DEMO_FINDINGS = [
  {
    id: "f1",
    severity: "critical",
    title: "Open S3 Bucket",
    host: "assets.demo.netmap.io",
    description: "Publicly accessible storage with 847 files — including .env and config files that may contain secrets.",
    action: "Apply restrictive IAM bucket policy and enable Block Public Access",
    source: "cloud-storage-probe",
    timestamp: "2024-01-15T14:32:45Z",
    whatItIs: "A cloud storage bucket with public read/list access enabled. Anyone on the internet can enumerate and download every object in the bucket.",
    whyItMatters: "Sensitive data, credentials, API keys, or customer PII may be exposed without any authentication. This is one of the most common and impactful cloud misconfigurations.",
    attackerCan: [
      "Download all 847 files in the bucket",
      "Extract API keys from .env files",
      "Exfiltrate customer PII and personal data",
      "Use discovered credentials in follow-on attacks",
    ],
    fixCode: `aws s3api put-public-access-block \\
  --bucket assets-demo-netmap-io \\
  --public-access-block-configuration \\
  BlockPublicAcls=true,\\
  IgnorePublicAcls=true,\\
  BlockPublicPolicy=true,\\
  RestrictPublicBuckets=true`,
  },
  {
    id: "f2",
    severity: "critical",
    title: "Exposed Admin Panel",
    host: "admin.demo.netmap.io",
    description: "Login page publicly reachable — no VPN or IP restriction in place.",
    action: "Restrict to VPN/IP allowlist via WAF rule",
    source: "admin-panel-heuristics",
    timestamp: "2024-01-15T14:33:01Z",
    whatItIs: "An administrative panel that is accessible from any IP address on the internet without VPN or network-level restrictions.",
    whyItMatters: "Admin panels are high-value targets. Without IP restrictions, attackers can attempt brute-force, credential stuffing, or exploit known vulnerabilities to gain full system control.",
    attackerCan: [
      "Brute-force admin credentials",
      "Attempt credential stuffing from leaked databases",
      "Exploit known CMS vulnerabilities",
      "Gain full administrative access to the application",
    ],
    fixCode: `# AWS WAF IP Set Rule
aws wafv2 create-ip-set \\
  --name admin-allowlist \\
  --scope REGIONAL \\
  --ip-address-version IPV4 \\
  --addresses "203.0.113.0/24" "198.51.100.0/24"`,
  },
  {
    id: "f3",
    severity: "high",
    title: "Missing HTTPS (TLS)",
    host: "dev.demo.netmap.io",
    description: "Development server only accessible over HTTP — all traffic sent in plaintext.",
    action: "Provision TLS certificate and enforce HTTPS redirect",
    source: "tls-scanner",
    timestamp: "2024-01-15T14:33:15Z",
    whatItIs: "This host serves traffic over unencrypted HTTP only, with no TLS/SSL certificate configured.",
    whyItMatters: "All data transmitted to and from this server — including credentials and session tokens — can be intercepted by anyone on the network path.",
    attackerCan: [
      "Intercept login credentials via MITM attack",
      "Steal session cookies to hijack accounts",
      "Inject malicious content into responses",
      "Monitor all user activity on the site",
    ],
    fixCode: `# Using certbot for Let's Encrypt
sudo certbot --nginx -d dev.demo.netmap.io

# Force HTTPS redirect in nginx
server {
    listen 80;
    server_name dev.demo.netmap.io;
    return 301 https://$server_name$request_uri;
}`,
  },
  {
    id: "f4",
    severity: "high",
    title: "Exposed .git Directory",
    host: "staging.demo.netmap.io",
    description: "Git metadata directory accessible — full source code can be reconstructed.",
    action: "Block access to .git directory in web server config",
    source: "path-scanner",
    timestamp: "2024-01-15T14:33:28Z",
    whatItIs: "The .git directory is exposed via the web server, allowing anyone to download the full Git history and reconstruct the complete source code.",
    whyItMatters: "Source code contains business logic, hardcoded secrets, internal APIs, and configuration details that significantly aid targeted attacks.",
    attackerCan: [
      "Reconstruct full source code from Git objects",
      "Extract hardcoded API keys and database credentials",
      "Identify business logic vulnerabilities",
      "Map internal API endpoints for further exploitation",
    ],
    fixCode: `# Nginx — block .git access
location ~ /\\.git {
    deny all;
    return 404;
}

# Apache — .htaccess
RedirectMatch 404 /\\.git`,
  },
  {
    id: "f5",
    severity: "high",
    title: "Subdomain Takeover Risk",
    host: "legacy.demo.netmap.io",
    description: "CNAME points to deprovisioned Heroku app — domain can be claimed by attacker.",
    action: "Remove dangling DNS record or re-provision the service",
    source: "dns-cname-check",
    timestamp: "2024-01-15T14:33:42Z",
    whatItIs: "This subdomain has a CNAME record pointing to a cloud service (Heroku) that has been deprovisioned. An attacker can register the same app name and take control of the subdomain.",
    whyItMatters: "Subdomain takeover allows attackers to serve arbitrary content under your domain, bypass same-origin policies, steal cookies, and conduct phishing attacks.",
    attackerCan: [
      "Claim the subdomain by registering the Heroku app",
      "Serve phishing pages under your trusted domain",
      "Steal cookies scoped to the parent domain",
      "Bypass content security policies",
    ],
    fixCode: `# Remove the dangling CNAME record
aws route53 change-resource-record-sets \\
  --hosted-zone-id Z1234567890 \\
  --change-batch '{
    "Changes": [{
      "Action": "DELETE",
      "ResourceRecordSet": {
        "Name": "legacy.demo.netmap.io",
        "Type": "CNAME",
        "TTL": 300,
        "ResourceRecords": [{"Value": "legacy-app.herokuapp.com"}]
      }
    }]
  }'`,
  },
  {
    id: "f6",
    severity: "high",
    title: "Outdated TLS (TLS 1.0)",
    host: "api.demo.netmap.io",
    description: "API endpoint supports deprecated TLS 1.0 which has known vulnerabilities.",
    action: "Disable TLS 1.0/1.1 and require TLS 1.2+",
    source: "tls-scanner",
    timestamp: "2024-01-15T14:33:55Z",
    whatItIs: "This host still supports TLS 1.0, a deprecated protocol version with known cryptographic weaknesses including BEAST and POODLE attacks.",
    whyItMatters: "Modern compliance standards (PCI DSS, HIPAA) require TLS 1.2 or higher. TLS 1.0 allows downgrade attacks that can decrypt sensitive traffic.",
    attackerCan: [
      "Perform BEAST or POODLE attacks to decrypt traffic",
      "Downgrade connections to exploit weak ciphers",
      "Intercept API authentication tokens",
    ],
    fixCode: `# Nginx — disable old TLS
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
ssl_prefer_server_ciphers off;`,
  },
  {
    id: "f7",
    severity: "high",
    title: "Open GraphQL Introspection",
    host: "api.demo.netmap.io",
    description: "GraphQL endpoint allows introspection queries — full API schema exposed.",
    action: "Disable introspection in production",
    source: "api-scanner",
    timestamp: "2024-01-15T14:34:02Z",
    whatItIs: "The GraphQL API allows introspection queries, exposing the complete schema including all types, fields, mutations, and relationships.",
    whyItMatters: "A fully mapped API schema gives attackers a detailed blueprint of your data model and available operations, dramatically reducing time to find and exploit vulnerabilities.",
    attackerCan: [
      "Map the entire API surface automatically",
      "Discover sensitive mutations and queries",
      "Identify authorization bypass opportunities",
      "Find deprecated but still-functional endpoints",
    ],
    fixCode: `// Apollo Server — disable introspection
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: false,
  plugins: [ApolloServerPluginLandingPageDisabled()],
});`,
  },
  {
    id: "f8",
    severity: "medium",
    title: "Missing Security Headers",
    host: "www.demo.netmap.io",
    description: "X-Frame-Options, CSP, and HSTS headers not present — clickjacking and XSS risk.",
    action: "Add security headers via web server or CDN configuration",
    source: "header-audit",
    timestamp: "2024-01-15T14:34:10Z",
    whatItIs: "Critical security headers are missing from HTTP responses, leaving the application vulnerable to common web attacks.",
    whyItMatters: "Without these headers, the site is vulnerable to clickjacking (iframe embedding), cross-site scripting, MIME type confusion, and protocol downgrade attacks.",
    attackerCan: [
      "Embed the site in a malicious iframe for clickjacking",
      "Inject scripts via XSS without CSP restrictions",
      "Perform MIME-type confusion attacks",
    ],
    fixCode: `# Nginx security headers
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;`,
  },
  {
    id: "f9",
    severity: "medium",
    title: "Server Version Exposed",
    host: "api.demo.netmap.io",
    description: "Server header reveals Apache/2.4.41 — version-specific exploits may apply.",
    action: "Remove or obfuscate Server header",
    source: "header-audit",
    timestamp: "2024-01-15T14:34:18Z",
    whatItIs: "The HTTP Server header discloses the exact web server software and version number in every response.",
    whyItMatters: "Knowing the exact server version lets attackers search CVE databases for known vulnerabilities specific to that version, reducing attack effort significantly.",
    attackerCan: [
      "Look up CVEs for Apache 2.4.41 specifically",
      "Use automated exploit kits targeting this version",
      "Chain version info with other findings for targeted attacks",
    ],
    fixCode: `# Apache — hide version
ServerTokens Prod
ServerSignature Off

# Nginx
server_tokens off;`,
  },
  {
    id: "f10",
    severity: "medium",
    title: "CORS Wildcard Policy",
    host: "api.demo.netmap.io",
    description: "Access-Control-Allow-Origin set to * — any website can make authenticated requests.",
    action: "Restrict CORS to specific trusted origins",
    source: "header-audit",
    timestamp: "2024-01-15T14:34:25Z",
    whatItIs: "The API returns Access-Control-Allow-Origin: * which means any website on the internet can make cross-origin requests to this API.",
    whyItMatters: "A wildcard CORS policy combined with credentialed requests can allow malicious websites to steal user data or perform actions on behalf of authenticated users.",
    attackerCan: [
      "Create a malicious page that reads data from the API",
      "Steal user data through cross-origin requests",
      "Perform state-changing operations via CSRF-like attacks",
    ],
    fixCode: `// Express.js — restrict CORS
const cors = require('cors');
app.use(cors({
  origin: ['https://www.demo.netmap.io', 'https://app.demo.netmap.io'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));`,
  },
  {
    id: "f11",
    severity: "medium",
    title: "Directory Listing Enabled",
    host: "docs.demo.netmap.io",
    description: "Web server shows file listing for /assets/ and /uploads/ directories.",
    action: "Disable directory listing in server config",
    source: "path-scanner",
    timestamp: "2024-01-15T14:34:32Z",
    whatItIs: "The web server has directory listing enabled, allowing anyone to browse the contents of certain directories.",
    whyItMatters: "Directory listings can expose sensitive files, backup files, configuration files, and internal documentation that shouldn't be publicly accessible.",
    attackerCan: [
      "Discover hidden files and backup copies",
      "Find configuration files with credentials",
      "Map the application structure",
    ],
    fixCode: `# Nginx
autoindex off;

# Apache .htaccess
Options -Indexes`,
  },
  {
    id: "f12",
    severity: "medium",
    title: "SPF Record Missing",
    host: "demo.netmap.io",
    description: "No SPF DNS record — domain can be used for email spoofing.",
    action: "Add SPF record to DNS configuration",
    source: "dns-record-check",
    timestamp: "2024-01-15T14:34:38Z",
    whatItIs: "The domain lacks a Sender Policy Framework (SPF) DNS record, which specifies which mail servers are authorized to send email on behalf of the domain.",
    whyItMatters: "Without SPF, attackers can send emails appearing to come from your domain. This enables phishing attacks that are hard for recipients to detect.",
    attackerCan: [
      "Send phishing emails that appear to come from your domain",
      "Bypass email filters at target organizations",
      "Damage brand reputation through spoofed messages",
    ],
    fixCode: `# Add SPF record to DNS
demo.netmap.io. IN TXT "v=spf1 include:_spf.google.com include:sendgrid.net -all"`,
  },
  {
    id: "f13",
    severity: "medium",
    title: "DMARC Not Configured",
    host: "demo.netmap.io",
    description: "No DMARC policy set — email authentication failures go unmonitored.",
    action: "Add DMARC DNS record with monitoring",
    source: "dns-record-check",
    timestamp: "2024-01-15T14:34:44Z",
    whatItIs: "No DMARC (Domain-based Message Authentication, Reporting & Conformance) record exists for this domain.",
    whyItMatters: "Without DMARC, there is no mechanism to enforce email authentication or receive reports about unauthorized use of the domain for sending email.",
    attackerCan: [
      "Spoof emails without detection by your security team",
      "Conduct phishing campaigns using your domain",
      "Bypass recipient email filters",
    ],
    fixCode: `# Add DMARC record
_dmarc.demo.netmap.io. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@demo.netmap.io; pct=100"`,
  },
  {
    id: "f14",
    severity: "medium",
    title: "Cookie Missing Secure Flag",
    host: "www.demo.netmap.io",
    description: "Session cookie sent over HTTP — can be intercepted on unsecured networks.",
    action: "Set Secure and HttpOnly flags on all session cookies",
    source: "cookie-audit",
    timestamp: "2024-01-15T14:34:50Z",
    whatItIs: "Session cookies are set without the Secure flag, meaning they can be transmitted over unencrypted HTTP connections.",
    whyItMatters: "On public WiFi or compromised networks, attackers can intercept these cookies and hijack user sessions.",
    attackerCan: [
      "Steal session cookies via network sniffing",
      "Hijack authenticated user sessions",
      "Access user accounts without credentials",
    ],
    fixCode: `// Express.js session config
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 3600000,
  },
}));`,
  },
  {
    id: "f15",
    severity: "low",
    title: "Robots.txt Exposes Paths",
    host: "www.demo.netmap.io",
    description: "Robots.txt reveals internal paths: /admin, /api/internal, /debug.",
    action: "Remove sensitive paths from robots.txt",
    source: "path-scanner",
    timestamp: "2024-01-15T14:34:55Z",
    whatItIs: "The robots.txt file explicitly lists internal paths that should not be crawled, inadvertently revealing them to attackers.",
    whyItMatters: "While robots.txt is meant for search engine crawlers, attackers routinely check it to discover hidden endpoints and administrative pages.",
    attackerCan: [
      "Discover hidden admin and debug endpoints",
      "Map internal API paths",
      "Use discovered paths for targeted attacks",
    ],
    fixCode: `# Simplified robots.txt — don't list sensitive paths
User-agent: *
Disallow: /

# Instead, use proper authentication and access controls`,
  },
  {
    id: "f16",
    severity: "low",
    title: "DNS Zone Transfer Allowed",
    host: "ns1.demo.netmap.io",
    description: "DNS server allows AXFR zone transfer — full subdomain list exposed.",
    action: "Restrict zone transfers to authorized secondary nameservers only",
    source: "dns-zone-check",
    timestamp: "2024-01-15T14:35:00Z",
    whatItIs: "The DNS server allows zone transfer (AXFR) requests from any IP, exposing the complete list of DNS records and subdomains.",
    whyItMatters: "An attacker can enumerate all subdomains instantly without brute-forcing, revealing the full attack surface including internal and staging services.",
    attackerCan: [
      "Enumerate all subdomains in a single query",
      "Discover internal services not intended to be public",
      "Map the entire infrastructure",
    ],
    fixCode: `# BIND — restrict zone transfers
zone "demo.netmap.io" {
    type master;
    allow-transfer { 198.51.100.1; };  // secondary NS only
};`,
  },
  {
    id: "f17",
    severity: "low",
    title: "Unnecessary Open Ports",
    host: "staging.demo.netmap.io",
    description: "Ports 8080, 8443, 9090 publicly accessible — non-standard services exposed.",
    action: "Restrict non-essential ports via security group / firewall",
    source: "port-scan-passive",
    timestamp: "2024-01-15T14:35:05Z",
    whatItIs: "Multiple non-standard ports are accessible from the internet, potentially running development or management services.",
    whyItMatters: "Each open port is an additional attack vector. Non-standard ports often run less-hardened services with weaker authentication.",
    attackerCan: [
      "Probe non-standard services for vulnerabilities",
      "Access development or debug tools",
      "Find management interfaces with default credentials",
    ],
    fixCode: `# AWS Security Group — restrict ports
aws ec2 revoke-security-group-ingress \\
  --group-id sg-12345678 \\
  --protocol tcp \\
  --port 8080 \\
  --cidr 0.0.0.0/0`,
  },
  {
    id: "f18",
    severity: "low",
    title: "WHOIS Info Public",
    host: "demo.netmap.io",
    description: "Domain WHOIS record exposes registrant name, email, and phone number.",
    action: "Enable WHOIS privacy protection through registrar",
    source: "whois-lookup",
    timestamp: "2024-01-15T14:35:10Z",
    whatItIs: "The domain WHOIS record contains personal information about the registrant, including name, email address, and phone number.",
    whyItMatters: "This information can be used for social engineering, targeted phishing, and gathering intelligence for more sophisticated attacks.",
    attackerCan: [
      "Craft targeted phishing emails to the domain owner",
      "Use personal info for social engineering",
      "Correlate with other leaked data",
    ],
    fixCode: `# Enable WHOIS privacy via your registrar's dashboard
# Most registrars offer this for free:
# - Namecheap: WhoisGuard
# - GoDaddy: Domain Privacy
# - Cloudflare: Automatic WHOIS redaction`,
  },
  {
    id: "f19",
    severity: "low",
    title: "Sitemap Reveals Structure",
    host: "www.demo.netmap.io",
    description: "XML sitemap exposes application structure including unlisted pages.",
    action: "Review sitemap entries and remove internal pages",
    source: "path-scanner",
    timestamp: "2024-01-15T14:35:15Z",
    whatItIs: "The XML sitemap lists URLs including pages that are not linked from the main navigation, potentially revealing internal or pre-release features.",
    whyItMatters: "Detailed sitemaps help attackers understand the application structure and find pages that may have weaker security controls.",
    attackerCan: [
      "Discover unlisted pages and features",
      "Find pre-release or beta endpoints",
      "Map the application structure for targeted attacks",
    ],
    fixCode: `<!-- Only include public pages in sitemap -->
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://www.demo.netmap.io/</loc></url>
  <url><loc>https://www.demo.netmap.io/about</loc></url>
  <!-- Remove internal/admin/staging URLs -->
</urlset>`,
  },
  {
    id: "f20",
    severity: "low",
    title: "Email Addresses Leaked",
    host: "www.demo.netmap.io",
    description: "3 email addresses found in page source — potential phishing targets.",
    action: "Replace with contact forms or obfuscate addresses",
    source: "content-scanner",
    timestamp: "2024-01-15T14:35:18Z",
    whatItIs: "Employee email addresses are embedded in publicly accessible web pages, making them targets for automated scraping.",
    whyItMatters: "Exposed email addresses are directly used for phishing campaigns, credential stuffing, and social engineering attacks.",
    attackerCan: [
      "Add addresses to phishing campaign target lists",
      "Attempt credential stuffing against known services",
      "Craft spear-phishing emails using gathered context",
    ],
    fixCode: `<!-- Replace direct email links with contact form -->
<a href="/contact">Contact Us</a>

<!-- Or obfuscate -->
<span data-email="support" data-domain="demo.netmap.io">
  Enable JavaScript to see email
</span>`,
  },
  {
    id: "f21",
    severity: "medium",
    title: "Exposed Environment File",
    host: "staging.demo.netmap.io",
    description: ".env file accessible at /.env — may contain API keys and database credentials.",
    action: "Block access to dotfiles in web server config",
    source: "path-scanner",
    timestamp: "2024-01-15T14:35:22Z",
    whatItIs: "The .env configuration file is accessible via the web server, potentially exposing database credentials, API keys, and other sensitive configuration.",
    whyItMatters: "Environment files typically contain the most sensitive secrets in an application — database passwords, API keys, encryption keys, and third-party service credentials.",
    attackerCan: [
      "Extract database connection strings",
      "Steal API keys for cloud services",
      "Gain access to third-party integrations",
      "Use credentials for lateral movement",
    ],
    fixCode: `# Nginx — block all dotfiles
location ~ /\\. {
    deny all;
    return 404;
}`,
  },
  {
    id: "f22",
    severity: "medium",
    title: "Unencrypted API Endpoint",
    host: "internal-api.demo.netmap.io",
    description: "Internal API accessible without encryption from external networks.",
    action: "Move behind VPN or add TLS and authentication",
    source: "api-scanner",
    timestamp: "2024-01-15T14:35:26Z",
    whatItIs: "An internal API service is publicly accessible without encryption, intended only for inter-service communication.",
    whyItMatters: "Internal APIs often lack authentication and authorization checks, assuming they are only accessed from trusted networks.",
    attackerCan: [
      "Access internal service data without authentication",
      "Enumerate internal API endpoints",
      "Manipulate internal operations",
    ],
    fixCode: `# Move behind AWS PrivateLink or VPN
# Or add API Gateway with auth:
aws apigateway create-rest-api \\
  --name 'internal-api-gateway' \\
  --endpoint-configuration types=PRIVATE`,
  },
  {
    id: "f23",
    severity: "low",
    title: "Weak Cipher Suites",
    host: "mail.demo.netmap.io",
    description: "TLS configuration includes weak cipher suites (RC4, 3DES).",
    action: "Update cipher suite configuration to modern standards",
    source: "tls-scanner",
    timestamp: "2024-01-15T14:35:30Z",
    whatItIs: "The TLS configuration supports outdated and weak cipher suites including RC4 and 3DES that have known cryptographic weaknesses.",
    whyItMatters: "Weak cipher suites can be exploited to decrypt communication. Modern browsers and security standards have deprecated these ciphers.",
    attackerCan: [
      "Exploit cipher weaknesses to decrypt traffic",
      "Perform downgrade attacks",
      "Intercept sensitive email communications",
    ],
    fixCode: `# Nginx — modern cipher suite
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
ssl_prefer_server_ciphers off;`,
  },
];

// Generate demo log entries for the scan simulation
export const DEMO_LOGS = [
  { type: "info", message: "Initializing NetMap passive reconnaissance..." },
  { type: "info", message: "Target: demo.netmap.io" },
  { type: "info", message: "Starting DNS enumeration..." },
  { type: "found", message: "Found subdomain: www.demo.netmap.io" },
  { type: "found", message: "Found subdomain: api.demo.netmap.io" },
  { type: "found", message: "Found subdomain: admin.demo.netmap.io" },
  { type: "found", message: "Found subdomain: dev.demo.netmap.io" },
  { type: "found", message: "Found subdomain: staging.demo.netmap.io" },
  { type: "found", message: "Found subdomain: docs.demo.netmap.io" },
  { type: "found", message: "Found subdomain: mail.demo.netmap.io" },
  { type: "found", message: "Found subdomain: assets.demo.netmap.io" },
  { type: "found", message: "Found subdomain: legacy.demo.netmap.io" },
  { type: "found", message: "Found subdomain: internal-api.demo.netmap.io" },
  { type: "found", message: "Found subdomain: ns1.demo.netmap.io" },
  { type: "info", message: "DNS enumeration complete — 11 subdomains discovered" },
  { type: "info", message: "Starting TLS certificate analysis..." },
  { type: "warn", message: "HTTP only (no TLS): dev.demo.netmap.io" },
  { type: "warn", message: "Outdated TLS 1.0 supported: api.demo.netmap.io" },
  { type: "warn", message: "Weak cipher suites detected: mail.demo.netmap.io" },
  { type: "info", message: "TLS analysis complete" },
  { type: "info", message: "Starting HTTP security header audit..." },
  { type: "warn", message: "Missing security headers: www.demo.netmap.io (X-Frame-Options, CSP, HSTS)" },
  { type: "warn", message: "Server header exposes version: api.demo.netmap.io (Apache/2.4.41)" },
  { type: "warn", message: "CORS wildcard policy: api.demo.netmap.io" },
  { type: "warn", message: "Cookie missing Secure flag: www.demo.netmap.io" },
  { type: "info", message: "Header audit complete" },
  { type: "info", message: "Checking cloud storage buckets..." },
  { type: "error", message: "CRITICAL: Open S3 bucket detected — assets.demo.netmap.io (847 files exposed)" },
  { type: "info", message: "Scanning for exposed admin panels..." },
  { type: "error", message: "CRITICAL: Admin panel publicly accessible — admin.demo.netmap.io" },
  { type: "info", message: "Checking for exposed files and directories..." },
  { type: "error", message: "Exposed .git directory: staging.demo.netmap.io" },
  { type: "warn", message: "Directory listing enabled: docs.demo.netmap.io (/assets/, /uploads/)" },
  { type: "warn", message: "Exposed .env file: staging.demo.netmap.io" },
  { type: "info", message: "Scanning for subdomain takeover risks..." },
  { type: "error", message: "Subdomain takeover possible: legacy.demo.netmap.io → herokuapp.com (NXDOMAIN)" },
  { type: "info", message: "Checking DNS configuration..." },
  { type: "warn", message: "DNS zone transfer allowed: ns1.demo.netmap.io" },
  { type: "warn", message: "SPF record missing: demo.netmap.io" },
  { type: "warn", message: "DMARC not configured: demo.netmap.io" },
  { type: "info", message: "Checking API security..." },
  { type: "warn", message: "GraphQL introspection enabled: api.demo.netmap.io" },
  { type: "warn", message: "Unencrypted API endpoint: internal-api.demo.netmap.io" },
  { type: "info", message: "Checking content for information leakage..." },
  { type: "warn", message: "Robots.txt reveals sensitive paths: www.demo.netmap.io" },
  { type: "warn", message: "XML sitemap exposes unlisted pages: www.demo.netmap.io" },
  { type: "warn", message: "3 email addresses found in page source: www.demo.netmap.io" },
  { type: "info", message: "Passive port analysis..." },
  { type: "warn", message: "Non-standard ports open: staging.demo.netmap.io (8080, 8443, 9090)" },
  { type: "info", message: "WHOIS lookup..." },
  { type: "warn", message: "WHOIS information public: demo.netmap.io" },
  { type: "info", message: "Generating risk analysis..." },
  { type: "info", message: "Scan complete. 23 assets discovered. 23 findings identified." },
];

// Scan stages for the stage tracker
export const SCAN_STAGES = [
  { id: "recon", label: "Recon", description: "DNS & subdomain enumeration" },
  { id: "tls", label: "TLS Scan", description: "Certificate & protocol analysis" },
  { id: "http", label: "HTTP Audit", description: "Headers, cookies & CORS" },
  { id: "cloud", label: "Cloud Probe", description: "Bucket & storage scanning" },
  { id: "vuln", label: "Vuln Check", description: "Exposed files & takeover" },
  { id: "analysis", label: "Analysis", description: "Risk scoring & reporting" },
];
