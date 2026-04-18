# NetMap — Frontend Development Specification
### Shadow IT Discovery & Attack Surface Mapper

---

## 🎯 Design Philosophy

**Aesthetic Direction:** Retro-futuristic hacker SaaS — think _Shodan meets Linear meets a Bloomberg terminal_.  
**One thing judges remember:** The scan feels like watching a real attack unfold in real time — alive, tense, precise.  
**Not:** Purple gradients. Generic dashboards. Student-project vibes.

---

## 🎨 Design System

### Color Palette (CSS Variables)

```css
:root {
  /* Backgrounds */
  --bg-void:       #0B0F17;   /* Page base — near-black navy */
  --bg-surface:    #111827;   /* Cards, panels */
  --bg-elevated:   #1A2233;   /* Hover states, drawers */
  --bg-glass:      rgba(17, 24, 39, 0.72); /* Glassmorphism */

  /* Borders */
  --border-subtle: rgba(255, 255, 255, 0.06);
  --border-active: rgba(255, 255, 255, 0.14);

  /* Severity — the core visual language */
  --critical:      #F43F5E;   /* Rose red */
  --critical-glow: rgba(244, 63, 94, 0.25);
  --high:          #F97316;   /* Orange */
  --high-glow:     rgba(249, 115, 22, 0.2);
  --medium:        #EAB308;   /* Amber */
  --medium-glow:   rgba(234, 179, 8, 0.2);
  --low:           #22C55E;   /* Emerald */
  --low-glow:      rgba(34, 197, 94, 0.2);
  --info:          #3B82F6;   /* Blue */

  /* Accent / Brand */
  --accent:        #00FFB2;   /* Terminal green-cyan — the NetMap signature */
  --accent-dim:    rgba(0, 255, 178, 0.15);
  --accent-glow:   rgba(0, 255, 178, 0.35);

  /* Text */
  --text-primary:  #F1F5F9;
  --text-secondary:#94A3B8;
  --text-muted:    #475569;
  --text-terminal: #00FFB2;   /* Monospace log output */
}
```

### Typography

```css
/* Display / Headings — geometric, technical */
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Syne:wght@600;700;800&display=swap');

--font-display:   'Syne', sans-serif;    /* Bold headings, logo */
--font-body:      'DM Mono', monospace;  /* Everything — keeps terminal feel */
--font-terminal:  'DM Mono', monospace;  /* Log stream, code blocks */

/* Scale */
--text-xs:   0.75rem;   /* 12px — labels, badges */
--text-sm:   0.875rem;  /* 14px — table rows, captions */
--text-base: 1rem;      /* 16px — body */
--text-lg:   1.125rem;  /* 18px — card titles */
--text-xl:   1.5rem;    /* 24px — section headers */
--text-2xl:  2rem;      /* 32px — hero title */
--text-3xl:  3.5rem;    /* 56px — landing headline */
```

### Spacing & Layout

```css
--radius-sm:  4px;
--radius-md:  8px;
--radius-lg:  12px;
--radius-xl:  16px;

/* Grid */
--max-width:  1280px;
--sidebar-w:  280px;
--drawer-w:   420px;
```

### Animation Tokens

```css
--ease-sharp:  cubic-bezier(0.16, 1, 0.3, 1);   /* Snappy entries */
--ease-smooth: cubic-bezier(0.4, 0, 0.2, 1);     /* General transitions */
--ease-bounce: cubic-bezier(0.34, 1.56, 0.64, 1); /* Playful pops */

--duration-fast:   150ms;
--duration-base:   250ms;
--duration-slow:   400ms;
--duration-crawl:  600ms;
```

---

## 🧩 Page Structure & App Flow

```
┌─────────────────────────────────────────┐
│              Navbar                     │
├─────────────────────────────────────────┤
│          Landing Section                │  ← scanStatus: "idle"
├─────────────────────────────────────────┤
│          Scan Screen (Live)             │  ← scanStatus: "running"
├─────────────────────────────────────────┤
│         Results Dashboard               │  ← scanStatus: "done"
│   ┌──────────────────┐  ┌────────────┐  │
│   │  Main Content    │  │  Decision  │  │
│   │  (Graph+Table)   │  │  Panel     │  │
│   └──────────────────┘  └────────────┘  │
├─────────────────────────────────────────┤
│         Detail Drawer (overlay)         │
├─────────────────────────────────────────┤
│         Export Section (footer)         │
└─────────────────────────────────────────┘
```

---

## ⚙️ State Shape

```typescript
interface AppState {
  domain:          string;
  scanStatus:      'idle' | 'running' | 'done';
  progress:        number;          // 0–100
  logs:            LogEntry[];
  findings:        Finding[];
  selectedFinding: Finding | null;
  activeFilter:    Severity | 'all';
  searchQuery:     string;
}

interface LogEntry {
  id:        string;
  timestamp: string;          // HH:MM:SS
  type:      'info' | 'found' | 'warn' | 'error';
  message:   string;
}

interface Finding {
  id:          string;
  severity:    'critical' | 'high' | 'medium' | 'low' | 'info';
  title:       string;
  host:        string;
  description: string;
  action:      string;
  source:      string;
  timestamp:   string;
  // Extended for drawer
  whatItIs?:      string;
  whyItMatters?:  string;
  attackerCan?:   string[];
  fixCode?:       string;
}
```

---

## 🧱 Component Architecture

```
App.jsx
├── Navbar
├── LandingPage                     ← shown when scanStatus === 'idle'
│     ├── HeroHeadline
│     ├── DomainInput
│     ├── QuickSuggestions
│     └── FeaturePills
│
├── ScanScreen                      ← shown when scanStatus === 'running'
│     ├── GlobalProgressBar         (top of screen, full-width)
│     ├── StageTracker (left)
│     └── LogStream (right)
│
├── Dashboard                       ← shown when scanStatus === 'done'
│     ├── SummaryCards
│     ├── AttackGraph
│     ├── FindingsTable
│     │     ├── SeverityFilter
│     │     ├── SearchBar
│     │     └── FindingRow
│     └── DecisionPanel
│
├── DetailDrawer                    ← overlay, shown when selectedFinding !== null
│     ├── DrawerHeader
│     ├── FindingMeta
│     ├── RiskNarrative
│     └── AIFixBlock
│
└── ExportSection
      ├── DownloadButton
      └── CopyButton
```

---

## 📐 Component Specifications

---

### 1. Navbar

**Layout:** Fixed top, `height: 56px`, full-width, `backdrop-filter: blur(16px)`, `border-bottom: 1px solid var(--border-subtle)`

**Left:** Logo mark (hex icon SVG in `--accent`) + wordmark `NETMAP` in `font-display`, weight 800, letter-spacing `0.12em`

**Right:**
- Small text badge: `v1.0 · PASSIVE` — `--text-muted`, monospace
- If scanStatus === 'done': `[ New Scan ]` ghost button

**Micro-detail:** A single 1px `--accent` line at the very top of the navbar (top border, not bottom) — like a monitor bezel highlight.

---

### 2. Landing Page

**Layout:** Full viewport height, flex center, single centered column, max-width 560px

**Background:** `--bg-void` with a very subtle radial gradient mesh centered behind the card:
```css
background: radial-gradient(ellipse 800px 600px at 50% 40%,
  rgba(0,255,178,0.04) 0%,
  transparent 70%);
```

**Hero Headline:**
```
NETMAP
```
- Font: `Syne`, weight 800, size `clamp(3rem, 8vw, 5rem)`
- Color: `--text-primary`
- Tagline below: `Attack Surface. Exposed.` — `--accent`, monospace, `text-sm`, letter-spacing `0.2em`, uppercase

**Input Card:**
- Background: `--bg-surface`
- Border: `1px solid var(--border-subtle)`
- Border-radius: `--radius-xl`
- Padding: `32px`
- Subtle box-shadow: `0 0 60px rgba(0,255,178,0.05)`
- On input focus: border transitions to `1px solid var(--accent)`, glow appears

**Domain Input:**
```
[ 🌐  example.com                    ] [  Start Scan →  ]
```
- Input: monospace font, `--text-primary`, placeholder `--text-muted`
- Prefix icon: subtle globe SVG
- Button: `--accent` text on `--accent-dim` background, `1px solid var(--accent)` border
- Button hover: background becomes `--accent`, text becomes `#0B0F17` (inverted)
- Strip `https://`, `http://`, trailing slashes on submit

**Quick Suggestions:**
```
Try:  [ google.com ]  [ github.com ]  [ tesla.com ]
```
- Pill buttons, `--bg-elevated` background, `--text-muted` text
- Hover: `--border-active`, `--text-secondary`

**Feature Pills (bottom):**
```
⚡ Passive only   🔒 No auth required   🌐 Public sources only
```
- Inline row, monospace `text-xs`, `--text-muted`

**Entry Animation:**
- Logo fades + slides up: `animation: fadeUp 0.6s var(--ease-sharp)`
- Input card fades in 200ms later
- Feature pills fade in 400ms later
- Staggered via `animation-delay`

---

### 3. Scan Screen

**Layout:** Two-column, `gap: 24px`, full viewport height minus navbar

**Top:** Full-width progress bar (see below)

#### 3a. Global Progress Bar

- Thin bar, `height: 3px`, pinned below navbar
- Fill color: `--accent`
- Background: `--border-subtle`
- Animated fill with `transition: width 400ms var(--ease-smooth)`
- Right edge: a small glowing dot `4px × 4px`, `box-shadow: 0 0 8px var(--accent)`

#### 3b. Stage Tracker (Left Column, ~35%)

Title: `SCAN STAGES` — monospace, `text-xs`, `--text-muted`, uppercase, letter-spacing `0.15em`

Each stage row:
```
  ✅  Recon           COMPLETE
  ⟳   DNS Check       RUNNING...
  ○   HTTP Scan       PENDING
  ○   Analysis        PENDING
```

**Stage states:**
| State | Icon | Color |
|-------|------|-------|
| Complete | `✓` checkmark SVG | `--low` (green) |
| Running | Spinning ring SVG | `--accent` |
| Pending | Circle outline | `--text-muted` |

- Running stage row has a subtle left border `2px solid var(--accent)` and `--bg-elevated` background
- Each row: `padding: 12px 16px`, `border-radius: var(--radius-md)`

**Scan metadata below stages:**
```
Target:      example.com
Started:     14:32:08
Elapsed:     0:01:42
Subdomains:  14 found
```
Monospace, `text-xs`, `--text-secondary` labels, `--text-primary` values.

#### 3c. Log Stream (Right Column, ~65%)

Header row:
```
LIVE OUTPUT                              [ CLEAR ]
```

**Log container:**
- Background: `--bg-void`
- Border: `1px solid var(--border-subtle)`
- Border-radius: `--radius-lg`
- Font: monospace, `text-sm`
- `overflow-y: auto`, max-height fills viewport
- Auto-scroll to bottom on new entries

**Log line format:**
```
14:32:09  [+]  Found subdomain: api.example.com
14:32:10  [!]  HTTP only (no TLS): dev.example.com
14:32:11  [*]  Checking bucket: assets-example...
14:32:12  [✗]  Open bucket detected: assets.example.com
```

**Log type colors:**
| Type | Prefix | Color |
|------|--------|-------|
| `info` | `[+]` | `--text-terminal` (accent) |
| `found` | `[+]` | `--low` |
| `warn` | `[!]` | `--medium` |
| `error` | `[✗]` | `--critical` |

**Typing animation:** New log lines appear with a subtle fade-in, `opacity: 0 → 1` over 200ms. The last line has a blinking `_` cursor appended while scan runs.

---

### 4. Dashboard

**Layout:** Main content area (left ~70%) + Decision Panel (right ~30%), `gap: 24px`

#### 4a. Summary Cards (Top Row)

5 cards in a row. Each card:
- Background: `--bg-surface`
- Border: `1px solid var(--border-subtle)`
- Border-radius: `--radius-lg`
- Padding: `20px 24px`
- Hover: `border-color: var(--border-active)`, slight `translateY(-2px)`
- Cursor: pointer (clicking filters the findings table)

**Card structure:**
```
🌐
23
Assets Found
```
- Icon: top, `24px`, colored per severity
- Number: `text-2xl`, `font-display`, bold, white
- Label: `text-xs`, `--text-muted`, uppercase, monospace

**Card active state (when filter applied):**
- Border becomes severity color
- Subtle glow: `box-shadow: 0 0 20px var(--{severity}-glow)`

**Card data:**
```
🌐 Assets Found   →  neutral / --info
🔴 Critical       →  --critical
🟠 High           →  --high
🟡 Medium         →  --medium
🟢 Low            →  --low
```

**Entry animation:** Cards stagger in with `fadeUp` + `animation-delay: calc(N * 80ms)`

---

#### 4b. Attack Surface Graph

**Library:** Use `react-force-graph-2d` or a D3-based canvas graph.

**Visual style:**
- Background: `--bg-surface` with faint grid lines (CSS background pattern, `rgba(255,255,255,0.02)`)
- Node for root domain: larger, hexagonal, `--accent` color
- Nodes for subdomains: circles, colored by highest severity finding
- Edges: `rgba(255,255,255,0.1)`, thin `1px`

**Node colors by severity:**
| Severity | Color |
|----------|-------|
| Critical | `--critical` |
| High | `--high` |
| Medium | `--medium` |
| Low/None | `--low` |

**Hover state:** Node glows (`filter: drop-shadow`), tooltip appears:
```
┌─────────────────────────┐
│ api.example.com          │
│ 🔴 Critical · 2 issues   │
└─────────────────────────┘
```

**Click:** Opens the DetailDrawer for that host's top finding.

**Layout:** Fixed height `320px`, fills card width. Pan + zoom enabled.

---

#### 4c. Findings Table

**Header row:**
```
FINDINGS (23)          [ 🔍 Search hosts, issues... ]
[ All ] [ Critical ] [ High ] [ Medium ] [ Low ]
```

Filter pills: same style as quick suggestions but severity-colored when active.

**Table columns:**
```
SEVERITY  |  ISSUE                    |  HOST                  |  ACTION         |
```

**Row design:**
- Severity: colored badge pill — e.g. `⬤ CRITICAL` in `--critical`, background `rgba(244,63,94,0.1)`
- Issue: `--text-primary`, weight 500
- Host: `--accent`, monospace, `text-sm`
- Action: `--text-secondary`, `text-sm`, truncated
- Hidden "View" column: appears on row hover as `→` arrow icon on right edge
- Row hover: `background: --bg-elevated`, `cursor: pointer`
- Click anywhere on row → opens DetailDrawer

**Default sort:** Critical → High → Medium → Low

**Empty state:**
```
     ◎
  No findings match
  your current filter.
```

---

#### 4d. CTO Decision Panel

**Position:** Right column, sticky `top: 80px`

**Header:**
```
⚡ DECISION BRIEF
```
Monospace, `text-xs`, uppercase, `--accent`

**Fix First block:**
```
🚨 Fix First  ·  HIGH IMPACT

  1  Open S3 Bucket
     assets.example.com

  2  Exposed Admin Panel
     admin.example.com
```
Each item is clickable (opens drawer). Left border `2px solid --critical` for critical items.

**Risk Reduction meter:**
```
Risk Reduction if fixed

Critical  ████████████░░  85%
High      ██████░░░░░░░░  43%
```

Progress bars in severity colors.

**Export shortcut at bottom of panel:**
```
[ 📋 Copy Summary ]   [ ↓ Download Report ]
```

---

### 5. Detail Drawer

**Behavior:**
- Slides in from right: `transform: translateX(100%) → translateX(0)`, `transition: 400ms var(--ease-sharp)`
- Backdrop: `rgba(0,0,0,0.5)` with `backdrop-filter: blur(4px)` over main content
- Close: click backdrop or `✕` button
- Width: `var(--drawer-w)` = 420px (full-width on mobile)

**Header:**
```
✕                     Open S3 Bucket
                       assets.example.com
```
- Title: `font-display`, weight 700, `text-lg`
- Host: `--accent`, monospace, `text-sm`
- Severity badge: large pill top-right

**Sections (with subtle dividers):**

```
WHAT IT IS
──────────
Publicly accessible cloud storage bucket.
Any internet user can list and download files.

WHY IT MATTERS
──────────────
Sensitive data, credentials, or customer PII
may be exposed without authentication.

WHAT AN ATTACKER DOES
─────────────────────
• Downloads all files in bucket
• Searches for API keys, .env files
• Exfiltrates customer data
• Uses data in follow-on attacks

RECOMMENDED ACTION
──────────────────
Apply a restrictive IAM bucket policy to block
public access. Enable Block Public Access settings.
```

**Section label style:** `text-xs`, `--text-muted`, uppercase, `letter-spacing: 0.12em`, monospace

**AI Fix Block:**

```
┌─────────────────────────────────┐
│  ✦ Generate Fix Code            │
│  [ Generate → ]                 │
└─────────────────────────────────┘
```

On click → calls Claude API → streams back code block:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": "arn:aws:s3:::assets-example/*"
  }]
}
```
Code block: dark background (`#0B0F17`), `--accent` text, monospace, with `[ Copy ]` button top-right.

---

### 6. Export Section

**Layout:** Centered row below dashboard, `padding: 48px 0`

**Buttons:**

```
[ ↓ Download Report (.txt) ]    [ ◻ Copy Summary to Clipboard ]
```

- Primary: filled `--accent` background, `#0B0F17` text
- Secondary: ghost with `--accent` border + text

**Download file format:**
```
NETMAP SECURITY REPORT
Generated: 2024-01-15 14:35:02
Target: example.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EXECUTIVE SUMMARY
─────────────────
Total Assets:  23
Critical:       2
High:           5
Medium:         8
Low:            8

FINDINGS
────────
[CRITICAL] Open S3 Bucket
  Host:    assets.example.com
  What:    Publicly accessible storage
  Action:  Make bucket private (IAM policy)

... (all findings)
```

---

## 🎬 Animation Choreography

### Landing → Scan transition
1. Input card scales down slightly + fades: `transform: scale(0.96)`, `opacity: 0`, `300ms`
2. Progress bar slides in from top
3. Scan screen fades in: `opacity: 0 → 1`, `400ms`

### Scan → Dashboard transition
1. Log stream freezes, final line: `[✓] Scan complete. 23 assets discovered.`
2. Progress bar fills to 100%, glows briefly
3. Dashboard fades in with staggered card animations

### Finding selection
1. Row highlights: `background` transitions to `--bg-elevated`
2. Drawer slides in from right: `translateX(100% → 0)`, `400ms var(--ease-sharp)`
3. Backdrop fades in simultaneously

### Log stream entry
```css
@keyframes logEntry {
  from { opacity: 0; transform: translateX(-8px); }
  to   { opacity: 1; transform: translateX(0); }
}
.log-line { animation: logEntry 180ms var(--ease-sharp); }
```

### Severity badge pulse (Critical only)
```css
@keyframes criticalPulse {
  0%, 100% { box-shadow: 0 0 0 0 var(--critical-glow); }
  50%       { box-shadow: 0 0 0 6px transparent; }
}
```

---

## 📱 Responsive Breakpoints

| Breakpoint | Layout changes |
|------------|----------------|
| `>1280px` | Full layout as specified |
| `1024–1280px` | Decision panel moves below findings table |
| `768–1024px` | Graph collapses to smaller height (220px) |
| `<768px` | Single column, drawer is full-width bottom sheet |

---

## 🤖 AI Fix Integration (Claude API)

```javascript
// Called when user clicks "Generate Fix Code" in drawer
async function generateFix(finding) {
  const response = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "claude-sonnet-4-20250514",
      max_tokens: 1000,
      messages: [{
        role: "user",
        content: `You are a security engineer. Generate a precise, copy-pasteable fix for this finding.
Finding: ${finding.title}
Host: ${finding.host}
Description: ${finding.description}

Return ONLY the fix — code, config, or CLI commands. No explanation. Use code blocks.`
      }]
    })
  });
  const data = await response.json();
  return data.content.map(b => b.text || "").join("");
}
```

**UI states during generation:**
1. Button shows spinner + `Generating...`
2. Code block appears with typewriter reveal
3. `[ Copy ]` button appears top-right of code block

---

## 📦 Dependencies

```json
{
  "dependencies": {
    "react": "^18",
    "react-dom": "^18",
    "react-force-graph-2d": "^1.x",
    "lucide-react": "^0.383.0"
  },
  "devDependencies": {
    "vite": "^5",
    "tailwindcss": "^3",
    "@vitejs/plugin-react": "^4"
  }
}
```

> **Note:** All Tailwind classes used must exist in the base stylesheet (no arbitrary values in production without a compiler). Use inline styles or CSS variables for dynamic values like glow colors and severity-specific theming.

---

## 🗂 File Structure

```
src/
├── App.jsx
├── main.jsx
├── index.css                 ← CSS variables, global resets, animations
├── components/
│   ├── Navbar.jsx
│   ├── LandingPage.jsx
│   ├── ScanScreen/
│   │   ├── index.jsx
│   │   ├── GlobalProgressBar.jsx
│   │   ├── StageTracker.jsx
│   │   └── LogStream.jsx
│   ├── Dashboard/
│   │   ├── index.jsx
│   │   ├── SummaryCards.jsx
│   │   ├── AttackGraph.jsx
│   │   ├── FindingsTable.jsx
│   │   └── DecisionPanel.jsx
│   ├── DetailDrawer.jsx
│   └── ExportSection.jsx
├── hooks/
│   ├── useScan.js            ← scan orchestration logic
│   └── useExport.js          ← report generation
├── data/
│   └── mockFindings.js       ← demo payload for presentations
└── utils/
    ├── domainParser.js
    └── severityHelpers.js
```

---

## 🏁 Demo Payload (for presentations)

Pre-seed `mockFindings.js` with realistic data for `demo.netmap.io`:

```javascript
export const DEMO_FINDINGS = [
  {
    id: "f1",
    severity: "critical",
    title: "Open S3 Bucket",
    host: "assets.demo.netmap.io",
    description: "Publicly accessible storage with 847 files",
    action: "Apply restrictive IAM bucket policy",
    source: "cloud-storage-probe",
    timestamp: "2024-01-15T14:32:45Z",
    whatItIs: "A cloud storage bucket with public read/list access enabled.",
    whyItMatters: "Anyone on the internet can download or enumerate all stored files.",
    attackerCan: ["Download all 847 files", "Extract API keys from .env files", "Exfiltrate customer PII"],
    fixCode: `aws s3api put-bucket-policy --bucket assets-demo-netmap-io --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::assets-demo-netmap-io/*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}'`
  },
  {
    id: "f2",
    severity: "critical",
    title: "Exposed Admin Panel",
    host: "admin.demo.netmap.io",
    description: "Login page publicly reachable — no VPN required",
    action: "Restrict to VPN/IP allowlist via WAF rule",
    source: "admin-panel-heuristics",
    timestamp: "2024-01-15T14:33:01Z",
    // ...
  },
  // ... 20+ more findings across all severities
];
```

---

## ✅ Pre-Demo Checklist

- [ ] Input strips `http://`, `https://`, trailing `/`
- [ ] Quick suggestion pills populate domain input on click
- [ ] Log stream auto-scrolls to bottom
- [ ] Scan stages animate in sequence
- [ ] Progress bar reaches exactly 100% at scan end
- [ ] Critical severity badges pulse
- [ ] Graph nodes are clickable and open drawer
- [ ] Table filter pills highlight active state
- [ ] Drawer slides in/out smoothly
- [ ] AI Fix button streams response
- [ ] Export download triggers file save with correct filename: `netmap-report-{domain}-{date}.txt`
- [ ] Mobile drawer renders as bottom sheet
- [ ] All colors use CSS variables (easy to theme)
- [ ] No console errors in production build

---

*NetMap · Frontend Spec v1.0 · Hackathon Edition*
