import React, { useState, useEffect, useRef } from "react";
import { ArrowRight, ArrowDown } from "lucide-react";
import { parseDomain, isValidDomain } from "../utils/domainParser";

const SUGGESTIONS = ["hiranandani.com", "github.com", "google.com"];

// ── Green accent for landing page only ───────────────────────────────────────
const G      = "#AAFF00";
const G_DIM  = "rgba(170,255,0,0.12)";
const G_GLOW = "rgba(170,255,0,0.35)";
const G_SOFT = "rgba(170,255,0,0.05)";
const BG     = "#050905";

// ── 3D Particle Globe (Canvas) ────────────────────────────────────────────────
function ParticleGlobe() {
  const canvasRef = useRef(null);
  const rafRef    = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    // Responsive sizing
    let W = canvas.offsetWidth;
    let H = canvas.offsetHeight;
    canvas.width  = W;
    canvas.height = H;

    const resize = () => {
      W = canvas.offsetWidth;
      H = canvas.offsetHeight;
      canvas.width  = W;
      canvas.height = H;
    };
    window.addEventListener("resize", resize);

    // ── Generate sphere points ──────────────────────────────────────────────
    const NUM_DOTS  = 280;
    const RADIUS    = Math.min(W, H) * 0.38;
    const CX        = W * 0.5;
    const CY        = H * 0.5;

    // Fibonacci sphere distribution for even spread
    const pts = [];
    const goldenRatio = Math.PI * (3 - Math.sqrt(5));
    for (let i = 0; i < NUM_DOTS; i++) {
      const y     = 1 - (i / (NUM_DOTS - 1)) * 2;
      const r     = Math.sqrt(1 - y * y);
      const theta = goldenRatio * i;
      pts.push({
        ox: Math.cos(theta) * r,       // original 3D coords on unit sphere
        oy: y,
        oz: Math.sin(theta) * r,
        size: Math.random() * 1.5 + 0.5,
        brightness: Math.random() * 0.5 + 0.5,
        pulse: Math.random() * Math.PI * 2,
      });
    }

    // Extra floating particles (ambient)
    const AMBIENT = 60;
    const ambient = Array.from({ length: AMBIENT }, () => ({
      x: Math.random() * W,
      y: Math.random() * H,
      vx: (Math.random() - 0.5) * 0.3,
      vy: (Math.random() - 0.5) * 0.3,
      size: Math.random() * 1.2 + 0.2,
      opacity: Math.random() * 0.4 + 0.1,
    }));

    let angle  = 0;
    let tiltX  = 0.18;  // slight tilt so it looks 3D
    let t      = 0;

    const draw = () => {
      ctx.clearRect(0, 0, W, H);

      // ── Central glow ─────────────────────────────────────────────────────
      const grd = ctx.createRadialGradient(CX, CY, 0, CX, CY, RADIUS * 1.2);
      grd.addColorStop(0,   "rgba(170,255,0,0.06)");
      grd.addColorStop(0.5, "rgba(170,255,0,0.02)");
      grd.addColorStop(1,   "transparent");
      ctx.fillStyle = grd;
      ctx.beginPath();
      ctx.arc(CX, CY, RADIUS * 1.2, 0, Math.PI * 2);
      ctx.fill();

      // ── Rotate sphere points ──────────────────────────────────────────────
      const cosA = Math.cos(angle);
      const sinA = Math.sin(angle);
      const cosX = Math.cos(tiltX);
      const sinX = Math.sin(tiltX);

      const projected = pts.map((p, idx) => {
        // Rotate Y-axis
        const rx  = p.ox * cosA - p.oz * sinA;
        const rz  = p.ox * sinA + p.oz * cosA;
        const ry  = p.oy;
        // Rotate X-axis (tilt)
        const ry2 = ry * cosX - rz * sinX;
        const rz2 = ry * sinX + rz * cosX;

        const scale = RADIUS / (RADIUS + rz2 * RADIUS * 0.4); // perspective
        const sx    = CX + rx * RADIUS * scale;
        const sy    = CY + ry2 * RADIUS * scale;
        const depth = (rz2 + 1) / 2; // 0=back, 1=front

        const pulse = Math.sin(t * 0.04 + p.pulse) * 0.3 + 0.7;
        const alpha = depth * 0.75 * p.brightness * pulse;
        const size  = p.size * scale * (0.6 + depth * 0.5);

        return { x: sx, y: sy, depth, alpha, size, idx };
      });

      // ── Draw edges (nearby pairs) ──────────────────────────────────────────
      const LINK_DIST = RADIUS * 0.38;
      for (let i = 0; i < projected.length; i++) {
        const a = projected[i];
        if (a.depth < 0.35) continue; // skip back-side
        for (let j = i + 1; j < projected.length; j++) {
          const b = projected[j];
          if (b.depth < 0.35) continue;
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const d  = Math.sqrt(dx * dx + dy * dy);
          if (d < LINK_DIST) {
            const opac = ((1 - d / LINK_DIST) * Math.min(a.depth, b.depth) * 0.45).toFixed(3);
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.strokeStyle = `rgba(170,255,0,${opac})`;
            ctx.lineWidth   = 0.4;
            ctx.stroke();
          }
        }
      }

      // ── Draw dots (front to back) ─────────────────────────────────────────
      projected
        .sort((a, b) => a.depth - b.depth)
        .forEach(({ x, y, depth, alpha, size }) => {
          if (depth < 0.2) return;

          // Glow halo
          const glow = ctx.createRadialGradient(x, y, 0, x, y, size * 3.5);
          glow.addColorStop(0, `rgba(170,255,0,${(alpha * 0.6).toFixed(3)})`);
          glow.addColorStop(1, "transparent");
          ctx.beginPath();
          ctx.arc(x, y, size * 3.5, 0, Math.PI * 2);
          ctx.fillStyle = glow;
          ctx.fill();

          // Core dot
          ctx.beginPath();
          ctx.arc(x, y, size, 0, Math.PI * 2);
          ctx.fillStyle = `rgba(220,255,100,${(alpha * 0.9).toFixed(3)})`;
          ctx.fill();
        });

      // ── Ambient floating particles ────────────────────────────────────────
      ambient.forEach((p) => {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0) p.x = W;
        if (p.x > W) p.x = 0;
        if (p.y < 0) p.y = H;
        if (p.y > H) p.y = 0;

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(170,255,0,${p.opacity.toFixed(2)})`;
        ctx.fill();
      });

      angle += 0.004;
      t++;
      rafRef.current = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      cancelAnimationFrame(rafRef.current);
      window.removeEventListener("resize", resize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: "absolute",
        inset: 0,
        width: "100%",
        height: "100%",
        pointerEvents: "none",
      }}
    />
  );
}

// ── Main LandingPage ──────────────────────────────────────────────────────────
export default function LandingPage({ onStartScan }) {
  const [input,   setInput]   = useState("");
  const [focused, setFocused] = useState(false);
  const [error,   setError]   = useState("");
  const scanRef = useRef(null);

  const handleSubmit = (e) => {
    e.preventDefault();
    const domain = parseDomain(input);
    if (!isValidDomain(domain)) {
      setError("Enter a valid domain (e.g. example.com)");
      return;
    }
    setError("");
    onStartScan(domain);
  };

  const handleSuggestion = (domain) => {
    setInput(domain);
    setError("");
    onStartScan(domain);
  };

  const scrollToScan = () => {
    scanRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  return (
    <div style={{ background: BG, minHeight: "100vh", overflowX: "hidden", fontFamily: "var(--font-body)" }}>

      {/* ── Hero Section (100vh) ───────────────────────────────────────────── */}
      <section
        style={{
          position: "relative",
          height: "100vh",
          display: "flex",
          flexDirection: "column",
          overflow: "hidden",
          background: `radial-gradient(ellipse 80% 60% at 70% 30%, rgba(170,255,0,0.07) 0%, transparent 60%), ${BG}`,
        }}
      >
        {/* Particle canvas — covers entire hero */}
        <div style={{ position: "absolute", inset: 0, zIndex: 0 }}>
          <ParticleGlobe />
        </div>

        {/* Spotlight from top */}
        <div
          style={{
            position: "absolute",
            top: -100,
            left: "50%",
            transform: "translateX(-50%)",
            width: 600,
            height: 500,
            background: "radial-gradient(ellipse at 50% 0%, rgba(170,255,0,0.09) 0%, transparent 70%)",
            pointerEvents: "none",
            zIndex: 1,
          }}
        />

        {/* Navbar inside hero */}
        <nav
          style={{
            position: "relative",
            zIndex: 10,
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "24px 40px",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <svg width="22" height="22" viewBox="0 0 28 28" fill="none">
              <polygon points="14,2 25,8 25,20 14,26 3,20 3,8" stroke={G} strokeWidth="1.5" fill="none"/>
              <circle cx="14" cy="14" r="4" fill={G}/>
            </svg>
            <span style={{ fontSize: 15, fontWeight: 800, letterSpacing: "0.18em", color: "#fff", fontFamily: "var(--font-display)" }}>
              NETMAP
            </span>
          </div>

          <button
            onClick={scrollToScan}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              padding: "9px 20px",
              fontSize: 13,
              fontWeight: 600,
              color: "#000",
              background: G,
              border: "none",
              borderRadius: 999,
              cursor: "pointer",
              fontFamily: "var(--font-display)",
              letterSpacing: "0.05em",
              boxShadow: `0 0 18px ${G_GLOW}`,
              transition: "all 0.25s ease",
            }}
            onMouseEnter={e => { e.currentTarget.style.transform = "scale(1.05)"; e.currentTarget.style.boxShadow = `0 0 28px ${G_GLOW}`; }}
            onMouseLeave={e => { e.currentTarget.style.transform = "scale(1)";    e.currentTarget.style.boxShadow = `0 0 18px ${G_GLOW}`; }}
          >
            Start Scan
            <span style={{ width: 22, height: 22, borderRadius: "50%", background: "rgba(0,0,0,0.2)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <ArrowRight size={12} color="#000" />
            </span>
          </button>
        </nav>

        {/* Hero Content */}
        <div
          style={{
            flex: 1,
            display: "flex",
            flexDirection: "column",
            justifyContent: "center",
            padding: "0 40px",
            position: "relative",
            zIndex: 5,
            maxWidth: 700,
          }}
        >
          {/* Label */}
          <div
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 8,
              marginBottom: 28,
              animation: "fadeUp 0.6s ease both",
            }}
          >
            <span style={{ color: G, fontSize: 11, letterSpacing: "0.25em", fontFamily: "var(--font-mono)", opacity: 0.8 }}>
              [ ATTACK SURFACE INTELLIGENCE ]
            </span>
          </div>

          {/* Big Headline */}
          <h1
            style={{
              fontSize: "clamp(3rem, 7vw, 5.5rem)",
              fontWeight: 800,
              color: "#fff",
              lineHeight: 1.05,
              letterSpacing: "-0.02em",
              marginBottom: 0,
              fontFamily: "var(--font-display)",
              animation: "fadeUp 0.6s ease 0.1s both",
            }}
          >
            Attack Surface
            <br />
            <span style={{ color: "#fff" }}>Intelligence.</span>
          </h1>
        </div>

        {/* Bottom bar */}
        <div
          style={{
            position: "relative",
            zIndex: 5,
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            borderTop: "1px solid rgba(170,255,0,0.1)",
            padding: "20px 40px",
            animation: "fadeUp 0.6s ease 0.3s both",
          }}
        >
          {/* Left: Scroll indicator */}
          <button
            onClick={scrollToScan}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              background: "none",
              border: "none",
              cursor: "pointer",
              color: G,
              fontSize: 13,
              fontFamily: "var(--font-body)",
              letterSpacing: "0.05em",
            }}
          >
            <ArrowDown size={16} color={G} style={{ animation: "bounce 2s ease-in-out infinite" }} />
            Scroll to scan
          </button>

          {/* Right: Tagline */}
          <p style={{ color: "rgba(255,255,255,0.55)", fontSize: 15, lineHeight: 1.65, fontFamily: "var(--font-body)" }}>
            NetMap maps every subdomain, open port, exposed service, and cloud bucket — automatically, with no credentials required.
          </p>
        </div>

        {/* Bottom nav pills */}
        <div
          style={{
            position: "relative",
            zIndex: 5,
            display: "flex",
            justifyContent: "center",
            paddingBottom: 32,
            animation: "fadeUp 0.6s ease 0.4s both",
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 4,
              background: "rgba(255,255,255,0.05)",
              border: "1px solid rgba(255,255,255,0.08)",
              borderRadius: 999,
              padding: "6px 8px",
            }}
          >
            {[
              { label: "Home", active: true },
              { label: "Scan" },
              { label: "Reports" },
              { label: "About" },
            ].map(({ label, active }) => (
              <button
                key={label}
                onClick={label === "Scan" ? scrollToScan : undefined}
                className="font-mono"
                style={{
                  padding: "6px 18px",
                  borderRadius: 999,
                  fontSize: 12,
                  letterSpacing: "0.05em",
                  background: active ? "rgba(170,255,0,0.15)" : "transparent",
                  color: active ? G : "rgba(255,255,255,0.5)",
                  border: "none",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                  transition: "all 0.2s",
                }}
                onMouseEnter={e => { if (!active) e.currentTarget.style.color = "rgba(255,255,255,0.8)"; }}
                onMouseLeave={e => { if (!active) e.currentTarget.style.color = "rgba(255,255,255,0.5)"; }}
              >
                {active && (
                  <span style={{ width: 6, height: 6, borderRadius: "50%", background: G, display: "inline-block" }} />
                )}
                {label}
              </button>
            ))}
          </div>
        </div>
      </section>

      {/* ── Scan Section (below fold) ──────────────────────────────────────── */}
      <section
        ref={scanRef}
        style={{
          minHeight: "100vh",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          padding: "80px 24px",
          background: `radial-gradient(ellipse 700px 500px at 50% 45%, rgba(170,255,0,0.04) 0%, transparent 70%), ${BG}`,
          position: "relative",
        }}
      >
        {/* Subtle grid */}
        <div
          style={{
            position: "absolute",
            inset: 0,
            backgroundImage: `linear-gradient(rgba(170,255,0,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(170,255,0,0.03) 1px, transparent 1px)`,
            backgroundSize: "60px 60px",
            pointerEvents: "none",
          }}
        />

        {/* Logo row */}
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", marginBottom: 36, position: "relative", zIndex: 2 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
            <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
              <polygon points="14,2 25,8 25,20 14,26 3,20 3,8" stroke={G} strokeWidth="1.5" fill="none"/>
              <circle cx="14" cy="14" r="4" fill={G}/>
            </svg>
            <span style={{ fontSize: 20, fontWeight: 800, letterSpacing: "0.18em", color: "#fff", fontFamily: "var(--font-display)" }}>
              NETMAP
            </span>
          </div>
          <p style={{ fontSize: 11, color: "rgba(170,255,0,0.5)", letterSpacing: "0.28em", textTransform: "uppercase", fontFamily: "var(--font-mono)" }}>
            Attack Surface Intelligence
          </p>
        </div>

        {/* Headline */}
        <div style={{ textAlign: "center", maxWidth: 560, marginBottom: 40, position: "relative", zIndex: 2 }}>
          <h2
            style={{
              fontSize: "clamp(2.2rem, 6vw, 3.2rem)",
              fontWeight: 800,
              color: "#fff",
              lineHeight: 1.1,
              marginBottom: 16,
              fontFamily: "var(--font-display)",
            }}
          >
            Know what you've
            <br/>exposed.
          </h2>
          <p style={{ fontSize: 16, color: "rgba(255,255,255,0.5)", lineHeight: 1.7, fontFamily: "var(--font-body)" }}>
            NetMap scans your domain and finds every security gap —{" "}
            <span style={{ color: G, fontStyle: "italic" }}>in plain English.</span>
          </p>
        </div>

        {/* Scan Input Card */}
        <div
          style={{
            maxWidth: 540,
            width: "100%",
            background: focused ? "rgba(170,255,0,0.04)" : "rgba(255,255,255,0.03)",
            border: focused ? `1px solid ${G}` : "1px solid rgba(255,255,255,0.1)",
            borderRadius: 16,
            padding: 28,
            boxShadow: focused ? `0 0 0 3px rgba(170,255,0,0.1), 0 0 60px rgba(170,255,0,0.06)` : "none",
            transition: "all 0.25s ease",
            position: "relative",
            zIndex: 2,
          }}
        >
          <p
            style={{
              fontSize: 10,
              color: "rgba(170,255,0,0.6)",
              letterSpacing: "0.22em",
              textTransform: "uppercase",
              marginBottom: 14,
              fontFamily: "var(--font-mono)",
            }}
          >
            Enter Your Domain
          </p>

          <form onSubmit={handleSubmit} style={{ display: "flex", gap: 10 }}>
            <input
              id="domain-input"
              type="text"
              value={input}
              onChange={e => { setInput(e.target.value); if (error) setError(""); }}
              onFocus={() => setFocused(true)}
              onBlur={() => setFocused(false)}
              placeholder="example.com"
              autoComplete="off"
              spellCheck="false"
              style={{
                flex: 1,
                background: "rgba(255,255,255,0.05)",
                border: "1px solid rgba(255,255,255,0.08)",
                borderRadius: 10,
                outline: "none",
                color: "#fff",
                fontSize: 15,
                padding: "12px 16px",
                fontFamily: "var(--font-mono)",
                transition: "border-color 0.2s",
              }}
            />
            <button
              id="start-scan-btn"
              type="submit"
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                padding: "12px 22px",
                fontSize: 14,
                fontWeight: 700,
                color: "#000",
                background: G,
                border: "none",
                borderRadius: 10,
                cursor: "pointer",
                whiteSpace: "nowrap",
                fontFamily: "var(--font-display)",
                boxShadow: `0 0 20px rgba(170,255,0,0.3)`,
                transition: "all 0.2s ease",
                letterSpacing: "0.04em",
              }}
              onMouseEnter={e => { e.currentTarget.style.transform = "scale(1.03)"; e.currentTarget.style.boxShadow = `0 0 30px rgba(170,255,0,0.5)`; }}
              onMouseLeave={e => { e.currentTarget.style.transform = "scale(1)";    e.currentTarget.style.boxShadow = `0 0 20px rgba(170,255,0,0.3)`; }}
            >
              Start Scan
              <ArrowRight size={15} />
            </button>
          </form>

          {error && (
            <p style={{ marginTop: 8, fontSize: 12, color: "#FF5F56", fontFamily: "var(--font-mono)" }}>
              {error}
            </p>
          )}

          {/* Suggestions */}
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 18, flexWrap: "wrap" }}>
            <span style={{ fontSize: 12, color: "rgba(255,255,255,0.3)", fontFamily: "var(--font-body)" }}>Try:</span>
            {SUGGESTIONS.map(s => (
              <button
                key={s}
                onClick={() => handleSuggestion(s)}
                style={{
                  padding: "4px 14px",
                  fontSize: 12,
                  color: "rgba(255,255,255,0.5)",
                  background: "rgba(255,255,255,0.05)",
                  border: "1px solid rgba(255,255,255,0.08)",
                  borderRadius: 999,
                  cursor: "pointer",
                  fontFamily: "var(--font-mono)",
                  transition: "all 0.2s",
                }}
                onMouseEnter={e => { e.currentTarget.style.borderColor = G; e.currentTarget.style.color = G; }}
                onMouseLeave={e => { e.currentTarget.style.borderColor = "rgba(255,255,255,0.08)"; e.currentTarget.style.color = "rgba(255,255,255,0.5)"; }}
              >
                {s}
              </button>
            ))}
          </div>
        </div>

        {/* Feature badges */}
        <div style={{ display: "flex", gap: 24, marginTop: 28, flexWrap: "wrap", justifyContent: "center", position: "relative", zIndex: 2 }}>
          {[
            { icon: "⚡", text: "Passive scan" },
            { icon: "🔒", text: "No auth needed" },
            { icon: "🌐", text: "Public data only" },
          ].map(f => (
            <span
              key={f.text}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 7,
                fontSize: 12,
                color: "rgba(170,255,0,0.55)",
                fontFamily: "var(--font-body)",
              }}
            >
              {f.icon} {f.text}
            </span>
          ))}
        </div>
      </section>

      {/* Bounce animation */}
      <style>{`
        @keyframes bounce {
          0%, 100% { transform: translateY(0); }
          50% { transform: translateY(6px); }
        }
      `}</style>
    </div>
  );
}
