import React, { useEffect, useRef } from "react";
import GlobalProgressBar from "./GlobalProgressBar";
import StageTracker from "./StageTracker";
import LogStream from "./LogStream";

// ── Ambient particle background (same as landing page) ────────────────────────
const G      = "#AAFF00";
const G_GLOW = "rgba(170,255,0,0.35)";

function AmbientCanvas() {
  const canvasRef = useRef(null);
  const rafRef    = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    let W = window.innerWidth;
    let H = window.innerHeight;
    canvas.width  = W;
    canvas.height = H;

    const resize = () => {
      W = window.innerWidth;
      H = window.innerHeight;
      canvas.width  = W;
      canvas.height = H;
    };
    window.addEventListener("resize", resize);

    // Small ambient floating particles
    const PARTICLES = Array.from({ length: 80 }, () => ({
      x:  Math.random() * W,
      y:  Math.random() * H,
      vx: (Math.random() - 0.5) * 0.25,
      vy: (Math.random() - 0.5) * 0.25,
      r:  Math.random() * 1.4 + 0.3,
      op: Math.random() * 0.25 + 0.05,
    }));

    const draw = () => {
      ctx.clearRect(0, 0, W, H);
      PARTICLES.forEach(p => {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0) p.x = W;
        if (p.x > W) p.x = 0;
        if (p.y < 0) p.y = H;
        if (p.y > H) p.y = 0;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(170,255,0,${p.op.toFixed(2)})`;
        ctx.fill();
      });
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
      style={{ position: "fixed", inset: 0, pointerEvents: "none", zIndex: 0 }}
    />
  );
}

export default function ScanScreen({
  progress,
  logs,
  stageStates,
  domain,
  elapsed,
  subsFound,
  hostsFound,
  openPortsFound,
}) {
  return (
    <div
      style={{
        minHeight: "100vh",
        paddingTop: 56,
        background: "#050905",
        position: "relative",
        animation: "fadeIn 0.4s ease",
      }}
    >
      {/* Ambient green radial glow */}
      <div
        style={{
          position: "fixed",
          top: "-15%",
          left: "50%",
          transform: "translateX(-50%)",
          width: 900,
          height: 600,
          background: "radial-gradient(ellipse at 50% 0%, rgba(170,255,0,0.07) 0%, transparent 65%)",
          pointerEvents: "none",
          zIndex: 1,
        }}
      />

      {/* Subtle grid overlay */}
      <div
        style={{
          position: "fixed",
          inset: 0,
          backgroundImage: `linear-gradient(rgba(170,255,0,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(170,255,0,0.025) 1px, transparent 1px)`,
          backgroundSize: "60px 60px",
          pointerEvents: "none",
          zIndex: 1,
        }}
      />

      {/* Floating ambient particles */}
      <AmbientCanvas />

      {/* Progress bar */}
      <div style={{ position: "relative", zIndex: 10 }}>
        <GlobalProgressBar progress={progress} />
      </div>

      {/* ── Main grid (fills the screen) ───────────────────────────────────── */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "380px 1fr",
          gap: 20,
          width: "100%",
          maxWidth: "100vw",
          padding: "20px 24px",
          minHeight: "calc(100vh - 56px)",
          position: "relative",
          zIndex: 5,
          boxSizing: "border-box",
        }}
      >
        {/* ── Left: Stage Tracker ────────────────────────────────────────── */}
        <div
          style={{
            background: "rgba(10,14,10,0.85)",
            border: "1px solid rgba(170,255,0,0.12)",
            borderRadius: 14,
            padding: "24px",
            backdropFilter: "blur(12px)",
            boxShadow: "0 0 40px rgba(170,255,0,0.04), inset 0 1px 0 rgba(170,255,0,0.06)",
            display: "flex",
            flexDirection: "column",
          }}
        >
          <StageTracker
            stageStates={stageStates}
            domain={domain}
            elapsed={elapsed}
            subsFound={subsFound}
            hostsFound={hostsFound}
            openPortsFound={openPortsFound}
          />
        </div>

        {/* ── Right: Log Stream ──────────────────────────────────────────── */}
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            minHeight: 0,
          }}
        >
          <LogStream logs={logs} isRunning={true} />
        </div>
      </div>
    </div>
  );
}
