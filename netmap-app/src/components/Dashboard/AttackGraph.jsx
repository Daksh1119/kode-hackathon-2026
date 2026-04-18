import React, { useRef, useCallback, useMemo, useEffect, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import {
  getUniqueHosts,
  getHostSeverity,
  getSeverityColor,
} from "../../utils/severityHelpers";

export default function AttackGraph({ findings, domain, onNodeClick }) {
  const graphRef = useRef();
  const containerRef = useRef();
  const [dimensions, setDimensions] = useState({ width: 800, height: 320 });

  // Measure container
  useEffect(() => {
    if (containerRef.current) {
      const rect = containerRef.current.getBoundingClientRect();
      setDimensions({ width: rect.width - 2, height: 320 });
    }
  }, []);

  // Build graph data
  const graphData = useMemo(() => {
    const hosts = getUniqueHosts(findings);

    const nodes = [
      {
        id: domain,
        label: domain,
        isRoot: true,
        severity: "accent",
        val: 20,
      },
      ...hosts.map((host) => ({
        id: host,
        label: host.replace(`.${domain}`, ""),
        isRoot: false,
        severity: getHostSeverity(findings, host),
        val: 10,
      })),
    ];

    const links = hosts.map((host) => ({
      source: domain,
      target: host,
    }));

    return { nodes, links };
  }, [findings, domain]);

  const paintNode = useCallback(
    (node, ctx) => {
      const size = node.isRoot ? 10 : 6;
      const color = node.isRoot ? "#00FFB2" : getSeverityColor(node.severity);

      // Glow
      ctx.shadowColor = color;
      ctx.shadowBlur = node.isRoot ? 16 : 8;

      if (node.isRoot) {
        // Hexagon for root
        const a = (2 * Math.PI) / 6;
        ctx.beginPath();
        for (let i = 0; i < 6; i++) {
          ctx.lineTo(
            node.x + size * Math.cos(a * i - Math.PI / 6),
            node.y + size * Math.sin(a * i - Math.PI / 6)
          );
        }
        ctx.closePath();
        ctx.fillStyle = color;
        ctx.fill();
      } else {
        // Circle for subdomains
        ctx.beginPath();
        ctx.arc(node.x, node.y, size, 0, 2 * Math.PI);
        ctx.fillStyle = color;
        ctx.fill();
      }

      ctx.shadowBlur = 0;

      // Label
      const label = node.label;
      ctx.font = `${node.isRoot ? "bold " : ""}10px 'DM Mono', monospace`;
      ctx.fillStyle = "rgba(241, 245, 249, 0.8)";
      ctx.textAlign = "center";
      ctx.textBaseline = "top";
      ctx.fillText(label, node.x, node.y + size + 4);
    },
    []
  );

  const handleNodeClick = useCallback(
    (node) => {
      if (!node.isRoot) {
        const finding = findings.find((f) => f.host === node.id);
        if (finding && onNodeClick) {
          onNodeClick(finding);
        }
      }
    },
    [findings, onNodeClick]
  );

  const nodeTooltip = useCallback(
    (node) => {
      if (node.isRoot) return `<div style="background:#1A2233;color:#F1F5F9;padding:8px 12px;border-radius:8px;font-family:'DM Mono',monospace;font-size:12px;border:1px solid rgba(255,255,255,0.1)"><strong>${domain}</strong><br/><span style="color:#00FFB2">Root Domain</span></div>`;
      const hostFindings = findings.filter((f) => f.host === node.id);
      const severity = getHostSeverity(findings, node.id);
      const color = getSeverityColor(severity);
      return `<div style="background:#1A2233;color:#F1F5F9;padding:8px 12px;border-radius:8px;font-family:'DM Mono',monospace;font-size:12px;border:1px solid rgba(255,255,255,0.1)"><strong>${node.id}</strong><br/><span style="color:${color}">● ${severity.toUpperCase()}</span> · ${hostFindings.length} issue${hostFindings.length !== 1 ? "s" : ""}</div>`;
    },
    [findings, domain]
  );

  return (
    <div
      ref={containerRef}
      style={{
        background: "var(--bg-surface)",
        border: "1px solid var(--border-subtle)",
        borderRadius: "var(--radius-lg)",
        overflow: "hidden",
        height: 320,
        position: "relative",
        backgroundImage:
          "radial-gradient(rgba(255,255,255,0.02) 1px, transparent 1px)",
        backgroundSize: "20px 20px",
      }}
    >
      <ForceGraph2D
        ref={graphRef}
        graphData={graphData}
        width={dimensions.width}
        height={dimensions.height}
        backgroundColor="transparent"
        linkColor={() => "rgba(255,255,255,0.08)"}
        linkWidth={1}
        nodeCanvasObject={paintNode}
        nodePointerAreaPaint={(node, color, ctx) => {
          const size = node.isRoot ? 12 : 8;
          ctx.fillStyle = color;
          ctx.beginPath();
          ctx.arc(node.x, node.y, size, 0, 2 * Math.PI);
          ctx.fill();
        }}
        onNodeClick={handleNodeClick}
        nodeLabel={nodeTooltip}
        cooldownTicks={100}
        d3AlphaDecay={0.02}
        d3VelocityDecay={0.3}
        enableZoomInteraction={true}
        enablePanInteraction={true}
      />
    </div>
  );
}
