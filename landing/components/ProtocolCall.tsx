"use client";

import { useEffect, useState } from "react";

export type ProtocolCallDirection = "send" | "receive";

interface ProtocolCallProps {
  direction: ProtocolCallDirection;
  fromAddress: string;
  toAddress: string;
  preview: string;
  agentColor: string;
  autoExpand?: boolean;
}

const COLOR_MAP: Record<string, { border: string; bg: string; text: string; label: string; compact: string }> = {
  violet: {
    border: "border-violet-500/30",
    bg: "bg-violet-950/20",
    text: "text-violet-400",
    label: "text-violet-400",
    compact: "text-violet-400/70",
  },
  emerald: {
    border: "border-emerald-500/30",
    bg: "bg-emerald-950/20",
    text: "text-emerald-400",
    label: "text-emerald-400",
    compact: "text-emerald-400/70",
  },
  rose: {
    border: "border-rose-500/30",
    bg: "bg-rose-950/20",
    text: "text-rose-400",
    label: "text-rose-400",
    compact: "text-rose-400/70",
  },
};

export default function ProtocolCall({
  direction,
  fromAddress,
  toAddress,
  preview,
  agentColor,
  autoExpand = false,
}: ProtocolCallProps) {
  const [visible, setVisible] = useState(false);
  const [expanded, setExpanded] = useState(autoExpand);
  const colors = COLOR_MAP[agentColor] || COLOR_MAP.violet;

  useEffect(() => {
    const timer = setTimeout(() => setVisible(true), 50);
    return () => clearTimeout(timer);
  }, []);

  // Auto-collapse after 2s if auto-expanded
  useEffect(() => {
    if (autoExpand) {
      const timer = setTimeout(() => setExpanded(false), 2500);
      return () => clearTimeout(timer);
    }
  }, [autoExpand]);

  const fnName = direction === "send" ? "uam.send" : "inbox.receive";
  const arrow = direction === "send" ? "\u2192" : "\u2190";
  const targetAddr = direction === "send" ? toAddress : fromAddress;

  return (
    <div
      className={`
        my-1.5 font-mono text-xs transition-all duration-300 cursor-pointer
        ${visible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-2"}
      `}
      onClick={() => setExpanded(!expanded)}
    >
      {/* Compact view */}
      {!expanded && (
        <div className="flex items-center gap-1.5 text-zinc-500 hover:text-zinc-400 transition-colors px-1">
          <span className="text-zinc-600">{arrow}</span>
          <span>{fnName}(</span>
          <span className={colors.compact}>{targetAddr}</span>
          <span>)</span>
        </div>
      )}

      {/* Expanded view */}
      {expanded && (
        <div className={`${colors.bg} border-l-2 ${colors.border} rounded-r-lg px-3 py-2.5 space-y-1`}>
          <div className={`${colors.label} font-medium`}>{fnName}()</div>
          <div className="text-zinc-500">
            <span>from: </span>
            <span className={colors.text}>{fromAddress}</span>
          </div>
          <div className="text-zinc-500">
            <span>to: </span>
            <span className={colors.text}>{toAddress}</span>
          </div>
          <div className="text-zinc-500 truncate">
            <span>msg: </span>
            <span className="text-zinc-400">
              &quot;{preview.slice(0, 50)}{preview.length > 50 ? "..." : ""}&quot;
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
