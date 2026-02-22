"use client";

import { useEffect, useRef } from "react";
import ProtocolCall from "./ProtocolCall";

export interface AgentConfig {
  name: string;
  address: string;
  tagline: string;
  color: string;
  thinkingText: string;
  initial: string;
  chips: { label: string; text: string; targetAgent?: number }[];
}

export interface DemoMessage {
  id: string;
  role: "user" | "agent" | "cross-agent";
  content: string;
  fromAddress: string;
  toAddress: string;
  timestamp: number;
  showProtocol: boolean;
  autoExpandProtocol?: boolean;
}

interface AgentPanelProps {
  agent: AgentConfig;
  messages: DemoMessage[];
  isThinking: boolean;
  isSelected: boolean;
  onSelect: () => void;
  onChipClick: (text: string, targetAgent?: number) => void;
  visitorAddress: string;
  /** Total messages sent by visitor (for auto-expand logic) */
  totalMessageCount: number;
}

const COLORS: Record<string, {
  pulse: string;
  headerBg: string;
  headerBorder: string;
  selectedRing: string;
  chipBg: string;
  chipText: string;
  chipBorder: string;
  thinkingDot: string;
  avatar: string;
}> = {
  violet: {
    pulse: "bg-violet-400",
    headerBg: "bg-gradient-to-r from-violet-950/40 to-zinc-900",
    headerBorder: "border-violet-800/30",
    selectedRing: "ring-2 ring-violet-500/30",
    chipBg: "bg-violet-500/10 hover:bg-violet-500/20",
    chipText: "text-violet-400/70 hover:text-violet-300",
    chipBorder: "border-violet-500/20",
    thinkingDot: "bg-violet-400",
    avatar: "bg-violet-500/20 text-violet-300 border-violet-500/30",
  },
  emerald: {
    pulse: "bg-emerald-400",
    headerBg: "bg-gradient-to-r from-emerald-950/40 to-zinc-900",
    headerBorder: "border-emerald-800/30",
    selectedRing: "ring-2 ring-emerald-500/30",
    chipBg: "bg-emerald-500/10 hover:bg-emerald-500/20",
    chipText: "text-emerald-400/70 hover:text-emerald-300",
    chipBorder: "border-emerald-500/20",
    thinkingDot: "bg-emerald-400",
    avatar: "bg-emerald-500/20 text-emerald-300 border-emerald-500/30",
  },
  rose: {
    pulse: "bg-rose-400",
    headerBg: "bg-gradient-to-r from-rose-950/40 to-zinc-900",
    headerBorder: "border-rose-800/30",
    selectedRing: "ring-2 ring-rose-500/30",
    chipBg: "bg-rose-500/10 hover:bg-rose-500/20",
    chipText: "text-rose-400/70 hover:text-rose-300",
    chipBorder: "border-rose-500/20",
    thinkingDot: "bg-rose-400",
    avatar: "bg-rose-500/20 text-rose-300 border-rose-500/30",
  },
};

export default function AgentPanel({
  agent,
  messages,
  isThinking,
  isSelected,
  onSelect,
  onChipClick,
  visitorAddress,
  totalMessageCount,
}: AgentPanelProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const c = COLORS[agent.color] || COLORS.violet;

  useEffect(() => {
    scrollRef.current?.scrollTo({
      top: scrollRef.current.scrollHeight,
      behavior: "smooth",
    });
  }, [messages, isThinking]);

  return (
    <div
      className={`
        flex flex-col bg-zinc-900/80 backdrop-blur-sm rounded-2xl overflow-hidden border transition-all duration-200 cursor-pointer
        ${isSelected ? `${c.selectedRing} border-transparent brightness-105` : "border-zinc-800/60 opacity-85 hover:opacity-95"}
      `}
      onClick={onSelect}
    >
      {/* Agent Header */}
      <div className={`${c.headerBg} px-4 py-3 border-b ${c.headerBorder} flex items-center gap-3`}>
        <div className={`w-8 h-8 ${c.avatar} rounded-lg border flex items-center justify-center text-sm font-bold`}>
          {agent.initial}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-sm text-white">{agent.name}</span>
            <div className={`w-2 h-2 ${c.pulse} rounded-full animate-pulse`} />
          </div>
          <div className="font-mono text-[11px] text-zinc-500 truncate">{agent.address}</div>
        </div>
      </div>

      {/* Messages */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto p-3 space-y-1 min-h-[260px] max-h-[380px]">
        {/* Empty state tagline */}
        {messages.length === 0 && !isThinking && (
          <div className="text-xs text-zinc-500 italic text-center py-8">
            &ldquo;{agent.tagline}&rdquo;
          </div>
        )}

        {messages.map((msg) => (
          <div key={msg.id} className="animate-message-in">
            {/* Message bubble */}
            <div className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
              {msg.role === "cross-agent" ? (
                <div className="text-[11px] text-zinc-500 italic px-2 py-1.5">
                  {msg.content}
                </div>
              ) : (
                <div
                  className={`
                    max-w-[90%] px-4 py-2.5 rounded-2xl text-[13px] leading-relaxed
                    ${msg.role === "user"
                      ? "bg-white text-zinc-900"
                      : "bg-zinc-800/80 text-zinc-100"
                    }
                  `}
                >
                  {msg.content}
                </div>
              )}
            </div>

            {/* Protocol call beneath message */}
            {msg.showProtocol && (
              <ProtocolCall
                direction={msg.role === "user" ? "send" : "receive"}
                fromAddress={msg.role === "user" ? visitorAddress : msg.fromAddress}
                toAddress={msg.role === "user" ? agent.address : visitorAddress}
                preview={msg.content}
                agentColor={agent.color}
                autoExpand={msg.autoExpandProtocol ?? totalMessageCount <= 2}
              />
            )}
          </div>
        ))}

        {/* Personality-specific thinking indicator */}
        {isThinking && (
          <div className="animate-message-in">
            <div className="flex justify-start">
              <div className="bg-zinc-800/80 px-4 py-2.5 rounded-2xl flex items-center gap-2">
                <span className="text-xs text-zinc-500">{agent.thinkingText}</span>
                <div className={`w-1.5 h-1.5 ${c.thinkingDot} rounded-full animate-dot-1`} />
                <div className={`w-1.5 h-1.5 ${c.thinkingDot} rounded-full animate-dot-2`} />
                <div className={`w-1.5 h-1.5 ${c.thinkingDot} rounded-full animate-dot-3`} />
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Cross-agent suggestion chips */}
      <div className="px-3 pb-3 flex gap-1.5 overflow-x-auto" onClick={(e) => e.stopPropagation()}>
        {agent.chips.map((chip, i) => (
          <button
            key={i}
            onClick={() => onChipClick(chip.text, chip.targetAgent)}
            className={`
              text-[11px] px-2.5 py-1 rounded-full border whitespace-nowrap transition-colors
              ${c.chipBg} ${c.chipText} ${c.chipBorder}
            `}
          >
            {chip.label}
          </button>
        ))}
      </div>
    </div>
  );
}
