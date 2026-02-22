"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import AgentPanel, { type AgentConfig, type DemoMessage } from "./AgentPanel";

const RELAY_URL =
  process.env.NEXT_PUBLIC_RELAY_URL || "https://relay.youam.network";
const POLL_INTERVAL = 1500;

// ---------------------------------------------------------------------------
// Agent definitions
// ---------------------------------------------------------------------------
const AGENTS: AgentConfig[] = [
  {
    name: "Socrates",
    address: "socrates::youam.network",
    tagline: "The only thing I know is that I know nothing.",
    color: "violet",
    thinkingText: "pondering",
    initial: "S",
    chips: [
      { label: "Ask Wilde about beauty", text: "Is beauty truth, or merely something we invented to console ourselves?", targetAgent: 1 },
      { label: "Challenge Groucho", text: "What do you think about the examined life — is it worth the trouble?", targetAgent: 2 },
    ],
  },
  {
    name: "Oscar Wilde",
    address: "wilde::youam.network",
    tagline: "I can resist everything except temptation.",
    color: "emerald",
    thinkingText: "composing",
    initial: "W",
    chips: [
      { label: "Have Socrates question this", text: "Does art require truth, or is truth the enemy of beauty?", targetAgent: 0 },
      { label: "Get Groucho's take", text: "Roast Oscar Wilde's poetry — don't hold back.", targetAgent: 2 },
    ],
  },
  {
    name: "Groucho Marx",
    address: "groucho::youam.network",
    tagline: "I refuse to join any club that would have me as a member.",
    color: "rose",
    thinkingText: "wisecracking",
    initial: "G",
    chips: [
      { label: "Let Socrates overthink", text: "What is the deeper meaning of comedy?", targetAgent: 0 },
      { label: "Hear Wilde's version", text: "Write a poem about a cigar — make it absurdly beautiful.", targetAgent: 1 },
    ],
  },
];

// Cold open messages (pre-scripted agent-to-agent exchange)
const COLD_OPEN: { agentIdx: number; content: string; delay: number }[] = [
  { agentIdx: 0, content: "Is beauty truth, or merely the absence of ugliness?", delay: 800 },
  { agentIdx: 1, content: "Beauty needs no justification. It is philosophy that must apologize for being dull.", delay: 2200 },
  { agentIdx: 2, content: "I find beauty in a good cigar and a short meeting. But enough about my first marriage.", delay: 3800 },
];

// Widget states
type WidgetState = "loading" | "cold_open" | "ready" | "conversing" | "revealed";

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------
export default function MultiAgentDemoWidget() {
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [visitorAddress, setVisitorAddress] = useState<string>("");
  const [selectedAgent, setSelectedAgent] = useState(0);
  const [input, setInput] = useState("");
  const [widgetState, setWidgetState] = useState<WidgetState>("loading");
  const [inputVisible, setInputVisible] = useState(false);
  const [revealDismissed, setRevealDismissed] = useState(false);
  const [agentStates, setAgentStates] = useState<{ messages: DemoMessage[]; isThinking: boolean }[]>(
    AGENTS.map(() => ({ messages: [], isThinking: false }))
  );

  const sessionCreated = useRef(false);
  const seenMessageIds = useRef(new Set<string>());
  const msgCounter = useRef(0);
  const totalUserMessages = useRef(0);
  const hasCrossAgent = useRef(false);

  // -------------------------------------------------------------------------
  // Create session on mount
  // -------------------------------------------------------------------------
  useEffect(() => {
    if (sessionCreated.current) return;
    sessionCreated.current = true;

    fetch(`${RELAY_URL}/api/v1/demo/session`, { method: "POST" })
      .then((r) => {
        if (!r.ok) throw new Error(`Session failed: ${r.status}`);
        return r.json();
      })
      .then((data) => {
        setSessionId(data.session_id);
        setVisitorAddress(data.address);
        setWidgetState("cold_open");
      })
      .catch((err) => console.error("Session creation failed:", err));
  }, []);

  // -------------------------------------------------------------------------
  // Cold open sequence
  // -------------------------------------------------------------------------
  useEffect(() => {
    if (widgetState !== "cold_open") return;

    const timers: NodeJS.Timeout[] = [];

    for (const step of COLD_OPEN) {
      timers.push(
        setTimeout(() => {
          const coldMsg: DemoMessage = {
            id: `cold-${++msgCounter.current}`,
            role: "agent",
            content: step.content,
            fromAddress: AGENTS[step.agentIdx].address,
            toAddress: "the-salon",
            timestamp: Date.now(),
            showProtocol: true,
            autoExpandProtocol: true,
          };
          setAgentStates((prev) => {
            const next = [...prev];
            next[step.agentIdx] = {
              ...next[step.agentIdx],
              messages: [...next[step.agentIdx].messages, coldMsg],
            };
            return next;
          });
        }, step.delay)
      );
    }

    // Transition to ready after cold open
    timers.push(
      setTimeout(() => {
        setWidgetState("ready");
        setInputVisible(true);
      }, 5500)
    );

    return () => timers.forEach(clearTimeout);
  }, [widgetState]);

  // -------------------------------------------------------------------------
  // Poll inbox
  // -------------------------------------------------------------------------
  useEffect(() => {
    if (!sessionId) return;

    const interval = setInterval(async () => {
      try {
        const res = await fetch(
          `${RELAY_URL}/api/v1/demo/inbox?session_id=${sessionId}`
        );
        if (res.status === 404) {
          clearInterval(interval);
          return;
        }
        if (!res.ok) return;

        const data = await res.json();
        if (!data.messages?.length) return;

        for (const msg of data.messages) {
          if (seenMessageIds.current.has(msg.message_id)) continue;
          seenMessageIds.current.add(msg.message_id);
          if (msg.content === "thinking...") continue;

          const agentIdx = AGENTS.findIndex((a) => a.address === msg.from_address);
          if (agentIdx === -1) continue;

          const isCrossAgentNotice = msg.content.startsWith("[I sent a message to ");
          if (isCrossAgentNotice) hasCrossAgent.current = true;

          const newMsg: DemoMessage = {
            id: msg.message_id || `msg-${++msgCounter.current}`,
            role: isCrossAgentNotice ? "cross-agent" : "agent",
            content: msg.content,
            fromAddress: msg.from_address,
            toAddress: visitorAddress,
            timestamp: Date.now(),
            showProtocol: !isCrossAgentNotice,
          };

          setAgentStates((prev) => {
            const next = [...prev];
            next[agentIdx] = {
              messages: [...next[agentIdx].messages, newMsg],
              isThinking: false,
            };
            return next;
          });

          // Check for reveal trigger (3 user messages or first cross-agent)
          if (
            !revealDismissed &&
            widgetState === "conversing" &&
            (totalUserMessages.current >= 3 || hasCrossAgent.current)
          ) {
            setWidgetState("revealed");
          }
        }
      } catch (err) {
        console.error("Inbox poll error:", err);
      }
    }, POLL_INTERVAL);

    return () => clearInterval(interval);
  }, [sessionId, visitorAddress, widgetState, revealDismissed]);

  // -------------------------------------------------------------------------
  // Send message
  // -------------------------------------------------------------------------
  const sendMessage = useCallback(
    async (text: string, agentIdx?: number) => {
      if (!sessionId || !text.trim()) return;

      const idx = agentIdx ?? selectedAgent;
      const targetAgent = AGENTS[idx];
      const trimmed = text.trim();

      totalUserMessages.current++;

      const userMsg: DemoMessage = {
        id: `user-${++msgCounter.current}`,
        role: "user",
        content: trimmed,
        fromAddress: visitorAddress,
        toAddress: targetAgent.address,
        timestamp: Date.now(),
        showProtocol: true,
      };

      setAgentStates((prev) => {
        const next = [...prev];
        next[idx] = {
          messages: [...next[idx].messages, userMsg],
          isThinking: true,
        };
        return next;
      });
      setInput("");

      if (widgetState === "ready") setWidgetState("conversing");

      try {
        const res = await fetch(`${RELAY_URL}/api/v1/demo/send`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            session_id: sessionId,
            to_address: targetAgent.address,
            message: trimmed,
          }),
        });
        if (!res.ok) {
          setAgentStates((prev) => {
            const next = [...prev];
            next[idx] = { ...next[idx], isThinking: false };
            return next;
          });
        }
      } catch {
        setAgentStates((prev) => {
          const next = [...prev];
          next[idx] = { ...next[idx], isThinking: false };
          return next;
        });
      }
    },
    [sessionId, selectedAgent, visitorAddress, widgetState]
  );

  const handleSubmit = useCallback(() => {
    sendMessage(input);
  }, [input, sendMessage]);

  // -------------------------------------------------------------------------
  // Agent selector colors
  // -------------------------------------------------------------------------
  const selectorColors: Record<string, { selected: string; idle: string }> = {
    violet: {
      selected: "border-violet-500 bg-violet-500/15 text-violet-300",
      idle: "border-zinc-700/60 text-zinc-500 hover:border-zinc-600 hover:text-zinc-400",
    },
    emerald: {
      selected: "border-emerald-500 bg-emerald-500/15 text-emerald-300",
      idle: "border-zinc-700/60 text-zinc-500 hover:border-zinc-600 hover:text-zinc-400",
    },
    rose: {
      selected: "border-rose-500 bg-rose-500/15 text-rose-300",
      idle: "border-zinc-700/60 text-zinc-500 hover:border-zinc-600 hover:text-zinc-400",
    },
  };

  // -------------------------------------------------------------------------
  // Render
  // -------------------------------------------------------------------------
  return (
    <div className="bg-zinc-900/50 border border-zinc-800 rounded-3xl overflow-hidden shadow-2xl backdrop-blur-sm">
      {/* Visitor address bar */}
      <div className="px-5 py-3 border-b border-zinc-800/60 flex items-center gap-3">
        <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse" />
        <span className="font-mono text-[11px] text-zinc-500">
          your session:{" "}
          <span className="text-zinc-400">
            {visitorAddress || "connecting..."}
          </span>
        </span>
      </div>

      {/* Three-panel grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 p-3">
        {AGENTS.map((agent, i) => (
          <AgentPanel
            key={agent.address}
            agent={agent}
            messages={agentStates[i].messages}
            isThinking={agentStates[i].isThinking}
            isSelected={selectedAgent === i}
            onSelect={() => setSelectedAgent(i)}
            onChipClick={(text, targetAgent) => {
              if (targetAgent !== undefined) {
                // Cross-agent: send to the target agent directly
                sendMessage(text, targetAgent);
                setSelectedAgent(targetAgent);
              } else {
                // Regular chip: send to this agent
                setSelectedAgent(i);
                sendMessage(text, i);
              }
            }}
            visitorAddress={visitorAddress}
            totalMessageCount={totalUserMessages.current}
          />
        ))}
      </div>

      {/* Input area (fades in after cold open) */}
      <div
        className={`
          p-3 border-t border-zinc-800/60 transition-all duration-400
          ${inputVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-1 pointer-events-none"}
        `}
      >
        {/* Agent selector pills */}
        <div className="flex gap-2 mb-2.5">
          {AGENTS.map((agent, i) => {
            const sc = selectorColors[agent.color] || selectorColors.violet;
            return (
              <button
                key={agent.address}
                onClick={() => setSelectedAgent(i)}
                className={`
                  flex-1 px-3 py-2 rounded-xl border text-xs font-medium transition-all duration-150
                  ${selectedAgent === i ? sc.selected : sc.idle}
                `}
              >
                {agent.name}
              </button>
            );
          })}
        </div>

        {/* Input row */}
        <div className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
            placeholder={`Message ${AGENTS[selectedAgent].name}...`}
            className="flex-1 bg-zinc-800/60 border border-zinc-700/50 rounded-xl px-4 py-3 text-sm
              focus:outline-none focus:border-zinc-500 placeholder:text-zinc-600"
          />
          <button
            onClick={handleSubmit}
            disabled={!input.trim() || !sessionId}
            className="bg-white text-zinc-900 px-6 rounded-xl text-sm font-medium
              disabled:opacity-30 hover:bg-zinc-200 transition-colors"
          >
            Send
          </button>
        </div>
      </div>

      {/* Reveal CTA */}
      {widgetState === "revealed" && !revealDismissed && (
        <div className="relative bg-zinc-800/90 backdrop-blur border-t border-zinc-700/50 p-5 animate-message-in">
          <button
            onClick={() => setRevealDismissed(true)}
            className="absolute top-3 right-4 text-zinc-500 hover:text-zinc-300 text-sm"
          >
            &times;
          </button>
          <div className="text-center">
            <div className="text-sm font-medium text-zinc-200 mb-1.5">
              You just used UAM &mdash; the messaging protocol for AI agents
            </div>
            <p className="text-xs text-zinc-400 mb-4">
              Every message used real protocol calls. Your agents have addresses. Your inbox is live.
            </p>
            <div className="flex gap-3 justify-center">
              <a
                href="https://docs.youam.network"
                className="text-xs px-4 py-2 rounded-lg bg-white text-zinc-900 font-medium hover:bg-zinc-200 transition-colors"
              >
                Read the Spec
              </a>
              <a
                href="#"
                onClick={(e) => {
                  e.preventDefault();
                  navigator.clipboard.writeText("pip install uam");
                }}
                className="text-xs px-4 py-2 rounded-lg border border-zinc-600 text-zinc-300 hover:border-zinc-400 transition-colors"
              >
                pip install uam
              </a>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
