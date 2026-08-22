import React, { useState, useRef, useEffect } from 'react';
import { Card } from '../common/Card';
import { useAIChat } from '../../hooks/useAIChat';
import { formatTimestamp } from '../../lib/utils';
import {
  Bot,
  User,
  Send,
  Trash2,
  Zap,
  ShieldCheck,
  Lock,
  ExternalLink,
  Sparkles,
  Loader2,
} from 'lucide-react';

const PROMPT_SHORTCUTS = [
  'Explain my highest-risk device',
  'What does this finding mean?',
  'How can I secure this camera?',
  'Why is my network risk high?',
  'How should I isolate my IoT devices?',
];

interface NemotronChatProps {
  initialPrompt?: string;
}

export const NemotronChat: React.FC<NemotronChatProps> = ({ initialPrompt }) => {
  const { messages, isTyping, error, sendMessage, clearChat } = useAIChat();
  const [inputText, setInputText] = useState<string>('');
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (initialPrompt) {
      sendMessage(initialPrompt);
    }
  }, [initialPrompt]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping]);

  const handleSend = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputText.trim()) return;
    sendMessage(inputText);
    setInputText('');
  };

  const handleShortcut = (shortcut: string) => {
    sendMessage(shortcut);
  };

  return (
    <Card
      title="CipherX"
      subtitle="Defensive cybersecurity assistant & contextual threat intelligence"
      action={
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 px-2.5 py-0.5 text-xs font-semibold text-emerald-400">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
            CipherX Active
          </span>
          <button
            onClick={clearChat}
            title="Reset Advisor Conversation"
            className="p-1 text-slate-400 hover:text-white transition-colors"
          >
            <Trash2 className="h-4 w-4" />
          </button>
        </div>
      }
      className="flex flex-col h-[700px]"
    >
      {/* Defensive Safety Banner */}
      <div className="mb-4 flex items-center justify-between rounded-lg border border-emerald-500/20 bg-emerald-950/20 px-3.5 py-2 text-xs text-emerald-200">
        <div className="flex items-center gap-2">
          <Lock className="h-4 w-4 text-emerald-400 shrink-0" />
          <span>
            <strong>Defensive Guidance Guardrails:</strong> Advisor operates under strict non-destructive, defensive remediation policies.
          </span>
        </div>
        <span className="text-[10px] text-emerald-400 font-mono">CipherX Active</span>
      </div>

      {/* Chat Messages Log */}
      <div className="flex-1 overflow-y-auto space-y-4 pr-2 mb-4">
        {messages.map((msg, index) => {
          const isUser = msg.role === 'user';
          return (
            <div
              key={index}
              className={`flex gap-3 text-xs leading-relaxed ${
                isUser ? 'justify-end' : 'justify-start'
              }`}
            >
              {!isUser && (
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-emerald-950 border border-emerald-500/30 text-emerald-400 shadow-sm">
                  <Bot className="h-4 w-4" />
                </div>
              )}

              <div
                className={`max-w-[85%] rounded-xl p-4 space-y-2.5 ${
                  isUser
                    ? 'bg-cyan-600 text-white shadow-md'
                    : 'bg-slate-950/80 border border-slate-800 text-slate-200 shadow-sm'
                }`}
              >
                <div className="flex items-center justify-between text-[10px] text-slate-400 pb-1 border-b border-slate-800/40">
                  <span className="font-semibold text-slate-300">
                    {isUser ? 'You (Security Operator)' : 'CipherX'}
                  </span>
                  <span>{formatTimestamp(msg.timestamp)}</span>
                </div>

                <div className="whitespace-pre-wrap leading-relaxed">{msg.content}</div>

                {/* Evidence Citations */}
                {!isUser && msg.evidence_citations && msg.evidence_citations.length > 0 && (
                  <div className="pt-2 border-t border-slate-800/60 text-[11px] space-y-1">
                    <span className="font-semibold text-cyan-400">Observed Evidence & Rules:</span>
                    <ul className="list-disc list-inside text-slate-400">
                      {msg.evidence_citations.map((c, i) => (
                        <li key={i}>{c}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Defensive Priorities */}
                {!isUser && msg.defensive_priorities && msg.defensive_priorities.length > 0 && (
                  <div className="rounded-lg bg-slate-900/90 p-2 border border-slate-800 text-[11px] space-y-1">
                    <span className="font-semibold text-emerald-300">Defensive Priorities:</span>
                    <div className="space-y-0.5">
                      {msg.defensive_priorities.map((p, i) => (
                        <div key={i} className="flex items-center gap-1.5 text-slate-300">
                          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                          <span>{p}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {isUser && (
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-cyan-900 text-cyan-200">
                  <User className="h-4 w-4" />
                </div>
              )}
            </div>
          );
        })}

        {isTyping && (
          <div className="flex gap-3 text-xs justify-start">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-emerald-950 border border-emerald-500/30 text-emerald-400">
              <Bot className="h-4 w-4" />
            </div>
            <div className="rounded-xl bg-slate-950/80 border border-slate-800 p-4 text-slate-400 flex items-center gap-2">
              <Loader2 className="h-4 w-4 animate-spin text-emerald-400" />
              <span>CipherX is analyzing defensive telemetry...</span>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Suggested Prompt Shortcuts */}
      <div className="mb-3 space-y-1.5">
        <span className="text-[10px] uppercase font-bold text-slate-400 flex items-center gap-1">
          <Sparkles className="h-3 w-3 text-cyan-400" />
          Suggested Guidance Inquiries
        </span>
        <div className="flex flex-wrap gap-1.5">
          {PROMPT_SHORTCUTS.map((s, i) => (
            <button
              key={i}
              onClick={() => handleShortcut(s)}
              disabled={isTyping}
              className="rounded-full bg-slate-900 border border-slate-800 hover:border-cyan-500/40 hover:text-cyan-300 px-3 py-1 text-[11px] text-slate-300 transition-colors disabled:opacity-50"
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* Input Form */}
      <form onSubmit={handleSend} className="flex gap-2 pt-2 border-t border-slate-800">
        <input
          type="text"
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          disabled={isTyping}
          placeholder="Ask CipherX for defensive advice, subnet isolation, or finding remediation..."
          className="flex-1 rounded-lg border border-slate-800 bg-slate-950 px-4 py-2.5 text-xs text-slate-100 placeholder-slate-400 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
        />
        <button
          type="submit"
          disabled={isTyping || !inputText.trim()}
          className="flex items-center gap-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-800 px-4 py-2.5 text-xs font-bold text-white transition-colors disabled:cursor-not-allowed shadow-md shadow-emerald-600/20"
        >
          <Send className="h-3.5 w-3.5" />
          <span>Ask CipherX</span>
        </button>
      </form>
    </Card>
  );
};
