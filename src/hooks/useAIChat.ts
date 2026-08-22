import { useState, useCallback } from 'react';
import { AIChatMessage } from '../types';
import { aiService } from '../services/aiService';

export function useAIChat() {
  const [messages, setMessages] = useState<AIChatMessage[]>([
    {
      role: 'assistant',
      content:
        'Greetings. I am CipherX, your defensive security advisor for Cyber Home Shield. I analyze network risk posture, IoT device vulnerabilities, and unusual telemetry flows to recommend defensive remediations.',
      timestamp: new Date().toISOString(),
      confidence: 100,
      evidence_citations: ['Cyber Home Shield Defensive Knowledgebase'],
      defensive_priorities: ['Network Segmentation', 'Least Privilege Services', 'Telemetry Baseline Monitoring'],
      ai_available: true,
    },
  ]);
  const [isTyping, setIsTyping] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const sendMessage = useCallback(
    async (text: string, contextDeviceId?: string) => {
      if (!text.trim() || isTyping) return;

      const userMsg: AIChatMessage = {
        role: 'user',
        content: text.trim(),
        timestamp: new Date().toISOString(),
      };

      setMessages((prev) => [...prev, userMsg]);
      setIsTyping(true);
      setError(null);

      try {
        const history = messages.map((m) => ({
          role: m.role,
          content: m.content,
        }));

        const response = await aiService.chatAdvisory({
          message: text.trim(),
          history,
          context_device_id: contextDeviceId,
        });

        const assistantMsg: AIChatMessage = {
          role: 'assistant',
          content: response.reply?.trim() || 'CipherX returned no message for this request.',
          timestamp: new Date().toISOString(),
          confidence: response.confidence,
          evidence_citations: response.evidence_citations,
          defensive_priorities: response.defensive_priorities,
          suggested_followups: response.suggested_followups,
          model_name: response.model_name,
          ai_available: response.ai_available,
        };

        setMessages((prev) => [...prev, assistantMsg]);
      } catch (err: any) {
        setError(err.message || 'Error communicating with CipherX');
        const fallbackMsg: AIChatMessage = {
          role: 'assistant',
          content:
            'CipherX advisory service encountered an error or is unreachable. Defensive fallback rule: Always isolate untrusted IoT devices onto an isolated VLAN subnet and disable unauthenticated management protocols.',
          timestamp: new Date().toISOString(),
          confidence: 70,
          ai_available: false,
        };
        setMessages((prev) => [...prev, fallbackMsg]);
      } finally {
        setIsTyping(false);
      }
    },
    [messages, isTyping]
  );

  const clearChat = useCallback(() => {
    setMessages([
      {
        role: 'assistant',
        content:
          'Cyber Home Shield session reset. I am ready to advise on authorized home network defenses, device risk breakdowns, and security findings.',
        timestamp: new Date().toISOString(),
        confidence: 100,
        ai_available: true,
      },
    ]);
  }, []);

  return {
    messages,
    isTyping,
    error,
    sendMessage,
    clearChat,
  };
}
