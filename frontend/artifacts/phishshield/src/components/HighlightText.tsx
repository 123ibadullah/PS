// Renders email body text with suspicious words and URLs underlined in amber.
// Hovering shows a tooltip explaining why the span was flagged.
import React from 'react';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { type SuspiciousSpan } from '@workspace/api-client-react';

interface HighlightTextProps {
  text: string;
  spans: SuspiciousSpan[];
}

function normalizeSpans(text: string, spans: SuspiciousSpan[] = []): SuspiciousSpan[] {
  const textLength = text.length;
  const seen = new Set<string>();

  return [...spans]
    .filter((span) => Number.isFinite(span?.start) && Number.isFinite(span?.end))
    .map((span) => ({
      ...span,
      start: Math.max(0, Math.min(textLength, Number(span.start))),
      end: Math.max(0, Math.min(textLength, Number(span.end))),
    }))
    .filter((span) => span.end > span.start)
    .sort((a, b) => {
      if (a.start !== b.start) return a.start - b.start;
      return (b.end - b.start) - (a.end - a.start);
    })
    .reduce<SuspiciousSpan[]>((acc, span) => {
      const key = `${span.start}:${span.end}:${span.reason}`;
      if (seen.has(key)) return acc;
      seen.add(key);

      const previous = acc[acc.length - 1];
      if (previous && span.start < previous.end) {
        return acc;
      }

      acc.push(span);
      return acc;
    }, []);
}

// Renders plain text but makes any http(s) URLs visually distinct
function TextWithUrls({ text }: { text: string }) {
  const urlRegex = /(https?:\/\/[^\s]+)/g;
  const parts = text.split(urlRegex);
  
  return (
    <>
      {parts.map((part, i) => {
        if (part.match(urlRegex)) {
          return (
            <span key={i} className="text-blue-400/80 underline cursor-default italic">
              {part}
            </span>
          );
        }
        return <span key={i}>{part}</span>;
      })}
    </>
  );
}

export function HighlightText({ text, spans }: HighlightTextProps) {
  const normalizedSpans = normalizeSpans(text, spans);

  if (normalizedSpans.length === 0) {
    return (
      <div className="whitespace-pre-wrap text-foreground/70 leading-relaxed font-mono text-sm">
        <TextWithUrls text={text} />
      </div>
    );
  }

  const elements: React.ReactNode[] = [];
  let lastIndex = 0;

  normalizedSpans.forEach((span, i) => {
    // Add text before the span
    if (span.start > lastIndex) {
      elements.push(
        <span key={`text-${i}`} className="text-foreground/70 leading-relaxed">
          <TextWithUrls text={text.slice(lastIndex, span.start)} />
        </span>
      );
    }
    
    // Add the highlighted span
    const spanText = text.slice(span.start, span.end);
    if (spanText) {
      elements.push(
        <TooltipProvider key={`span-${i}`}>
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="underline underline-offset-2 decoration-warning/60 decoration-wavy text-warning/90 cursor-help transition-colors hover:text-warning inline-block">
                {spanText}
              </span>
            </TooltipTrigger>
            <TooltipContent className="bg-popover border border-popover-border text-foreground shadow-sm font-medium max-w-62.5">
              <p>{span.reason}</p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      );
    }
    lastIndex = Math.max(lastIndex, span.end);
  });

  // Add remaining text
  if (lastIndex < text.length) {
    elements.push(
      <span key="text-last" className="text-foreground/70 leading-relaxed">
        <TextWithUrls text={text.slice(lastIndex)} />
      </span>
    );
  }

  return <div className="whitespace-pre-wrap font-mono text-sm">{elements}</div>;
}
