import { useState } from 'react';
import { Check, Copy } from 'lucide-react';

interface TerminalWindowProps {
  children: React.ReactNode;
  title?: string;
  copyText?: string;
}

export function TerminalWindow({ children, title = "terminal", copyText }: TerminalWindowProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    if (copyText) {
      navigator.clipboard.writeText(copyText);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="terminal-window overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border">
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-danger" />
          <div className="w-3 h-3 rounded-full bg-warning" />
          <div className="w-3 h-3 rounded-full bg-success" />
        </div>
        <span className="text-xs font-mono text-muted-foreground">{title}</span>
        {copyText && (
          <button onClick={handleCopy} className="text-muted-foreground hover:text-primary transition-colors">
            {copied ? <Check size={14} /> : <Copy size={14} />}
          </button>
        )}
      </div>
      <div className="p-4 font-mono text-sm leading-relaxed overflow-x-auto">
        {children}
      </div>
    </div>
  );
}
