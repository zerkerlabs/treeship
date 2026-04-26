'use client';

import { useState, useCallback } from 'react';

export function CopyInstall() {
  const [copied, setCopied] = useState(false);
  const command = 'curl -fsSL treeship.dev/install | sh';

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(command).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }, [command]);

  return (
    <button
      type="button"
      onClick={handleCopy}
      className="sidebar-install-banner w-full rounded-lg px-3 py-2.5 text-left text-xs font-mono text-fd-muted-foreground cursor-pointer hover:text-fd-foreground transition-colors"
      title="Click to copy"
    >
      <span className="select-all">$ {command}</span>
      {copied && (
        <span className="ml-2 text-fd-primary text-[10px]">Copied!</span>
      )}
    </button>
  );
}
