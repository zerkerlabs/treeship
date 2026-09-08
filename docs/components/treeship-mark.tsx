// The Treeship mark: the node glyph from the homepage nav and the favicon.
// Zerker's wordmark is a slashed Z in tracked capitals; this is not that.
// currentColor, so it takes the ink of whatever chrome it sits in.
export function TreeshipMark({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 26 26" fill="none" aria-hidden="true">
      <circle cx="13" cy="5" r="3" fill="currentColor" />
      <circle cx="5" cy="20" r="3" fill="currentColor" opacity="0.55" />
      <circle cx="21" cy="20" r="3" fill="currentColor" opacity="0.55" />
      <line x1="13" y1="8" x2="5" y2="17" stroke="currentColor" strokeWidth="1.5" strokeOpacity="0.45" />
      <line x1="13" y1="8" x2="21" y2="17" stroke="currentColor" strokeWidth="1.5" strokeOpacity="0.45" />
      <line x1="5" y1="20" x2="21" y2="20" stroke="currentColor" strokeWidth="1" strokeOpacity="0.2" strokeDasharray="2 3" />
    </svg>
  );
}

// Mark + wordmark, set the way the homepage nav sets it: Geist, semibold,
// sentence case, tight tracking. Never uppercase, never letter-spaced.
export function TreeshipWordmark({ size = 22 }: { size?: number }) {
  return (
    <span className="inline-flex items-center gap-2 font-sans text-[15px] font-semibold normal-case tracking-[-0.02em] text-zk-ink">
      <TreeshipMark size={size} />
      Treeship
    </span>
  );
}
