// GENERATED from design/tokens.json by scripts/gen-design-tokens.py. DO NOT EDIT.

export const color = {
  paper: "#F1F0EA",
  panel: "#EBEAE1",
  ink: "#1F2329",
  muted: "#5F646B",
  faint: "#9B9B93",
  hair: "#DAD8CD",
  hairCool: "#CBCED0",
  steel: "#37454F",
  bronze: "#856733",
  bronzeHi: "#C6A972",
  bronzeLo: "#5E4923",
  verdictPass: "#3B6A4E",
  verdictFail: "#9F4230",
  verdictWarn: "#8F5E1F",
} as const;

export type VerdictKey =
  | "full_pass"
  | "structural_pass"
  | "countersigned"
  | "permitted"
  | "anchored"
  | "declared"
  | "self_asserted"
  | "pending"
  | "revoked"
  | "unverified";

export const verdicts: Record<VerdictKey, { word: string; color: string; glyph: string }> = {
  fullPass: { word: "full pass", color: "#3B6A4E", glyph: "△" },
  structuralPass: { word: "structural pass", color: "#3B6A4E", glyph: "△" },
  countersigned: { word: "countersigned", color: "#3B6A4E", glyph: "△" },
  permitted: { word: "permitted", color: "#3B6A4E", glyph: "○" },
  anchored: { word: "anchored", color: "#3B6A4E", glyph: "◇" },
  declared: { word: "declared", color: "#8F5E1F", glyph: "△" },
  selfAsserted: { word: "self-asserted", color: "#8F5E1F", glyph: "△" },
  pending: { word: "pending", color: "#5F646B", glyph: "·" },
  revoked: { word: "revoked", color: "#9F4230", glyph: "✕" },
  unverified: { word: "unverified", color: "#9F4230", glyph: "✕" },
};
