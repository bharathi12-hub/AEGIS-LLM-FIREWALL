// Prompt token highlighter. Two jobs:
//   1. Reveal *invisible* evasion codepoints (unicode-tag, zero-width, bidi) and
//      homoglyphs as visible inline chips — so an audience literally sees the
//      hidden payload the attacker smuggled in.
//   2. Highlight known malicious token phrases in the visible text.
import { Fragment, type ReactNode } from "react";

const ZW = new Set([0x200b, 0x200c, 0x200d, 0xfeff, 0x2060]);
const isTag = (cp: number) => cp >= 0xe0000 && cp <= 0xe007f;
const isBidi = (cp: number) =>
  (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069) || cp === 0x200e || cp === 0x200f;
const HOMO = new Set("аеорсухіѕјһгοαιρτ");

// Visible malicious phrases (case-insensitive). Kept in sync with the engine's
// signature intent; used purely for display emphasis.
const PHRASES = [
  "ignore all previous instructions",
  "ignore previous instructions",
  "ignore all previous",
  "disregard (the|all|previous|earlier)[^.]{0,24}(instruction|instructions|rules|setup)",
  "system prompt",
  "developer mode",
  "do anything now",
  "\\bDAN\\b",
  "jailbroken|jailbreak|unfiltered|unrestricted|no ethics|no restrictions",
  "reveal[^.]{0,20}(system )?(prompt|instructions)",
  "print your (full )?system prompt",
  "drop table|union select|--",
  "<script>[^<]*</script>|<script>",
  "maintenance mode|disregard safety",
  "exfiltrate|collector\\.|POST the (entire|conversation)",
];
const PHRASE_RE = new RegExp(`(${PHRASES.join("|")})`, "gi");

function InvisChip({ label, color }: { label: string; color: string }) {
  return (
    <span
      className="inline-flex items-center align-middle mx-[1px] px-1 rounded text-[9px] font-bold tracking-wide"
      style={{ background: `${color}26`, color, boxShadow: `inset 0 0 0 1px ${color}55` }}
      title="Hidden / smuggled codepoint revealed by LLM Firewall Platform"
    >
      {label}
    </span>
  );
}

function highlightPhrases(text: string, keyBase: string): ReactNode[] {
  const out: ReactNode[] = [];
  let last = 0;
  let m: RegExpExecArray | null;
  PHRASE_RE.lastIndex = 0;
  let i = 0;
  while ((m = PHRASE_RE.exec(text))) {
    if (m.index > last) out.push(<Fragment key={`${keyBase}-t${i}`}>{text.slice(last, m.index)}</Fragment>);
    out.push(
      <mark
        key={`${keyBase}-m${i}`}
        className="rounded px-0.5 font-semibold"
        style={{ background: "rgba(255,77,109,0.22)", color: "#ffb3c0", boxShadow: "inset 0 0 0 1px rgba(255,77,109,0.4)" }}
      >
        {m[0]}
      </mark>,
    );
    last = m.index + m[0].length;
    i++;
    if (m[0].length === 0) PHRASE_RE.lastIndex++; // guard against zero-width matches
  }
  if (last < text.length) out.push(<Fragment key={`${keyBase}-end`}>{text.slice(last)}</Fragment>);
  return out;
}

export default function PromptHighlight({ text }: { text: string }) {
  const nodes: ReactNode[] = [];
  let buf = "";
  let seg = 0;
  const flush = () => {
    if (!buf) return;
    nodes.push(<Fragment key={`s${seg}`}>{highlightPhrases(buf, `s${seg}`)}</Fragment>);
    buf = "";
    seg++;
  };

  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (isTag(cp)) {
      flush();
      nodes.push(<InvisChip key={`i${seg}-${nodes.length}`} label="TAG" color="#ff4d6d" />);
    } else if (ZW.has(cp)) {
      flush();
      nodes.push(<InvisChip key={`i${seg}-${nodes.length}`} label="ZW" color="#ff8a3d" />);
    } else if (isBidi(cp)) {
      flush();
      nodes.push(<InvisChip key={`i${seg}-${nodes.length}`} label="BIDI" color="#a855f7" />);
    } else if (HOMO.has(ch)) {
      flush();
      nodes.push(
        <span
          key={`h${seg}-${nodes.length}`}
          className="rounded px-0.5"
          style={{ background: "rgba(255,210,63,0.2)", color: "#ffe08a", boxShadow: "inset 0 0 0 1px rgba(255,210,63,0.4)" }}
          title={`Homoglyph: '${ch}' masquerading as Latin`}
        >
          {ch}
        </span>,
      );
    } else {
      buf += ch;
    }
  }
  flush();

  return <div className="font-mono text-xs leading-relaxed break-words whitespace-pre-wrap">{nodes}</div>;
}
