import { useId } from "react";

/**
 * The vault-door mark from docs/public/logo.svg, inlined so it stays crisp at
 * sidebar size. Same geometry and gradient as the site favicon and the packaged
 * app icon (app/build/icon.svg) — one brand, three renderings.
 *
 * The gradient id is derived from useId because an SVG gradient id is global to
 * the document; two inline copies with the same id would make the second one
 * paint with whatever the first resolved to.
 */
export function Logo({ size = 20 }: { size?: number }): React.JSX.Element {
  const gid = `tv-gold-${useId().replace(/[^a-zA-Z0-9]/g, "")}`;
  const stroke = `url(#${gid})`;

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      aria-hidden="true"
      style={{ flexShrink: 0, display: "block" }}
    >
      <defs>
        <linearGradient id={gid} x1="6" y1="6" x2="42" y2="42" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#FFC861" />
          <stop offset="1" stopColor="#E8920C" />
        </linearGradient>
      </defs>
      {/* vault door */}
      <rect x="5.5" y="7.5" width="37" height="33" rx="6.5" stroke={stroke} strokeWidth="3" />
      {/* dial ring */}
      <circle cx="23" cy="24" r="8.5" stroke={stroke} strokeWidth="3" />
      {/* dial hub */}
      <circle cx="23" cy="24" r="2.4" fill={stroke} />
      {/* spokes */}
      <g stroke={stroke} strokeWidth="3" strokeLinecap="round">
        <path d="M23 15.5 V11.5" />
        <path d="M23 36.5 V32.5" />
        <path d="M31.5 24 H35.5" />
        <path d="M14.5 24 H10.5" />
      </g>
      {/* handle */}
      <path d="M37 24 H40.5" stroke={stroke} strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}
