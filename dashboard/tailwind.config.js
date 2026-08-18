/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // AEGIS enterprise SOC palette. Surface tokens (bg/panel/panel-2) are
        // driven by CSS variables so they flip between dark and light themes;
        // accent/severity colors are fixed (they read well on both).
        aegis: {
          bg: "rgb(var(--c-bg) / <alpha-value>)",
          panel: "rgb(var(--c-panel) / <alpha-value>)",
          "panel-2": "rgb(var(--c-panel-2) / <alpha-value>)",
          accent: "#4f8cff",
          cyan: "#22d3ee",
          danger: "#ff4d6d",
          ok: "#2dd4a7",
          warn: "#ffb454",
        },
        // Color-coded severity system (Critical → Info) used across the UI.
        sev: {
          critical: "#ff4d6d",
          high: "#ff8a3d",
          medium: "#ffd23f",
          low: "#4f8cff",
          info: "#64748b",
          safe: "#2dd4a7",
        },
      },
      fontFamily: {
        sans: [
          "Inter",
          "IBM Plex Sans",
          "ui-sans-serif",
          "system-ui",
          "Segoe UI",
          "Roboto",
          "Helvetica Neue",
          "Arial",
          "sans-serif",
        ],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(79,140,255,0.25), 0 8px 30px -8px rgba(79,140,255,0.35)",
        "glow-danger": "0 0 0 1px rgba(255,77,109,0.3), 0 8px 30px -8px rgba(255,77,109,0.4)",
        card: "0 1px 0 0 rgba(255,255,255,0.04) inset, 0 10px 34px -14px rgba(0,0,0,0.7)",
      },
      backdropBlur: { xs: "2px" },
      keyframes: {
        "fade-in": { from: { opacity: 0 }, to: { opacity: 1 } },
        "slide-up": {
          from: { opacity: 0, transform: "translateY(8px)" },
          to: { opacity: 1, transform: "translateY(0)" },
        },
        "slide-in-right": {
          from: { opacity: 0, transform: "translateX(16px)" },
          to: { opacity: 1, transform: "translateX(0)" },
        },
        "pulse-ring": {
          "0%": { boxShadow: "0 0 0 0 rgba(255,77,109,0.5)" },
          "70%": { boxShadow: "0 0 0 10px rgba(255,77,109,0)" },
          "100%": { boxShadow: "0 0 0 0 rgba(255,77,109,0)" },
        },
        "flow-dash": { to: { strokeDashoffset: "-24" } },
        shimmer: { "100%": { transform: "translateX(100%)" } },
        "spin-slow": { to: { transform: "rotate(360deg)" } },
        blip: { "0%,100%": { opacity: 0.25 }, "50%": { opacity: 1 } },
      },
      animation: {
        "fade-in": "fade-in 180ms ease-out",
        "slide-up": "slide-up 220ms cubic-bezier(0.22,1,0.36,1)",
        "slide-in-right": "slide-in-right 220ms cubic-bezier(0.22,1,0.36,1)",
        "pulse-ring": "pulse-ring 1.8s cubic-bezier(0.4,0,0.6,1) infinite",
        "flow-dash": "flow-dash 1s linear infinite",
        shimmer: "shimmer 1.6s infinite",
        "spin-slow": "spin-slow 14s linear infinite",
        blip: "blip 2s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
