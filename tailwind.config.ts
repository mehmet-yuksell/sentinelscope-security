import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        base: {
          950: "#07080a",
          900: "#0c0e12",
          850: "#11141a",
          800: "#161a22",
          700: "#1f242e",
          600: "#2a303c",
          500: "#3a4150",
        },
        accent: {
          400: "#5eead4",
          500: "#2dd4bf",
          600: "#14b8a6",
        },
        risk: {
          verylow: "#2dd4bf",
          low: "#60a5fa",
          moderate: "#eab308",
          high: "#f97316",
          critical: "#ef4444",
        },
      },
      fontFamily: {
        sans: ["var(--font-inter)", "system-ui", "sans-serif"],
        mono: ["var(--font-jetbrains)", "ui-monospace", "monospace"],
      },
      keyframes: {
        fadeIn: {
          "0%": { opacity: "0", transform: "translateY(6px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        scoreIn: {
          "0%": { strokeDashoffset: "var(--dash-full)" },
          "100%": { strokeDashoffset: "var(--dash-value)" },
        },
      },
      animation: {
        fadeIn: "fadeIn 0.4s ease-out both",
        scoreIn: "scoreIn 1s cubic-bezier(0.16, 1, 0.3, 1) forwards",
      },
    },
  },
  plugins: [],
};

export default config;
