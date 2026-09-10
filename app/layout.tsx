import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter", display: "swap" });
const jetbrainsMono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-jetbrains", display: "swap" });

const SITE_DESCRIPTION =
  "Analyze the security posture and public intelligence of a website, domain, or IP address — DNS, TLS, HTTP headers, IP reputation, and threat intelligence in one passive scan.";

export const metadata: Metadata = {
  title: {
    default: "SentinelScope — Website & Domain Threat Intelligence",
    template: "%s · SentinelScope",
  },
  description: SITE_DESCRIPTION,
  icons: {
    icon: "data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 24 24%22><text y=%2220%22 font-size=%2220%22>🛡️</text></svg>",
  },
  openGraph: {
    title: "SentinelScope — Website & Domain Threat Intelligence",
    description: SITE_DESCRIPTION,
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "SentinelScope — Website & Domain Threat Intelligence",
    description: SITE_DESCRIPTION,
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} ${jetbrainsMono.variable}`}>
      <body className="min-h-screen bg-base-950 font-sans antialiased">
        {children}
        <footer className="no-print py-6 text-center text-[11px] text-base-600">© 2026 Mehmet Yüksel</footer>
      </body>
    </html>
  );
}
