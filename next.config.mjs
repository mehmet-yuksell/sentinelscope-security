/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // "standalone" output is what the Dockerfile copies into the runtime
  // image for self-hosted deployments. Vercel does its own output tracing
  // and packaging — enabling standalone there produces a build tree Vercel
  // doesn't expect and breaks its post-build step. `VERCEL` is set
  // automatically in Vercel's build environment.
  output: process.env.VERCEL ? undefined : "standalone",
};

export default nextConfig;
