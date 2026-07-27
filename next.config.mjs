/** @type {import('next').NextConfig} */
const nextConfig = {
  typescript: {
    // Allows production builds to successfully complete even if type errors exist
    ignoreBuildErrors: true,
  },
  eslint: {
    // Allows production builds to complete even if ESLint errors exist
    ignoreDuringBuilds: true,
  },
};

export default nextConfig;