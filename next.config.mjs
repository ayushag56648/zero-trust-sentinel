/** @type {import('next').NextConfig} */
const nextConfig = {
  typescript: {
    // Allows production builds to complete even if type errors exist
    ignoreBuildErrors: true,
  },
};

export default nextConfig;