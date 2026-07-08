/** @type {import('next').NextConfig} */
const internalApiUrl = process.env.INTERNAL_API_URL || 'http://localhost:8443';

const nextConfig = {
  // Produce a self-contained server bundle for the slim Docker runner stage
  output: 'standalone',
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${internalApiUrl}/api/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
