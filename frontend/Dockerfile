# ── deps stage: install node_modules (cached) ──────────────────────
FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --no-audit --no-fund

# ── builder stage: compile the Next.js app ─────────────────────────
FROM node:20-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
# NEXT_PUBLIC_API_URL is inlined into the client bundle at BUILD time, so it
# must be set here (runtime env vars in docker-compose have NO effect on it).
# The browser will call the backend directly at this URL. Port 8443 is exposed
# on the host via docker-compose, so http://localhost:8443 works from the
# user's browser. Override with --build-arg for non-local deployments.
ARG NEXT_PUBLIC_API_URL=
ARG INTERNAL_API_URL=http://backend:8443
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}
ENV INTERNAL_API_URL=${INTERNAL_API_URL}
RUN npm run build

# ── runner stage: minimal production image ────────────────────────
FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME=0.0.0.0
ENV NEXT_PUBLIC_API_URL=
ENV INTERNAL_API_URL=http://backend:8443

# Non-root user for security
RUN addgroup -g 1001 -S nodejs && adduser -S nextjs -u 1001

COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
COPY --from=builder --chown=nextjs:nodejs /app/public ./public

USER nextjs
EXPOSE 3000
CMD ["node", "server.js"]
