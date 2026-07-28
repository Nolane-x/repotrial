FROM node:24.18.0-bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates coreutils util-linux \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --chown=node:node package.json ./
COPY --chown=node:node bin ./bin
COPY --chown=node:node src ./src
COPY --chown=node:node integrations ./integrations
COPY --chown=node:node schemas ./schemas

USER node
ENTRYPOINT ["node", "/app/bin/repotrial.mjs"]
CMD ["help"]
