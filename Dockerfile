# Sólo el binario de Go llega al runtime: la interfaz va embebida con go:embed,
# sin Node ni build de frontend. Es una decisión (docs/DISENO.md): una interfaz
# de autenticación sin JavaScript es más pequeña y más fácil de auditar.

FROM golang:1.27.1-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
# CGO fuera: pgx es Go puro, así que el binario sale estático. -trimpath deja las
# rutas de compilación fuera, que es lo que permite reconstruirlo igual desde
# otro directorio.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/account ./cmd/account

FROM alpine:3.24 AS runtime
ENV HOSTNAME=0.0.0.0 PORT=3467
# Alpine con CA y shell: la shell la usa el `command` del compose para cargar el
# fichero de entorno, y las CA hacen falta si GoTrue se alcanza por HTTPS.
# uid 10001, el de las imágenes de la casa.
RUN apk -U upgrade --no-cache \
 && apk add --no-cache ca-certificates \
 && addgroup -S -g 10001 account && adduser -S -u 10001 -G account account
COPY --from=build /out/account /usr/local/bin/account
USER account
EXPOSE 3467
# La sonda va dentro del binario: aquí no hay curl ni wget que preguntar. Pega
# a /api/health, que comprueba la base y GoTrue: una app de cuenta que no llega
# a ninguno de los dos no está sana aunque responda.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["account", "sonda"]
CMD ["account"]

LABEL org.opencontainers.image.title="KaiCorp Account" \
      org.opencontainers.image.description="Sign-in, registration, second factor and OAuth consent for the KaiCorp Labs tools, on a self-hosted Supabase Auth" \
      org.opencontainers.image.source="https://github.com/Ulzuhan/kaicorp-account" \
      org.opencontainers.image.licenses="MIT"
