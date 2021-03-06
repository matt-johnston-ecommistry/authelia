# =======================================
# ===== Build image for the backend =====
# =======================================
FROM golang:1.13-alpine AS builder-backend

ARG BUILD_TAG
ARG BUILD_COMMIT

# gcc and musl-dev are required for building go-sqlite3
RUN apk --no-cache add gcc musl-dev

WORKDIR /go/src/app

COPY go.mod go.mod
COPY go.sum go.sum

RUN go mod download

COPY cmd cmd
COPY internal internal

# Set the build version and time
RUN echo "Write tag ${BUILD_TAG} and commit ${BUILD_COMMIT} in binary." && \
    BUILD_TIME=`date +"%Y-%m-%d %T"` && \
    sed -i "s/__BUILD_TAG__/${BUILD_TAG}/" cmd/authelia/constants.go && \
    sed -i "s/__BUILD_COMMIT__/${BUILD_COMMIT}/" cmd/authelia/constants.go && \
    sed -i "s/__BUILD_TIME__/${BUILD_TIME}/" cmd/authelia/constants.go

# CGO_ENABLED=1 is mandatory for building go-sqlite3
RUN cd cmd/authelia && GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -tags netgo -ldflags '-w' -o authelia


# ========================================
# ===== Build image for the frontend =====
# ========================================
FROM node:12-alpine AS builder-frontend

WORKDIR /node/src/app
COPY web .

# Install the dependencies and build
RUN npm ci && npm run build

# ===================================
# ===== Authelia official image =====
# ===================================
FROM alpine:3.10.3

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /usr/app

COPY --from=builder-backend /go/src/app/cmd/authelia/authelia authelia
COPY --from=builder-frontend /node/src/app/build public_html

EXPOSE 9091

VOLUME /etc/authelia
VOLUME /var/lib/authelia

CMD ["./authelia", "--config", "/etc/authelia/configuration.yml"]
