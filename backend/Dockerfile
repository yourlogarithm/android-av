ARG RUST_VERSION=1.78
ARG APP_NAME=av-api

FROM rust:${RUST_VERSION}-bookworm as builder
ARG APP_NAME
RUN rustup default nightly
RUN apt-get update && apt-get install -y cmake
WORKDIR /app
COPY . .
RUN cargo build --locked --release --bin ${APP_NAME} && cp target/release/${APP_NAME} /bin/app

FROM debian:bookworm-slim AS final
RUN  apt-get update \
&& apt-get install -y wget \
&& rm -rf /var/lib/apt/lists/*
ARG HARDWARE=cpu
ARG FILENAME=libtensorflow-${HARDWARE}-linux-x86_64-2.15.0.tar.gz
RUN wget -q --no-check-certificate https://storage.googleapis.com/tensorflow/libtensorflow/${FILENAME} \
    && tar -C /usr/local -xzf ${FILENAME} \
    && ldconfig /usr/local/lib \
    && rm ${FILENAME}
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "10001" \
    appuser
USER appuser
WORKDIR /app
COPY --from=builder /bin/app /app
EXPOSE 8000
CMD ["./app"]
