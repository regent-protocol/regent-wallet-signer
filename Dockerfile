FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN pip install --no-cache-dir . && adduser --disabled-password --gecos "" signer
USER signer
ENV LISTEN=0.0.0.0:8402 STATE_FILE=/state/signer.json
VOLUME ["/state"]
EXPOSE 8402
CMD ["regent-wallet-signer", "serve"]
