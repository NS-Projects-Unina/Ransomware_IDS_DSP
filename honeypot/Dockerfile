FROM alpine:3.20

RUN apk add --no-cache python3

WORKDIR /app

COPY honeypot.py /app/honeypot.py
COPY legitimate_service.py /app/legitimate_service.py

EXPOSE 8080 8081

CMD ["sh", "-c", "python3 -u /app/legitimate_service.py & exec python3 -u /app/honeypot.py"]
