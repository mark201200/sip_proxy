FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

CMD ["python", "/app/sip_proxy.py"]
