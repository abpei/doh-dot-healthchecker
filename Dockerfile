FROM python:3.13-slim

LABEL maintainer="doh-monitor"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py dns_probe.py alerting.py ./

CMD ["python", "-u", "main.py"]
