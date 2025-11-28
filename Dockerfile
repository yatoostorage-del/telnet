FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY telnet.py .

ENV BOT_TOKEN=""
ENV OWNER_ID=""

CMD ["python", "telnet.py"]
