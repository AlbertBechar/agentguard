FROM python:3.12-slim

WORKDIR /srv
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY system.md entrypoint.sh ./
RUN chmod +x entrypoint.sh && mkdir -p /data

EXPOSE 8080
ENTRYPOINT ["./entrypoint.sh"]
