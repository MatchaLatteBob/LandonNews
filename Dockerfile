FROM python:3.11-slim

WORKDIR /app

# system deps
RUN apt-get update && apt-get install -y build-essential gcc --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# copy app
COPY . /app

# create a non-root user
RUN useradd -m appuser && chown -R appuser /app
USER appuser

ENV FLASK_ENV=production
ENV PORT=5000
EXPOSE 5000

# use shell form so $PORT is expanded at runtime by the container
CMD ["sh", "-c", "gunicorn -w 4 -b 0.0.0.0:$PORT app:app"]
