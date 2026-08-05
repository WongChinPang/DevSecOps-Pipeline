FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN useradd appuser
USER appuser
EXPOSE 8000