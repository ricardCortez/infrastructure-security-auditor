# Deployment Guide

## Docker Compose (Development)

```bash
docker-compose up -d
```

## Production (Kubernetes)

```bash
kubectl apply -f k8s/
```

## Environment Variables

See `.env.example` for all required variables.

## Health Checks

- API: `GET /api/v1/health/ready`
- Live: `GET /api/v1/health/live`
