.PHONY: help build up down logs test rebuild clean env health

# Default target
help:
	@echo "PhishShield Docker Management - Available Commands:"
	@echo ""
	@echo "  make build              Build Docker images for both services"
	@echo "  make up                 Start services in background (docker-compose up -d)"
	@echo "  make down               Stop all services (docker-compose down)"
	@echo "  make logs               View live logs from all services (docker-compose logs -f)"
	@echo "  make test               Run pytest inside backend container"
	@echo "  make rebuild            Rebuild images without cache (docker-compose up --build)"
	@echo "  make clean              Stop services and remove all containers/volumes/images"
	@echo "  make env                Create .env file from .env.example"
	@echo "  make health             Check health of both services"
	@echo "  make status             Show running container status"
	@echo "  make backend-shell      Open bash shell in backend container"
	@echo "  make frontend-shell     Open ash shell in frontend container"
	@echo ""
	@echo "Quick start:"
	@echo "  1. make env             # Create .env and fill in API tokens"
	@echo "  2. make rebuild         # First time build"
	@echo "  3. make up              # Start services"
	@echo "  4. make health          # Verify both are running"
	@echo "  5. make logs            # Watch logs"

# Build images
build:
	@echo "Building Docker images..."
	docker-compose build

# Start services in background
up:
	@echo "Starting PhishShield services..."
	docker-compose up -d
	@echo ""
	@echo "Services starting:"
	@echo "  Backend:  http://localhost:8000/health"
	@echo "  Frontend: http://localhost"
	@echo ""
	@echo "Use 'make logs' to view logs"

# Stop services
down:
	@echo "Stopping PhishShield services..."
	docker-compose down

# View live logs
logs:
	docker-compose logs -f

# Run pytest in backend
test:
	@echo "Running tests in backend container..."
	docker-compose exec backend python -m pytest tests/ -v

# Rebuild with --build flag
rebuild:
	@echo "Rebuilding Docker images and starting services..."
	docker-compose up --build -d
	@echo ""
	@echo "Services restarted. Use 'make logs' to view logs"

# Deep clean
clean:
	@echo "Performing deep clean..."
	docker-compose down -v
	docker system prune -f
	@echo "Clean complete. All containers, volumes, and unused images removed."

# Create .env from .env.example
env:
	@if [ -f .env ]; then \
		echo ".env already exists. Skipping..."; \
	else \
		cp .env.example .env; \
		echo ".env created from .env.example"; \
		echo ""; \
		echo "⚠️  Please edit .env and add your API tokens:"; \
		echo "   - HF_TOKEN: Hugging Face API token"; \
		echo "   - VT_API_KEY: VirusTotal API key"; \
		echo ""; \
		echo "Then run: make rebuild"; \
	fi

# Check health of both services
health:
	@echo "Checking service health..."
	@echo ""
	@echo "Backend health:"
	@curl -s http://localhost:8000/health || echo "❌ Backend not responding"
	@echo ""
	@echo ""
	@echo "Frontend health:"
	@curl -s http://localhost/health || echo "❌ Frontend not responding"
	@echo ""

# Show container status
status:
	@echo "Container Status:"
	docker-compose ps

# Backend shell access
backend-shell:
	docker-compose exec backend /bin/bash

# Frontend shell access
frontend-shell:
	docker-compose exec frontend /bin/ash

# View backend logs only
backend-logs:
	docker-compose logs -f backend

# View frontend logs only
frontend-logs:
	docker-compose logs -f frontend

# Restart a specific service
restart-backend:
	docker-compose restart backend

restart-frontend:
	docker-compose restart frontend

# Pull latest base images
pull:
	@echo "Pulling latest base images..."
	docker pull python:3.12-slim
	docker pull node:20-alpine
	docker pull nginx:alpine

# Push images to registry (customize REGISTRY variable)
# Usage: make push REGISTRY=myregistry.azurecr.io
push: build
	@echo "Pushing images to registry..."
	docker tag phishshield-backend:latest $(REGISTRY)/phishshield-backend:latest
	docker tag phishshield-frontend:latest $(REGISTRY)/phishshield-frontend:latest
	docker push $(REGISTRY)/phishshield-backend:latest
	docker push $(REGISTRY)/phishshield-frontend:latest
	@echo "Push complete!"

# Verify docker-compose is working
verify:
	@echo "Verifying Docker setup..."
	@docker --version
	@docker-compose --version
	@echo "✅ Docker and Docker Compose are installed!"

# Development convenience: full restart with logging
dev:
	@echo "Starting in development mode (with live logs)..."
	make down || true
	make rebuild
	make logs

# Production check: verify everything is healthy
prod-check: status
	@echo ""
	@echo "Performing production health checks..."
	@make health

# View docker network
network:
	docker network ls
	@echo ""
	docker network inspect phishshield-network 2>/dev/null || echo "Network not found (services not running)"
