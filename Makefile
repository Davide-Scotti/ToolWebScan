.PHONY: help build start stop restart logs test status clean

help:
	@echo "🔐 Security Scanner - Available Commands:"
	@echo ""
	@echo "  make build      - Build Docker container"
	@echo "  make start      - Start services"
	@echo "  make stop       - Stop services"
	@echo "  make restart    - Restart services"
	@echo "  make logs       - Show live logs"
	@echo "  make test       - Run test scan"
	@echo "  make status     - Check service status"
	@echo "  make clean      - Remove all containers and volumes"
	@echo ""

build:
	@echo "🏗️  Building Docker container..."
	docker-compose build

start:
	@echo "🚀 Starting services..."
	docker-compose up -d
	@echo ""
	@echo "✅ Services started!"
	@echo "🌐 Dashboard: http://localhost:5000"
	@echo ""

stop:
	@echo "🛑 Stopping services..."
	docker-compose down

restart: stop start

logs:
	@echo "📋 Showing logs (Ctrl+C to exit)..."
	docker-compose logs -f

test:
	@echo "🧪 Running test scan..."
	@echo "Testing with: http://testphp.vulnweb.com"
	@curl -X POST http://localhost:5000/api/start_scan \
		-H "Content-Type: application/json" \
		-d '{"target_url": "http://testphp.vulnweb.com"}' \
		2>/dev/null | python3 -m json.tool || echo "❌ Failed to start scan"
	@echo ""
	@echo "✅ Test scan initiated!"
	@echo "Check the dashboard at http://localhost:5000"

status:
	@echo "📊 Service Status:"
	@docker-compose ps
	@echo ""
	@echo "🏥 Health Check:"
	@curl -s http://localhost:5000/health | python3 -m json.tool || echo "❌ Dashboard not responding"

clean:
	@echo "🧹 Cleaning up..."
	docker-compose down -v
	@echo "✅ Cleanup complete!"