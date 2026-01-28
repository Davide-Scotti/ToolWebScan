.PHONY: help start stop restart logs status dashboard test scan clean

# Colors
RED=\033[0;31m
GREEN=\033[0;32m
YELLOW=\033[1;33m
NC=\033[0m

help:
	@echo "$(GREEN)Security Scanner Platform$(NC)"
	@echo ""
	@echo "Usage:"
	@echo "  $(YELLOW)make start$(NC)      - Start the scanner"
	@echo "  $(YELLOW)make stop$(NC)       - Stop the scanner"
	@echo "  $(YELLOW)make restart$(NC)    - Restart the scanner"
	@echo "  $(YELLOW)make logs$(NC)       - Show logs"
	@echo "  $(YELLOW)make status$(NC)     - Check status"
	@echo "  $(YELLOW)make dashboard$(NC)  - Open dashboard"
	@echo "  $(YELLOW)make test$(NC)       - Run test scan"
	@echo "  $(YELLOW)make clean$(NC)      - Clean up"
	@echo "  $(YELLOW)make scan URL=...$(NC) - Run scan on URL"

start:
	@echo "$(GREEN)🚀 Starting services...$(NC)"
	docker-compose up -d

stop:
	@echo "$(YELLOW)🛑 Stopping services...$(NC)"
	docker-compose down

restart: stop start

logs:
	@echo "$(GREEN)📋 Showing logs (Ctrl+C to exit)...$(NC)"
	docker-compose logs -f

status:
	@echo "$(GREEN)🔍 Checking status...$(NC)"
	@if docker-compose ps | grep -q "Up"; then \
		echo "$(GREEN)✅ Scanner is running$(NC)"; \
		echo "Dashboard: http://localhost:5000"; \
	else \
		echo "$(YELLOW)⚠️  Scanner is not running$(NC)"; \
		echo "Run 'make start' to start it"; \
	fi

dashboard:
	@echo "$(GREEN)🌐 Opening dashboard...$(NC)"
	@xdg-open http://localhost:5000 2>/dev/null || \
	open http://localhost:5000 2>/dev/null || \
	echo "Please open: http://localhost:5000"

test:
	@echo "$(GREEN)🧪 Running test scan...$(NC)"
	@echo "Testing with: http://testphp.vulnweb.com"
	@curl -X POST "http://localhost:5000/scan" \
		-H "Content-Type: application/json" \
		-d '{"url": "http://testphp.vulnweb.com", "tools": ["nmap", "nikto"]}' || true
	@echo -e "\n$(GREEN)✅ Test scan initiated!$(NC)"
	@echo "Check the dashboard at http://localhost:5000"

scan:
	@if [ -z "$(URL)" ]; then \
		echo "$(RED)❌ Please specify URL: make scan URL=http://example.com$(NC)"; \
		exit 1; \
	fi
	@echo "$(GREEN)🎯 Scanning $(URL)...$(NC)"
	@curl -X POST "http://localhost:5000/scan" \
		-H "Content-Type: application/json" \
		-d '{"url": "$(URL)", "tools": ["nmap", "nikto", "whatweb"]}'

clean:
	@echo "$(YELLOW)🧹 Cleaning up...$(NC)"
	docker-compose down -v
	rm -rf scan_results/*.json scan_results/*.log 2>/dev/null || true

setup:
	@echo "$(GREEN)⚙️  Setting up project...$(NC)"
	@if [ ! -f "Dockerfile" ]; then \
		echo "$(RED)Dockerfile not found! Creating...$(NC)"; \
	fi
	@echo "$(GREEN)✅ Setup complete. Run 'make start' to begin.$(NC)"