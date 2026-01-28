.PHONY: help build start stop restart logs dashboard scan test clean status

# Colors
CYAN := \033[0;36m
GREEN := \033[0;32m
YELLOW := \033[1;33m
NC := \033[0m

help: ## Show this help message
	@echo ""
	@echo "$(CYAN)╔═══════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(CYAN)║   🔐 Security Scanner - Available Commands              ║$(NC)"
	@echo "$(CYAN)╚═══════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-15s$(NC) %s\n", $$1, $$2}'
	@echo ""

build: ## Build Docker container
	@echo "$(CYAN)🏗️  Building Docker container...$(NC)"
	docker-compose build
	@echo "$(GREEN)✓ Build completed$(NC)"

start: ## Start the scanner services
	@echo "$(CYAN)🚀 Starting services...$(NC)"
	docker-compose up -d
	@sleep 3
	@echo "$(GREEN)✓ Services started$(NC)"
	@echo "$(YELLOW)📊 Dashboard: http://localhost:5000$(NC)"

stop: ## Stop the scanner services
	@echo "$(CYAN)🛑 Stopping services...$(NC)"
	docker-compose down
	@echo "$(GREEN)✓ Services stopped$(NC)"

restart: ## Restart the scanner services
	@echo "$(CYAN)🔄 Restarting services...$(NC)"
	docker-compose restart
	@sleep 3
	@echo "$(GREEN)✓ Services restarted$(NC)"

logs: ## Show container logs
	@echo "$(CYAN)📋 Showing logs (Ctrl+C to exit)...$(NC)"
	docker-compose logs -f

dashboard: ## Open dashboard in browser
	@echo "$(CYAN)🌐 Opening dashboard...$(NC)"
	@command -v xdg-open >/dev/null 2>&1 && xdg-open http://localhost:5000 || \
	 command -v open >/dev/null 2>&1 && open http://localhost:5000 || \
	 echo "$(YELLOW)Please open http://localhost:5000 in your browser$(NC)"

scan: ## Run CLI scan (Usage: make scan URL=http://target.com)
ifndef URL
	@echo "$(YELLOW)⚠️  Usage: make scan URL=http://target.com$(NC)"
else
	@echo "$(CYAN)🎯 Scanning $(URL)...$(NC)"
	@docker exec -it security_scanner python3 orchestrator.py $(URL)
endif

test: ## Run test scan on legal target
	@echo "$(CYAN)🧪 Running test scan...$(NC)"
	@bash test_scanner.sh

clean: ## Clean scan results
	@echo "$(YELLOW)⚠️  This will delete all scan results!$(NC)"
	@read -p "Are you sure? (y/N): " confirm; \
	if [ "$$confirm" = "y" ]; then \
		echo "$(CYAN)🧹 Cleaning scan results...$(NC)"; \
		rm -rf scan_results/*; \
		echo "$(GREEN)✓ Cleaned$(NC)"; \
	else \
		echo "$(YELLOW)Cancelled$(NC)"; \
	fi

status: ## Check scanner status
	@echo "$(CYAN)🔍 Checking status...$(NC)"
	@if docker ps | grep -q security_scanner; then \
		echo "$(GREEN)✓ Scanner is running$(NC)"; \
		echo "$(YELLOW)📊 Dashboard: http://localhost:5000$(NC)"; \
		docker ps --filter name=security_scanner --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"; \
	else \
		echo "$(YELLOW)⚠️  Scanner is not running$(NC)"; \
		echo "$(CYAN)Run 'make start' to start it$(NC)"; \
	fi

install: ## Install/setup everything
	@echo "$(CYAN)📦 Running installation...$(NC)"
	@bash setup.sh

update: ## Update scanner tools
	@echo "$(CYAN)🔄 Updating tools...$(NC)"
	docker exec security_scanner nuclei -update-templates
	@echo "$(GREEN)✓ Tools updated$(NC)"

shell: ## Open shell in container
	@echo "$(CYAN)🐚 Opening shell...$(NC)"
	docker exec -it security_scanner /bin/bash

health: ## Check container health
	@echo "$(CYAN)🏥 Checking health...$(NC)"
	@curl -s http://localhost:5000/health | python3 -m json.tool || echo "$(YELLOW)⚠️  Dashboard not responding$(NC)"

stats: ## Show scan statistics
	@echo "$(CYAN)📈 Fetching statistics...$(NC)"
	@curl -s http://localhost:5000/api/statistics | python3 -m json.tool || echo "$(YELLOW)⚠️  Cannot fetch stats$(NC)"

backup: ## Backup scan results
	@echo "$(CYAN)💾 Creating backup...$(NC)"
	@tar -czf scan_results_backup_$$(date +%Y%m%d_%H%M%S).tar.gz scan_results/
	@echo "$(GREEN)✓ Backup created$(NC)"

rebuild: ## Rebuild container from scratch
	@echo "$(CYAN)🔨 Rebuilding container...$(NC)"
	docker-compose down
	docker-compose build --no-cache
	docker-compose up -d
	@echo "$(GREEN)✓ Rebuild completed$(NC)"

prune: ## Remove all containers and images (clean slate)
	@echo "$(YELLOW)⚠️  This will remove ALL Docker containers and images!$(NC)"
	@read -p "Are you sure? (y/N): " confirm; \
	if [ "$$confirm" = "y" ]; then \
		echo "$(CYAN)🧹 Pruning Docker...$(NC)"; \
		docker-compose down -v; \
		docker system prune -af; \
		echo "$(GREEN)✓ Pruned$(NC)"; \
	else \
		echo "$(YELLOW)Cancelled$(NC)"; \
	fi