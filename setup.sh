#!/bin/bash

###############################################################################
# Security Scanner Platform - Auto Setup Script
# Installa e configura automaticamente tutto l'ambiente
###############################################################################

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🔐 SECURITY SCANNER PLATFORM - AUTO SETUP 🔐          ║
║                                                           ║
║   Setting up complete security testing environment       ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo -e "${RED}⚠️  Please do not run as root${NC}"
    exit 1
fi

# Detect OS
echo -e "\n${CYAN}📋 Detecting operating system...${NC}"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VERSION=$VERSION_ID
    echo -e "${GREEN}✓ Detected: $OS $VERSION${NC}"
else
    echo -e "${RED}✗ Cannot detect OS${NC}"
    exit 1
fi

# Check Docker installation
echo -e "\n${CYAN}🐳 Checking Docker installation...${NC}"
if command -v docker &> /dev/null; then
    DOCKER_VERSION=$(docker --version)
    echo -e "${GREEN}✓ Docker found: $DOCKER_VERSION${NC}"
else
    echo -e "${YELLOW}⚠️  Docker not found. Installing Docker...${NC}"
    
    # Install Docker (Ubuntu/Debian)
    if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
        sudo apt-get update
        sudo apt-get install -y \
            ca-certificates \
            curl \
            gnupg \
            lsb-release
        
        sudo mkdir -p /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        
        echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
          $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        
        sudo apt-get update
        sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
        
        # Add user to docker group
        sudo usermod -aG docker $USER
        
        echo -e "${GREEN}✓ Docker installed successfully${NC}"
        echo -e "${YELLOW}⚠️  Please log out and log back in for group changes to take effect${NC}"
    else
        echo -e "${RED}✗ Automatic Docker installation not supported for this OS${NC}"
        echo -e "${YELLOW}Please install Docker manually: https://docs.docker.com/engine/install/${NC}"
        exit 1
    fi
fi

# Check Docker Compose
echo -e "\n${CYAN}🐳 Checking Docker Compose...${NC}"
if command -v docker-compose &> /dev/null || docker compose version &> /dev/null; then
    echo -e "${GREEN}✓ Docker Compose found${NC}"
else
    echo -e "${YELLOW}⚠️  Installing Docker Compose...${NC}"
    sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    echo -e "${GREEN}✓ Docker Compose installed${NC}"
fi

# Create project directory
PROJECT_DIR="$HOME/security-scanner"
echo -e "\n${CYAN}📁 Creating project directory...${NC}"

if [ -d "$PROJECT_DIR" ]; then
    echo -e "${YELLOW}⚠️  Directory $PROJECT_DIR already exists${NC}"
    read -p "Do you want to overwrite it? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$PROJECT_DIR"
        mkdir -p "$PROJECT_DIR"
    else
        echo -e "${RED}✗ Setup cancelled${NC}"
        exit 1
    fi
else
    mkdir -p "$PROJECT_DIR"
fi

cd "$PROJECT_DIR"
echo -e "${GREEN}✓ Created directory: $PROJECT_DIR${NC}"

# Create necessary subdirectories
mkdir -p scan_results templates static

# Download/create project files
echo -e "\n${CYAN}📥 Setting up project files...${NC}"

# Check if we're in the right directory
if [ -f "orchestrator.py" ] && [ -f "dashboard.py" ]; then
    echo -e "${GREEN}✓ Project files found in current directory${NC}"
    
    # Ensure all required files exist
    if [ ! -f "scanner.py" ]; then
        echo -e "${YELLOW}⚠️  Creating scanner.py...${NC}"
        # Create basic scanner.py if missing
        cat > scanner.py << 'EOF'
#!/usr/bin/env python3
import json
print('{"status": "ready"}')
EOF
    fi
    
    if [ ! -f "Dockerfile" ]; then
        echo -e "${RED}✗ Dockerfile not found${NC}"
        echo -e "${YELLOW}Please create Dockerfile first${NC}"
        exit 1
    fi
    
    if [ ! -f "docker-compose.yml" ]; then
        echo -e "${RED}✗ docker-compose.yml not found${NC}"
        echo -e "${YELLOW}Please create docker-compose.yml first${NC}"
        exit 1
    fi
    
    if [ ! -f "Makefile" ]; then
        echo -e "${YELLOW}⚠️  Creating Makefile...${NC}"
        # Create Makefile if missing
        cat > Makefile << 'EOF'
.PHONY: help start
help:
	@echo "Run: make start"
start:
	docker-compose up -d
EOF
    fi
else
    echo -e "${RED}✗ Required files not found${NC}"
    echo -e "${YELLOW}Please ensure you have:${NC}"
    echo "  - orchestrator.py"
    echo "  - dashboard.py"
    echo "  - scanner.py"
    echo "  - Dockerfile"
    echo "  - docker-compose.yml"
    echo ""
    exit 1
fi
# Verify all files exist
echo -e "\n${CYAN}🔍 Verifying project files...${NC}"
REQUIRED_FILES=("orchestrator.py" "dashboard.py" "requirements.txt" "Dockerfile" "docker-compose.yml")
MISSING_FILES=()

for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${GREEN}✓ $file${NC}"
    else
        echo -e "${RED}✗ $file (missing)${NC}"
        MISSING_FILES+=("$file")
    fi
done

if [ ${#MISSING_FILES[@]} -gt 0 ]; then
    echo -e "\n${RED}✗ Missing required files. Please add them and run setup again.${NC}"
    exit 1
fi

# Build Docker image
echo -e "\n${CYAN}🏗️  Building Docker image (this may take 10-15 minutes)...${NC}"
echo -e "${YELLOW}☕ Grab a coffee while we set everything up!${NC}\n"

docker-compose build

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Docker image built successfully${NC}"
else
    echo -e "${RED}✗ Failed to build Docker image${NC}"
    exit 1
fi

# Start services
echo -e "\n${CYAN}🚀 Starting services...${NC}"
docker-compose up -d

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Services started successfully${NC}"
else
    echo -e "${RED}✗ Failed to start services${NC}"
    exit 1
fi

# Wait for services to be ready
echo -e "\n${CYAN}⏳ Waiting for services to be ready...${NC}"
sleep 5

# Health check
echo -e "\n${CYAN}🏥 Performing health check...${NC}"
for i in {1..10}; do
    if curl -s http://localhost:5000/health > /dev/null; then
        echo -e "${GREEN}✓ Dashboard is healthy and ready!${NC}"
        break
    else
        if [ $i -eq 10 ]; then
            echo -e "${RED}✗ Dashboard failed to start${NC}"
            echo -e "${YELLOW}Check logs with: docker-compose logs${NC}"
            exit 1
        fi
        echo -e "${YELLOW}  Attempt $i/10...${NC}"
        sleep 2
    fi
done

# Create desktop shortcut (optional)
echo -e "\n${CYAN}🖥️  Creating desktop shortcut...${NC}"
DESKTOP_FILE="$HOME/Desktop/SecurityScanner.desktop"

if [ -d "$HOME/Desktop" ]; then
    cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Security Scanner Dashboard
Comment=Web Application Security Testing Platform
Exec=xdg-open http://localhost:5000
Icon=security-high
Terminal=false
Categories=Development;Security;
EOF
    chmod +x "$DESKTOP_FILE"
    echo -e "${GREEN}✓ Desktop shortcut created${NC}"
fi

# Create useful aliases
echo -e "\n${CYAN}🔧 Creating helpful aliases...${NC}"
BASHRC="$HOME/.bashrc"

if ! grep -q "# Security Scanner Aliases" "$BASHRC"; then
    cat >> "$BASHRC" << 'EOF'

# Security Scanner Aliases
alias scanner-start='cd ~/security-scanner && docker-compose up -d'
alias scanner-stop='cd ~/security-scanner && docker-compose down'
alias scanner-logs='cd ~/security-scanner && docker-compose logs -f'
alias scanner-dashboard='xdg-open http://localhost:5000'
alias scanner-scan='docker exec -it security_scanner python3 orchestrator.py'
EOF
    echo -e "${GREEN}✓ Aliases added to ~/.bashrc${NC}"
    echo -e "${YELLOW}  Run 'source ~/.bashrc' to activate them${NC}"
fi

# Final summary
echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                                           ║${NC}"
echo -e "${GREEN}║   ✅ SETUP COMPLETED SUCCESSFULLY! ✅                    ║${NC}"
echo -e "${GREEN}║                                                           ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${CYAN}🎉 Your Security Scanner is ready!${NC}\n"

echo -e "${YELLOW}📊 Access the Dashboard:${NC}"
echo -e "   🌐 http://localhost:5000\n"

echo -e "${YELLOW}🔧 Useful Commands:${NC}"
echo -e "   ${CYAN}scanner-start${NC}      - Start the scanner"
echo -e "   ${CYAN}scanner-stop${NC}       - Stop the scanner"
echo -e "   ${CYAN}scanner-logs${NC}       - View logs"
echo -e "   ${CYAN}scanner-dashboard${NC}  - Open dashboard in browser"
echo -e "   ${CYAN}scanner-scan <url>${NC} - Run CLI scan\n"

echo -e "${YELLOW}📁 Project Location:${NC}"
echo -e "   $PROJECT_DIR\n"

echo -e "${YELLOW}🚀 Quick Start:${NC}"
echo -e "   1. Open browser: http://localhost:5000"
echo -e "   2. Enter target URL (e.g., http://testphp.vulnweb.com)"
echo -e "   3. Click 'Start Scan'"
echo -e "   4. View results in real-time\n"

echo -e "${RED}⚠️  IMPORTANT REMINDER:${NC}"
echo -e "${YELLOW}   Only scan systems you own or have written authorization to test!${NC}"
echo -e "${YELLOW}   Unauthorized scanning is illegal and unethical.${NC}\n"

# Offer to open dashboard
read -p "$(echo -e ${GREEN}Would you like to open the dashboard now? \(Y/n\): ${NC})" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
    if command -v xdg-open &> /dev/null; then
        xdg-open http://localhost:5000
    elif command -v open &> /dev/null; then
        open http://localhost:5000
    else
        echo -e "${YELLOW}Please open http://localhost:5000 in your browser${NC}"
    fi
fi

echo -e "\n${GREEN}Happy Hacking! 🔐${NC}\n"