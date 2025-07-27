#!/bin/bash

# Discord Bot Control Panel - Secure Deployment Script
# Usage: ./deploy.sh [production|staging]

set -euo pipefail

ENVIRONMENT=${1:-staging}
PROJECT_NAME="discord-bot-control"
BACKUP_DIR="./backups"
LOG_FILE="./deployment.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        error "This script should not be run as root for security reasons"
    fi
}

# Check system requirements
check_requirements() {
    log "Checking system requirements..."
    
    # Check Docker/Podman
    if ! command -v docker &> /dev/null && ! command -v podman &> /dev/null; then
        error "Docker or Podman is required but not installed"
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null && ! command -v podman-compose &> /dev/null; then
        error "Docker Compose or Podman Compose is required but not installed"
    fi
    
    # Check available disk space (minimum 2GB)
    available_space=$(df . | tail -1 | awk '{print $4}')
    if [[ $available_space -lt 2097152 ]]; then
        error "Insufficient disk space. At least 2GB required."
    fi
    
    success "System requirements met"
}

# Validate environment file
validate_env() {
    log "Validating environment configuration..."
    
    if [[ ! -f ".env" ]]; then
        error ".env file not found. Copy .env.example and configure it."
    fi
    
    # Check required variables
    required_vars=("BOT_TOKEN" "DISCORD_CLIENT_ID" "DISCORD_CLIENT_SECRET" "SECRET_KEY" "REDIS_PASSWORD")
    
    for var in "${required_vars[@]}"; do
        if ! grep -q "^$var=" .env || grep -q "^$var=$" .env || grep -q "${var}=.*_here" .env; then
            error "Environment variable $var is not properly configured in .env"
        fi
    done
    
    # Validate SECRET_KEY length (should be 64 hex chars)
    secret_key=$(grep "^SECRET_KEY=" .env | cut -d'=' -f2)
    if [[ ${#secret_key} -ne 64 ]]; then
        warning "SECRET_KEY should be 32 bytes (64 hex characters) for optimal security"
    fi
    
    success "Environment configuration validated"
}

# Validate configuration files
validate_config() {
    log "Validating configuration files..."
    
    if [[ ! -f "config.json" ]]; then
        error "config.json not found. Create it with allowed Discord user IDs."
    fi
    
    # Validate JSON syntax
    if ! python3 -m json.tool config.json > /dev/null 2>&1; then
        error "config.json contains invalid JSON"
    fi
    
    # Check if allowed_users exists and is not empty
    if ! python3 -c "import json; config=json.load(open('config.json')); assert 'allowed_users' in config and len(config['allowed_users']) > 0" 2>/dev/null; then
        error "config.json must contain 'allowed_users' array with at least one Discord user ID"
    fi
    
    success "Configuration files validated"
}

# Generate SSL certificates if needed
setup_ssl() {
    log "Setting up SSL certificates..."
    
    mkdir -p ssl
    
    if [[ "$ENVIRONMENT" == "production" ]]; then
        if [[ ! -f "ssl/cert.pem" ]] || [[ ! -f "ssl/key.pem" ]]; then
            warning "SSL certificates not found in ssl/ directory"
            echo "For production, you need valid SSL certificates."
            echo "Consider using Let's Encrypt: https://letsencrypt.org/"
            echo ""
            read -p "Do you want to generate self-signed certificates for testing? (y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                generate_self_signed_cert
            else
                error "SSL certificates are required for production deployment"
            fi
        fi
    else
        # Generate self-signed cert for staging
        generate_self_signed_cert
    fi
    
    success "SSL setup completed"
}

generate_self_signed_cert() {
    log "Generating self-signed SSL certificate..."
    
    openssl req -x509 -newkey rsa:4096 -keyout ssl/key.pem -out ssl/cert.pem -days 365 -nodes \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" 2>/dev/null
    
    chmod 600 ssl/key.pem
    chmod 644 ssl/cert.pem
    
    warning "Using self-signed certificate. Not suitable for production!"
}

# Create backup
create_backup() {
    if [[ -d "$BACKUP_DIR" ]] || [[ -f "docker-compose.yml" ]]; then
        log "Creating backup..."
        
        mkdir -p "$BACKUP_DIR"
        backup_file="$BACKUP_DIR/backup-$(date +%Y%m%d-%H%M%S).tar.gz"
        
        tar -czf "$backup_file" --exclude="$BACKUP_DIR" \
            config.json .env ssl/ logs/ docker-compose.yml 2>/dev/null || true
        
        success "Backup created: $backup_file"
    fi
}

# Set secure file permissions
set_permissions() {
    log "Setting secure file permissions..."
    
    # Secure sensitive files
    chmod 600 .env 2>/dev/null || true
    chmod 600 config.json 2>/dev/null || true
    chmod 600 ssl/key.pem 2>/dev/null || true
    chmod 644 ssl/cert.pem 2>/dev/null || true
    
    # Create logs directory with proper permissions
    mkdir -p logs
    chmod 755 logs
    
    # Ensure scripts are executable
    chmod +x deploy.sh 2>/dev/null || true
    
    success "File permissions set"
}

# Deploy application
deploy() {
    log "Deploying Discord Bot Control Panel..."
    
    # Pull latest images
    if command -v docker-compose &> /dev/null; then
        docker-compose pull
        docker-compose down --remove-orphans
        docker-compose up -d --build
    elif command -v podman-compose &> /dev/null; then
        podman-compose pull
        podman-compose down --remove-orphans  
        podman-compose up -d --build
    else
        error "Neither docker-compose nor podman-compose found"
    fi
    
    success "Deployment completed"
}

# Health check
health_check() {
    log "Performing health check..."
    
    # Wait for services to start
    sleep 10
    
    # Check if containers are running
    if command -v docker &> /dev/null; then
        if ! docker ps | grep -q discord-bot-control; then
            error "Discord bot container is not running"
        fi
        if ! docker ps | grep -q discord-bot-redis; then
            error "Redis container is not running"
        fi
    fi
    
    # Check health endpoint
    max_attempts=30
    attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if curl -f -s http://localhost:5000/health > /dev/null 2>&1; then
            success "Health check passed"
            return 0
        fi
        
        log "Health check attempt $attempt/$max_attempts failed, retrying..."
        sleep 2
        ((attempt++))
    done
    
    error "Health check failed after $max_attempts attempts"
}

# Main deployment function
main() {
    log "Starting deployment for environment: $ENVIRONMENT"
    
    check_root
    check_requirements
    validate_env
    validate_config
    setup_ssl
    create_backup
    set_permissions
    deploy
    health_check
    
    success "🎉 Deployment completed successfully!"
    
    echo ""
    echo "=================================="
    echo "  Discord Bot Control Panel"
    echo "=================================="
    echo "Environment: $ENVIRONMENT"
    echo "Backend URL: http://localhost:5000"
    echo "Health Check: http://localhost:5000/health"
    echo ""
    echo "Next steps:"
    echo "1. Set up your frontend (React app)"
    echo "2. Configure your reverse proxy if needed"
    echo "3. Test the Discord OAuth flow"
    echo "4. Monitor logs: docker-compose logs -f"
    echo ""
    
    if [[ "$ENVIRONMENT" == "production" ]]; then
        echo "🔒 Production Security Reminders:"
        echo "- Ensure your domain DNS is pointing to this server"
        echo "- Verify SSL certificates are valid (not self-signed)"
        echo "- Set up monitoring and log aggregation"
        echo "- Configure automated backups"
        echo "- Review firewall rules"
        echo ""
    fi
}

# Script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "${1:-}" in
        production|staging)
            main "$1"
            ;;
        --help|-h)
            echo "Usage: $0 [production|staging]"
            echo ""
            echo "Deploys the Discord Bot Control Panel with security hardening."
            echo ""
            echo "Environments:"
            echo "  production  - Full security hardening, requires SSL certificates"
            echo "  staging     - Development/testing environment with self-signed certs"
            echo ""
            exit 0
            ;;
        *)
            echo "Usage: $0 [production|staging]"
            echo "Use --help for more information"
            exit 1
            ;;
    esac
fi