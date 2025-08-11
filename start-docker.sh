#!/bin/bash

# Volatility3 Web Interface - Docker Compose Startup Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Default profile
PROFILE="basic"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --profile)
            PROFILE="$2"
            shift 2
            ;;
        --help|-h)
            echo "Volatility3 Web Interface - Docker Compose Startup"
            echo ""
            echo "Usage: $0 [--profile PROFILE]"
            echo ""
            echo "Profiles:"
            echo "  basic      - Core Volatility web interface only (default)"
            echo "  files      - Core + File Browser"
            echo "  monitoring - Core + Prometheus + Grafana"
            echo "  logging    - Core + ELK Stack"
            echo "  full       - All services"
            echo ""
            echo "Examples:"
            echo "  $0                    # Start basic service"
            echo "  $0 --profile files    # Start with file browser"
            echo "  $0 --profile full     # Start all services"
            exit 0
            ;;
        *)
            print_error "Unknown argument: $1"
            exit 1
            ;;
    esac
done

print_status "Starting Volatility3 Web Interface..."
print_status "Profile: $PROFILE"

# Create required directories
print_status "Creating required directories..."
mkdir -p data memory-dumps monitoring/grafana-provisioning logstash/config

# Set proper permissions
print_status "Setting permissions..."
chmod 755 data memory-dumps

# Check if Docker and Docker Compose are available
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed or not in PATH"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose is not installed or not in PATH"
    exit 1
fi

# Stop any existing containers
print_status "Stopping existing containers..."
docker-compose down 2>/dev/null || true

# Start services based on profile
case $PROFILE in
    basic)
        print_status "Starting basic Volatility web interface..."
        docker-compose up -d
        SERVICES="Volatility Web Interface"
        URLS="http://localhost:8080"
        ;;
    files)
        print_status "Starting with file browser..."
        docker-compose --profile filebrowser up -d
        SERVICES="Volatility Web Interface, File Browser"
        URLS="http://localhost:8080 (Web Interface), http://localhost:8081 (File Browser)"
        ;;
    monitoring)
        print_status "Starting with monitoring stack..."
        docker-compose --profile monitoring up -d
        SERVICES="Volatility Web Interface, Prometheus, Grafana"
        URLS="http://localhost:8080 (Web Interface), http://localhost:3000 (Grafana)"
        ;;
    logging)
        print_status "Starting with logging stack..."
        docker-compose --profile logging up -d
        SERVICES="Volatility Web Interface, Elasticsearch, Logstash, Kibana"
        URLS="http://localhost:8080 (Web Interface), http://localhost:5601 (Kibana)"
        ;;
    full)
        print_status "Starting all services..."
        docker-compose --profile filebrowser --profile monitoring --profile logging up -d
        SERVICES="All services (Web Interface, File Browser, Monitoring, Logging)"
        URLS="http://localhost:8080 (Web Interface), http://localhost:8081 (File Browser), http://localhost:3000 (Grafana), http://localhost:5601 (Kibana)"
        ;;
    *)
        print_error "Unknown profile: $PROFILE"
        exit 1
        ;;
esac

# Wait for services to start
print_status "Waiting for services to start..."
sleep 10

# Check if main service is running
if docker-compose ps | grep -q "volatility3-web.*Up"; then
    print_success "Services started successfully!"
    echo ""
    echo "Started services: $SERVICES"
    echo "Available URLs: $URLS"
    echo ""
    echo "To view logs: docker-compose logs -f"
    echo "To stop services: docker-compose down"
    echo ""
else
    print_error "Failed to start services. Check logs with: docker-compose logs"
    exit 1
fi

# Additional instructions based on profile
case $PROFILE in
    files)
        echo "File Browser default login: admin/admin"
        echo "Configure file browser at: http://localhost:8081"
        ;;
    monitoring)
        echo "Grafana default login: admin/admin123"
        echo "Prometheus available at: http://localhost:9090"
        ;;
    logging)
        echo "Create Kibana index pattern: volatility-logs-*"
        echo "Elasticsearch available at: http://localhost:9200"
        ;;
    full)
        echo "File Browser default login: admin/admin"
        echo "Grafana default login: admin/admin123"
        echo "Create Kibana index pattern: volatility-logs-*"
        ;;
esac

print_success "Setup complete!"
