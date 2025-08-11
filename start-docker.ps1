# Volatility3 Web Interface - Docker Compose Startup Script (PowerShell)

param(
    [string]$ServiceProfile = "basic",
    [switch]$Help
)

# Function to print colored output
function Write-Status {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

if ($Help) {
    Write-Host "Volatility3 Web Interface - Docker Compose Startup"
    Write-Host ""
    Write-Host "Usage: .\start-docker.ps1 [-ServiceProfile PROFILE]"
    Write-Host ""
    Write-Host "Profiles:"
    Write-Host "  basic      - Core Volatility web interface only (default)"
    Write-Host "  files      - Core + File Browser"
    Write-Host "  monitoring - Core + Prometheus + Grafana"
    Write-Host "  logging    - Core + ELK Stack"
    Write-Host "  full       - All services"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\start-docker.ps1                           # Start basic service"
    Write-Host "  .\start-docker.ps1 -ServiceProfile files     # Start with file browser"
    Write-Host "  .\start-docker.ps1 -ServiceProfile full      # Start all services"
    exit 0
}

Write-Status "Starting Volatility3 Web Interface..."
Write-Status "ServiceProfile: $ServiceProfile"

# Create required directories
Write-Status "Creating required directories..."
$directories = @("data", "memory-dumps", "monitoring\grafana-provisioning", "logstash\config")
foreach ($dir in $directories) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# Check if Docker and Docker Compose are available
try {
    docker --version | Out-Null
}
catch {
    Write-Error "Docker is not installed or not in PATH"
    exit 1
}

try {
    docker-compose --version | Out-Null
}
catch {
    Write-Error "Docker Compose is not installed or not in PATH"
    exit 1
}

# Stop any existing containers
Write-Status "Stopping existing containers..."
try {
    docker-compose down 2>$null
}
catch {
    # Ignore errors if no containers are running
}

# Start services based on profile
switch ($ServiceProfile) {
    "basic" {
        Write-Status "Starting basic Volatility web interface..."
        docker-compose up -d
        $Services = "Volatility Web Interface"
        $URLs = "http://localhost:8080"
    }
    "files" {
        Write-Status "Starting with file browser..."
        docker-compose --profile filebrowser up -d
        $Services = "Volatility Web Interface, File Browser"
        $URLs = "http://localhost:8080 (Web Interface), http://localhost:8081 (File Browser)"
    }
    "monitoring" {
        Write-Status "Starting with monitoring stack..."
        docker-compose --profile monitoring up -d
        $Services = "Volatility Web Interface, Prometheus, Grafana"
        $URLs = "http://localhost:8080 (Web Interface), http://localhost:3000 (Grafana)"
    }
    "logging" {
        Write-Status "Starting with logging stack..."
        docker-compose --profile logging up -d
        $Services = "Volatility Web Interface, Elasticsearch, Logstash, Kibana"
        $URLs = "http://localhost:8080 (Web Interface), http://localhost:5601 (Kibana)"
    }
    "full" {
        Write-Status "Starting all services..."
        docker-compose --profile filebrowser --profile monitoring --profile logging up -d
        $Services = "All services (Web Interface, File Browser, Monitoring, Logging)"
        $URLs = "http://localhost:8080 (Web Interface), http://localhost:8081 (File Browser), http://localhost:3000 (Grafana), http://localhost:5601 (Kibana)"
    }
    default {
        Write-Error "Unknown profile: $ServiceProfile"
        exit 1
    }
}

# Wait for services to start
Write-Status "Waiting for services to start..."
Start-Sleep -Seconds 10

# Check if main service is running
$containerStatus = docker-compose ps | Select-String "volatility3-web.*Up"
if ($containerStatus) {
    Write-Success "Services started successfully!"
    Write-Host ""
    Write-Host "Started services: $Services"
    Write-Host "Available URLs: $URLs"
    Write-Host ""
    Write-Host "To view logs: docker-compose logs -f"
    Write-Host "To stop services: docker-compose down"
    Write-Host ""
}
else {
    Write-Error "Failed to start services. Check logs with: docker-compose logs"
    exit 1
}

# Additional instructions based on profile
switch ($ServiceProfile) {
    "files" {
        Write-Host "File Browser default login: admin/admin"
        Write-Host "Configure file browser at: http://localhost:8081"
    }
    "monitoring" {
        Write-Host "Grafana default login: admin/admin123"
        Write-Host "Prometheus available at: http://localhost:9090"
    }
    "logging" {
        Write-Host "Create Kibana index pattern: volatility-logs-*"
        Write-Host "Elasticsearch available at: http://localhost:9200"
    }
    "full" {
        Write-Host "File Browser default login: admin/admin"
        Write-Host "Grafana default login: admin/admin123"
        Write-Host "Create Kibana index pattern: volatility-logs-*"
    }
}

Write-Success "Setup complete!"
