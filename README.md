# Parental Control DNS API

A secure FastAPI application for managing parental control DNS configurations using BIND DNS server with Response Policy Zones (RPZ).

## Overview

This application provides a REST API to dynamically configure DNS blocking rules for parental controls. It integrates with BIND DNS server to create Response Policy Zones (RPZ) that can block specific domain categories, custom domains, and VPN services.

## Features

- **Category-based Blocking**: Block domains by categories (Adult Content, Gambling, Social Networking, Fake News, Adware/Malware)
- **Custom Domain Blocking**: Add custom domains to block lists
- **VPN Blocking**: Optionally block common VPN services
- **Per-User Configuration**: Create separate DNS policies for different users/subnets
- **Dynamic Updates**: Real-time updates to BIND DNS configurations
- **JWT Authentication**: Secure API access with JWT tokens
- **Automatic Caching**: Efficient caching of domain lists from external sources
- **Health Monitoring**: System health checks and permission validation

## Architecture

The application:
1. Fetches domain lists from StevenBlack's hosts project
2. Generates BIND RPZ zone files with blocked domains
3. Updates BIND configuration with user-specific views
4. Manages DNS policy per IP subnet

## API Endpoints

### Authentication
- `POST /login` - Authenticate and get JWT token
- `GET /health` - Health check endpoint

### Configuration Management  
- `POST /update-config` - Create/update DNS configuration for a user
- `GET /get-config/{user_id}` - Get raw configuration files for a user
- `GET /get-config-details/{user_id}` - Get structured configuration details
- `DELETE /remove-config/{user_id}` - Remove DNS configuration for a user

### Utilities
- `GET /categories` - Get available domain categories
- `GET /system-check` - Check system permissions and BIND status

## Installation

### Prerequisites

1. **BIND DNS Server**: Install and configure BIND9
   ```bash
   sudo apt update
   sudo apt install bind9 bind9utils bind9-doc
   ```

2. **Python Dependencies**: Install required Python packages
   ```bash
   pip3 install fastapi uvicorn aiohttp authlib pydantic
   ```

### System Setup

1. **BIND Configuration**: Ensure BIND is properly configured with:
   - Zone path: `/var/lib/bind`
   - Configuration path: `/etc/bind/named.conf.local`
   - Proper bind user and group permissions

2. **Permissions**: Run the application with appropriate permissions:
   ```bash
   # Option 1: Run as root (recommended for production)
   sudo python3 main.py
   
   # Option 2: Add user to bind group
   sudo usermod -a -G bind $USER
   ```

3. **Security**: Set a strong JWT secret:
   ```bash
   export JWT_SECRET="your-strong-secret-key-here"
   ```

## Usage

### Start the Server

```bash
python3 main.py
```

The server will start on `http://0.0.0.0:8000`

### Basic API Usage

1. **Login to get token**:
   ```bash
   curl -X POST "http://localhost:8000/login" \
        -H "Content-Type: application/json" \
        -d '{"username": "dnsapi", "password": "dnsapi@123"}'
   ```

2. **Update DNS configuration**:
   ```bash
   curl -X POST "http://localhost:8000/update-config" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer YOUR_JWT_TOKEN" \
        -d '{
          "user_id": "family_laptop",
          "ip_subnet": "192.168.1.100/32",
          "domain_categories": ["Adult_Content", "Gambling"],
          "custom_domains": ["example.com", "badsite.org"],
          "vpn_bypass": false
        }'
   ```

3. **Check system status**:
   ```bash
   curl "http://localhost:8000/system-check"
   ```

## Configuration

### Environment Variables

- `JWT_SECRET`: Secret key for JWT tokens (default: "your-secret-key-change-this")

### BIND Configuration Paths

- **Zone Path**: `/var/lib/bind` - Where RPZ zone files are stored
- **Config Path**: `/etc/bind/named.conf.local` - BIND local configuration file
- **Log Path**: `/var/log/named/api.log` - Application log file

### Domain Categories

Available categories from StevenBlack's hosts project:
- `Adware_Malware`: Base malware and adware domains
- `Adult_Content`: Adult/pornographic content
- `Gambling`: Gambling and betting sites
- `Social_Networking`: Social media platforms
- `Fake_News`: Fake news and misinformation sites

## API Request/Response Examples

### DNS Configuration Request
```json
{
  "user_id": "john_laptop",
  "ip_subnet": "192.168.1.150/32",
  "domain_categories": ["Adult_Content", "Gambling"],
  "custom_domains": ["distractingsite.com"],
  "vpn_bypass": false
}
```

### DNS Configuration Response
```json
{
  "generated_domains_count": 15420,
  "blocked_categories": ["Adult_Content", "Gambling"],
  "vpn_blocked": true,
  "config_location": "/etc/bind/named.conf.local",
  "zone_location": "/var/lib/bind/john_laptop.rpz.zone",
  "custom_domains": ["distractingsite.com"],
  "category_domains_count": 15400,
  "vpn_domains_count": 16
}
```

## Security Considerations

1. **Change Default Credentials**: Update the default username/password in the login function
2. **JWT Secret**: Use a strong, unique JWT secret in production
3. **Network Access**: Restrict API access to trusted networks
4. **File Permissions**: Ensure proper BIND file permissions
5. **HTTPS**: Use HTTPS in production deployments

## Logging

The application logs to:
- Primary: `/var/log/named/api.log`
- Fallback: `./api.log` (if primary location not accessible)
- Console: Always enabled

## Troubleshooting

### Permission Issues
Run the system check endpoint to identify permission problems:
```bash
curl "http://localhost:8000/system-check"
```

### BIND Configuration Errors
The application automatically validates BIND configuration before applying changes. Check logs for detailed error messages.

### Fallback Mode
If the application cannot write to system directories, it will create files in the local directory and provide instructions for manual copying.

## Development

### Adding New Categories
Update the `CATEGORY_URLS` dictionary to add new domain category sources.

### Custom Authentication
Replace the simple authentication in the `/login` endpoint with your preferred authentication system.

### Monitoring
The application provides health check and system status endpoints for monitoring integration.

## Support

For issues and questions:
1. Check the `/system-check` endpoint for permission problems
2. Review application logs for detailed error messages
3. Verify BIND configuration syntax with `named-checkconf`
