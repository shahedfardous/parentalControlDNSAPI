#!/usr/bin/env python3
"""
Secure FastAPI application for parental control DNS management
Manages BIND DNS server configurations with RPZ (Response Policy Zones)
"""

import os
import re
import json
import asyncio
import logging
import subprocess
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from pathlib import Path
import ipaddress
import shutil
import pwd
import grp

import aiohttp
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, field_validator, Field
from authlib.jose import jwt
from authlib.jose.errors import JoseError

# Configuration
JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key-change-this")
JWT_ALGORITHM = "HS256"
BIND_CONFIG_PATH = "/etc/bind/named.conf.local"
ZONE_PATH = "/var/lib/bind"
LOG_PATH = "/var/log/named/api.log"
CACHE_TTL = 24 * 3600  # 24 hours

# BIND user and group (adjust based on your system)
BIND_USER = "bind"
BIND_GROUP = "bind"

# Add these new constants at the top with other configurations
BIND_BASE_CONFIG = "/etc/bind/named.conf"
BIND_LOCAL_CONFIG = "/etc/bind/named.conf.local"
BIND_OPTIONS_CONFIG = "/etc/bind/named.conf.options"

# Setup logging with fallback
def setup_logging():
    handlers = [logging.StreamHandler()]  # Always include console output
    
    # Try to add file handler, fallback to local directory if /var/log is not accessible
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        handlers.append(logging.FileHandler(LOG_PATH, mode='a'))
    except (PermissionError, OSError):
        # Fallback to local directory
        local_log_path = "./api.log"
        try:
            handlers.append(logging.FileHandler(local_log_path, mode='a'))
            print(f"Warning: Could not write to {LOG_PATH}, logging to {local_log_path}")
        except Exception as e:
            print(f"Warning: Could not create log file, console logging only: {e}")
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers
    )

setup_logging()
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI(
    title="Parental Control DNS API",
    description="Secure DNS management for parental controls using BIND RPZ",
    version="1.0.0"
)

security = HTTPBearer()

# Pydantic models
class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int

class DNSConfigRequest(BaseModel):
    user_id: str = Field(..., pattern=r'^[a-zA-Z0-9_-]+$', min_length=1, max_length=50)
    ip_subnet: str
    domain_categories: List[str] = Field(default=[])
    custom_domains: List[str] = Field(default=[])
    vpn_bypass: bool = Field(default=True)
    
    @field_validator('ip_subnet')
    @classmethod
    def validate_subnet(cls, v):
        try:
            ipaddress.ip_network(v, strict=False)
            return v
        except ValueError:
            raise ValueError('Invalid CIDR notation for ip_subnet')
    
    @field_validator('domain_categories')
    @classmethod
    def validate_categories(cls, v):
        valid_categories = {'social', 'porn', 'gambling', 'fakenews', 'default'}
        for item in v:
            if item not in valid_categories:
                raise ValueError(f'Invalid category: {item}. Must be one of {valid_categories}')
        return v
    
    @field_validator('custom_domains')
    @classmethod
    def validate_domains(cls, v):
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        validated_domains = []
        for domain in v:
            if not re.match(domain_pattern, domain):
                raise ValueError(f'Invalid domain format: {domain}')
            validated_domains.append(domain.lower())
        return validated_domains

class DNSConfigResponse(BaseModel):
    generated_domains_count: int
    blocked_categories: List[str]
    vpn_blocked: bool
    config_location: str
    zone_location: str
    custom_domains: List[str]  # Add this field
    category_domains_count: int  # Add this to show domains from categories
    vpn_domains_count: int  # Add this to show VPN domains count

class CategoriesResponse(BaseModel):
    categories: List[str]

# Global cache for StevenBlack hosts
hosts_cache = {}

# Category to URL mapping
CATEGORY_URLS = {
    'default': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    'fakenews': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-only/hosts',
    'gambling': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts',
    'porn': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts',
    'social': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social-only/hosts'
}
# # Static category domains
# STATIC_CATEGORY_DOMAINS = {
#     "porn": [
#         "pornhub.com", "xvideos.com", "xnxx.com", "redtube.com", "brazzers.com"
#     ],
#     "gambling": [
#         "bet365.com", "pokerstars.com", "casino.com"
#     ],
#     "social": [
#         "facebook.com", "twitter.com", "instagram.com"
#     ],
#     "fakenews": [
#         "infowars.com", "breitbart.com"
#     ],
#     "default": []
# }

# Static category domains
STATIC_CATEGORY_DOMAINS = {
    "porn": [
        "cdn.ampproject.org", "xvideos.com", "xnxx.com", "redtube.com", "brazzers.com"
    ],
    "gambling": [],
    "social": [],
    "fakenews": [],
    "default": []
}

# Common VPN domains to block
VPN_DOMAINS = [
    'nordvpn.com', 'expressvpn.com', 'surfshark.com', 'cyberghostvpn.com',
    'purevpn.com', 'hotspotshield.com', 'tunnelbear.com', 'windscribe.com',
    'protonvpn.com', 'mullvad.net', 'privateinternetaccess.com', 'ipvanish.com',
    'vyprvpn.com', 'zenmate.com', 'hidemyass.com', 'torguard.net'
]

def check_permissions():
    """Check if the application has proper permissions"""
    issues = []
    
    # Check if running as root or with proper permissions
    if os.geteuid() != 0:
        issues.append("Application not running as root - may have permission issues")
    
    # Check BIND directories
    if not os.path.exists(ZONE_PATH):
        issues.append(f"BIND zone directory {ZONE_PATH} does not exist")
    elif not os.access(ZONE_PATH, os.W_OK):
        issues.append(f"No write permission to {ZONE_PATH}")
    
    if not os.path.exists(os.path.dirname(BIND_CONFIG_PATH)):
        issues.append(f"BIND config directory {os.path.dirname(BIND_CONFIG_PATH)} does not exist")
    elif not os.access(os.path.dirname(BIND_CONFIG_PATH), os.W_OK):
        issues.append(f"No write permission to {os.path.dirname(BIND_CONFIG_PATH)}")
    
    # Check if bind user exists
    try:
        pwd.getpwnam(BIND_USER)
    except KeyError:
        issues.append(f"BIND user '{BIND_USER}' does not exist")
    
    try:
        grp.getgrnam(BIND_GROUP)
    except KeyError:
        issues.append(f"BIND group '{BIND_GROUP}' does not exist")
    
    return issues

def get_bind_uid_gid():
    """Get BIND user and group IDs"""
    try:
        bind_uid = pwd.getpwnam(BIND_USER).pw_uid
        bind_gid = grp.getgrnam(BIND_GROUP).gr_gid
        return bind_uid, bind_gid
    except KeyError:
        logger.warning(f"Could not find BIND user/group, using current user")
        return os.getuid(), os.getgid()

def generate_access_token(user_id: str, expires_hours: int = 24) -> str:
    """Generate JWT access token"""
    payload = {
        "sub": user_id,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=expires_hours),
        "user_id": user_id
    }
    
    header = {"alg": JWT_ALGORITHM}
    token = jwt.encode(header, payload, JWT_SECRET)
    return token.decode('utf-8') if isinstance(token, bytes) else token

async def verify_jwt_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token"""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET)
        return payload
    except JoseError as e:
        logger.warning(f"JWT verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token"
        )

async def fetch_hosts_data(url: str, session: aiohttp.ClientSession) -> List[str]:
    """Fetch and parse hosts data from URL"""
    cache_key = url
    current_time = datetime.now()
    
    # Check cache
    if cache_key in hosts_cache:
        cache_data, cache_time = hosts_cache[cache_key]
        if (current_time - cache_time).total_seconds() < CACHE_TTL:
            logger.info(f"Using cached data for {url}")
            return cache_data
    
    try:
        logger.info(f"Fetching hosts data from {url}")
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
            if response.status == 200:
                content = await response.text()
                domains = parse_hosts_content(content)
                # Cache the result
                hosts_cache[cache_key] = (domains, current_time)
                logger.info(f"Fetched {len(domains)} domains from {url}")
                return domains
            else:
                logger.error(f"Failed to fetch {url}: HTTP {response.status}")
                return []
    except Exception as e:
        logger.error(f"Error fetching {url}: {e}")
        return []

def parse_hosts_content(content: str) -> List[str]:
    """Parse hosts file content and extract domains"""
    domains = []
    lines = content.split('\n')
    
    for line in lines:
        line = line.strip()
        # Skip comments and empty lines
        if not line or line.startswith('#'):
            continue
        
        # Parse hosts format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
        parts = line.split()
        if len(parts) >= 2:
            ip = parts[0]
            domain = parts[1]
            
            # Check if it's a blocking entry (0.0.0.0 or 127.0.0.1)
            if ip in ['0.0.0.0', '127.0.0.1'] and domain != 'localhost':
                # Basic domain validation
                if '.' in domain and not domain.startswith('.'):
                    domains.append(domain.lower())
    
    return list(set(domains))  # Remove duplicates

def generate_rpz_zone_content(domains: List[str], user_id: str) -> str:
    """Generate RPZ zone file content"""
    zone_content = f"""$TTL 300
@   IN  SOA localhost. root.localhost. (
    {int(datetime.now().timestamp())}  ; Serial
    3600        ; Refresh
    1800        ; Retry
    604800      ; Expire
    300 )       ; Minimum TTL

@   IN  NS  localhost.

; RPZ entries for {user_id}
"""
    
    for domain in sorted(domains):
        # Add both the domain and wildcard subdomain entries
        zone_content += f"{domain} CNAME .\n"
        zone_content += f"*.{domain} CNAME .\n"
    
    return zone_content

async def write_zone_file(user_id: str, content: str) -> str:
    """Write zone file with proper permissions"""
    zone_file = Path(ZONE_PATH) / f"{user_id}.rpz.zone"
    fallback_used = False
    
    try:
        # Ensure directory exists
        zone_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Write zone file
        await asyncio.get_event_loop().run_in_executor(
            None, zone_file.write_text, content
        )
        
        # Set proper ownership and permissions
        try:
            bind_uid, bind_gid = get_bind_uid_gid()
            os.chown(zone_file, bind_uid, bind_gid)
            os.chmod(zone_file, 0o644)  # rw-r--r--
            logger.info(f"Zone file written with proper permissions: {zone_file}")
        except (PermissionError, OSError) as e:
            logger.warning(f"Could not set proper ownership/permissions for {zone_file}: {e}")
            
    except (PermissionError, OSError) as e:
        # Fallback to local directory if /var/lib/bind is not writable
        local_zone_path = Path("./zones")
        local_zone_path.mkdir(exist_ok=True)
        local_zone_file = local_zone_path / f"{user_id}.rpz.zone"
        
        await asyncio.get_event_loop().run_in_executor(
            None, local_zone_file.write_text, content
        )
        
        logger.warning(f"Could not write to {zone_file}, wrote to {local_zone_file} instead")
        logger.warning(f"Please copy {local_zone_file} to {zone_file} and set proper permissions")
        zone_file = local_zone_file
        fallback_used = True
    
    return str(zone_file)

async def update_bind_config(user_id: str, ip_subnet: str) -> str:
    """Update BIND configuration with new client view"""
    config_file = Path(BIND_LOCAL_CONFIG)
    
    try:
        # Base configuration template for new files
        base_config = """// Basic options
options {
    directory "/var/cache/bind";
    recursion yes;
    allow-recursion { any; };
    dnssec-validation auto;
    auth-nxdomain no;
};

// Standard zones 
"""
        # Read existing config or create new
        if config_file.exists():
            content = config_file.read_text()
        else:
            content = base_config

        # Generate ACL and view configuration for new user
        new_config = f"""
// Define ACL for {user_id}
acl "{user_id}_subnet" {{ {ip_subnet}; }};

// View for {user_id} - Generated on {datetime.now().isoformat()}
view "{user_id}_view" {{
    match-clients {{ {user_id}_subnet; }};
    recursion yes;
    
    // Standard zones
    zone "." {{
        type hint;
        file "/usr/share/dns/root.hints";
    }};

    zone "localhost" {{
        type master;
        file "/etc/bind/db.local";
    }};

    zone "127.in-addr.arpa" {{
        type master;
        file "/etc/bind/db.127";
    }};

    // Custom RPZ zones
    zone "rpz.lancache.net" {{
        type master;
        file "/etc/bind/customZones/db.rpz.lancache.net";
    }};
    
    zone "rpz.staticentry.local" {{
        type master;
        file "/etc/bind/customZones/db.rpz.staticentry.local";
    }};
    
    // Parental Control RPZ
    zone "{user_id}.rpz" {{
        type master;
        file "{ZONE_PATH}/{user_id}.rpz.zone";
        allow-query {{ any; }};
        allow-transfer {{ none; }};
    }};
    
    // Response Policy configuration
    response-policy {{ 
        zone "{user_id}.rpz";
        zone "rpz.lancache.net";
        zone "rpz.staticentry.local";
    }} recursive-only yes;
}};
"""
        # Check if this is first configuration
        is_first_config = "view" not in content

        if is_first_config:
            # For first configuration, add everything including default view
            default_view = """
// Default view for non-matched clients
view "default" {
    match-clients { any; };
    recursion yes;
    
    // Standard zones
    zone "." {
        type hint;
        file "/usr/share/dns/root.hints";
    };

    zone "localhost" {
        type master;
        file "/etc/bind/db.local";
    };

    // Custom RPZ zones
    zone "rpz.lancache.net" {
        type master;
        file "/etc/bind/customZones/db.rpz.lancache.net";
    };
    
    zone "rpz.staticentry.local" {
        type master;
        file "/etc/bind/customZones/db.rpz.staticentry.local";
    };
    
    response-policy { 
        zone "rpz.lancache.net";
        zone "rpz.staticentry.local";
    } recursive-only yes;
};"""
            content = content.rstrip() + "\n\n" + new_config + "\n" + default_view
        else:
            # For subsequent configurations, just insert before default view
            # First remove any existing config for this user
            acl_pattern = rf'\/\/ Define ACL for {re.escape(user_id)}.*?}};'
            view_pattern = rf'view "{re.escape(user_id)}_view".*?^}};'
            
            content = re.sub(acl_pattern, '', content, flags=re.MULTILINE | re.DOTALL)
            content = re.sub(view_pattern, '', content, flags=re.MULTILINE | re.DOTALL)
            
            # Insert new config before default view
            default_view_pos = content.find('view "default"')
            if default_view_pos != -1:
                content = content[:default_view_pos] + new_config + content[default_view_pos:]
            else:
                content = content.rstrip() + "\n\n" + new_config

        # Clean up empty lines
        content = re.sub(r'\n\s*\n\s*\n', '\n\n', content)

        # Create backup
        if config_file.exists():
            backup_file = config_file.with_suffix(f'.backup.{int(datetime.now().timestamp())}')
            shutil.copy2(str(config_file), str(backup_file))
            logger.info(f"Backup created: {backup_file}")

        # Write updated config
        await asyncio.get_event_loop().run_in_executor(
            None, lambda: Path(config_file).write_text(content)
        )

        # Set proper permissions
        bind_uid, bind_gid = get_bind_uid_gid()
        if bind_uid and bind_gid:
            os.chown(str(config_file), bind_uid, bind_gid)
            os.chmod(str(config_file), 0o644)
            logger.info(f"BIND config updated with proper permissions: {config_file}")

        # Test and reload configuration
        if await test_bind_config():
            await reload_bind()
            logger.info(f"Configuration updated successfully for user {user_id}")
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to validate BIND configuration"
            )

        return str(config_file)

    except Exception as e:
        logger.error(f"Error updating BIND config: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update BIND configuration: {str(e)}"
        )

async def test_bind_config():
    """Test BIND configuration syntax"""
    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: subprocess.run(
                ["named-checkconf"],
                capture_output=True,
                text=True,
                check=False  # Don't raise exception on non-zero exit
            )
        )
        
        if result.returncode == 0:
            logger.info("BIND configuration syntax is valid")
            return True
            
        logger.error(f"BIND configuration syntax error: {result.stderr}")
        return False
        
    except FileNotFoundError:
        logger.error("named-checkconf command not found")
        return False
    except Exception as e:
        logger.error(f"Error checking BIND config: {e}")
        return False

async def reload_bind():
    """Reload BIND configuration"""
    if not await test_bind_config():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="BIND configuration syntax error - refusing to reload"
        )
    
    try:
        # Try rndc reload first
        result = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: subprocess.run(
                ["rndc", "reload"],
                capture_output=True,
                text=True,
                check=False
            )
        )
        
        if result.returncode == 0:
            logger.info("BIND reloaded successfully with rndc")
            return True
            
        logger.warning(f"rndc reload failed: {result.stderr}")
        
        # Try systemctl reload as fallback
        result = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: subprocess.run(
                ["systemctl", "reload", "bind9"],
                capture_output=True,
                text=True,
                check=False
            )
        )
        
        if result.returncode == 0:
            logger.info("BIND reloaded successfully with systemctl")
            return True
            
        logger.error(f"Failed to reload BIND: {result.stderr}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reload BIND configuration"
        )
        
    except FileNotFoundError as e:
        logger.error(f"Command not found: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Required commands not found (rndc/systemctl)"
        )
    except Exception as e:
        logger.error(f"Unexpected error reloading BIND: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to reload BIND configuration: {str(e)}"
        )

# API Routes

@app.get("/system-check")
async def system_check():
    """Check system permissions and BIND status"""
    issues = check_permissions()
    
    # Check BIND service status
    bind_status = "unknown"
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "bind9"], 
            capture_output=True, text=True
        )
        bind_status = result.stdout.strip()
    except FileNotFoundError:
        try:
            result = subprocess.run(
                ["service", "bind9", "status"], 
                capture_output=True, text=True
            )
            bind_status = "active" if result.returncode == 0 else "inactive"
        except FileNotFoundError:
            bind_status = "service command not found"
    
    return {
        "permission_issues": issues,
        "bind_status": bind_status,
        "running_as_root": os.geteuid() == 0,
        "bind_config_path": BIND_CONFIG_PATH,
        "zone_path": ZONE_PATH,
        "bind_user": BIND_USER,
        "bind_group": BIND_GROUP
    }

@app.post("/login", response_model=TokenResponse)
async def login(credentials: LoginRequest):
    """Simple login endpoint - replace with proper authentication"""
    
    # SIMPLE AUTHENTICATION - REPLACE WITH PROPER USER VALIDATION
    valid_users = {
        "dnsapi": "dnsapi@123"
    }
    
    if credentials.username in valid_users and valid_users[credentials.username] == credentials.password:
        token = generate_access_token(credentials.username)
        logger.info(f"User {credentials.username} logged in successfully")
        return TokenResponse(
            access_token=token,
            token_type="bearer",
            expires_in=24 * 3600
        )
    else:
        logger.warning(f"Failed login attempt for username: {credentials.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

@app.get("/categories", response_model=CategoriesResponse)
async def get_categories():
    """Get available domain categories"""
    return CategoriesResponse(categories=list(CATEGORY_URLS.keys()))

@app.post("/update-config", response_model=DNSConfigResponse)
async def update_dns_config(
    config: DNSConfigRequest,
    token_data: dict = Depends(verify_jwt_token)
):
    logger.info(f"Updating DNS config for {config.user_id}")
    try:
        category_domains = set()
        # Fetch domains from selected categories
        async with aiohttp.ClientSession() as session:
            for category in config.domain_categories:
                if category in CATEGORY_URLS:
                    domains = await fetch_hosts_data(CATEGORY_URLS[category], session)
                    category_domains.update(domains)
                    logger.info(f"Added {len(domains)} domains from {category} category")
                # Add static domains for this category
                if category in STATIC_CATEGORY_DOMAINS:
                    static_domains = STATIC_CATEGORY_DOMAINS[category]
                    category_domains.update(static_domains)
                    logger.info(f"Added {len(static_domains)} static domains for {category}")

        # Create a copy of all domains starting with category domains
        all_domains = category_domains.copy()
        
        # Add custom domains
        all_domains.update(config.custom_domains)
        
        # Track VPN domains count
        vpn_domains_added = 0
        
        # Modified VPN domains logic
        should_block_vpn = config.vpn_bypass == False
        if should_block_vpn:
            all_domains.update(VPN_DOMAINS)
            vpn_domains_added = len(VPN_DOMAINS)
            logger.info(f"Added {vpn_domains_added} VPN domains")
        
        # Generate and write zone file
        zone_content = generate_rpz_zone_content(list(all_domains), config.user_id)
        zone_location = await write_zone_file(config.user_id, zone_content)
        
        # Update BIND configuration
        config_location = await update_bind_config(config.user_id, config.ip_subnet)
        
        # Reload BIND
        await reload_bind()
        
        logger.info(f"DNS config updated successfully for {config.user_id}")
        
        return DNSConfigResponse(
            generated_domains_count=len(all_domains),
            blocked_categories=config.domain_categories,
            vpn_blocked=should_block_vpn,  # Use the explicit boolean variable
            config_location=config_location,
            zone_location=zone_location,
            custom_domains=config.custom_domains,
            category_domains_count=len(category_domains),
            vpn_domains_count=vpn_domains_added
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error updating DNS config: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

async def remove_user_config(user_id: str) -> dict:
    """Remove DNS configuration for a specific user"""
    config_file = Path(BIND_LOCAL_CONFIG)
    zone_file = Path(ZONE_PATH) / f"{user_id}.rpz.zone"
    
    try:
        if not config_file.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="BIND configuration file not found"
            )

        # Read current config
        content = config_file.read_text()

        # Create backup
        backup_file = config_file.with_suffix(f'.backup.{int(datetime.now().timestamp())}')
        shutil.copy2(str(config_file), str(backup_file))
        
        # Improved patterns to catch timestamp comments and all related configurations
        patterns = [
            # Match timestamp comment
            rf'\/\/ View for {re.escape(user_id)} - Generated on.*?\n',
            # Match ACL definition
            rf'\/\/ Define ACL for {re.escape(user_id)}.*?}};',
            # Match view configuration
            rf'view "{re.escape(user_id)}_view".*?^}};'
        ]
        
        # Apply all patterns
        new_content = content
        for pattern in patterns:
            new_content = re.sub(pattern, '', new_content, flags=re.MULTILINE | re.DOTALL)
        
        # Clean up empty lines (improved to handle multiple consecutive empty lines)
        new_content = re.sub(r'\n{3,}', '\n\n', new_content)
        new_content = new_content.strip() + '\n'

        # Write updated config
        await asyncio.get_event_loop().run_in_executor(
            None, lambda: Path(config_file).write_text(new_content)
        )

        # Remove zone file if exists
        if zone_file.exists():
            zone_file.unlink()
            logger.info(f"Removed zone file: {zone_file}")

        # Test and reload configuration
        if await test_bind_config():
            await reload_bind()
            logger.info(f"Configuration removed successfully for user {user_id}")
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to validate BIND configuration after removal"
            )

        return {
            "status": "success",
            "message": f"Configuration removed for user {user_id}",
            "config_file": str(config_file),
            "zone_file_removed": str(zone_file)
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing configuration for {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to remove configuration: {str(e)}"
        )

# Add remove-config endpoint
@app.delete("/remove-config/{user_id}")
async def remove_config_endpoint(
    user_id: str,
    token_data: dict = Depends(verify_jwt_token)
):
    """Remove DNS configuration for a specific user"""
    return await remove_user_config(user_id)

# Add get-config-details endpoint
@app.get("/get-config-details/{user_id}", response_model=DNSConfigResponse)
async def get_config_details(
    user_id: str,
    token_data: dict = Depends(verify_jwt_token)
):
    """Get detailed DNS configuration for a specific user in a structured format"""
    config_file = Path(BIND_LOCAL_CONFIG)
    zone_file = Path(ZONE_PATH) / f"{user_id}.rpz.zone"
    
    if not config_file.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="BIND configuration file not found"
        )
    
    if not zone_file.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Zone file for user {user_id} not found"
        )
    
    try:
        # Read zone file content
        zone_content = zone_file.read_text()
        
        # Extract domains from zone file
        domains = []
        for line in zone_content.splitlines():
            line = line.strip()
            if line and not line.startswith(';') and not line.startswith('$') and not line.startswith('@'):
                parts = line.split()
                if len(parts) >= 2 and 'CNAME' in parts:
                    domain = parts[0]
                    if not domain.startswith('*'):  # Skip wildcard entries
                        domains.append(domain)
        
        # Read config file to determine blocked categories and VPN status
        config_content = config_file.read_text()
        
        # Extract view configuration for this user
        view_pattern = rf'view "{re.escape(user_id)}_view".*?^}};'
        view_match = re.search(view_pattern, config_content, re.MULTILINE | re.DOTALL)
        
        # Default values
        blocked_categories = []
        vpn_blocked = False
        custom_domains = []
        category_domains_count = 0
        vpn_domains_count = 0
        
        # Try to determine categories and VPN status from comments in the config
        if view_match:
            view_content = view_match.group(0)
            
            # Look for category comments
            category_pattern = r'// Blocked categories: (.*?)$'
            category_match = re.search(category_pattern, view_content, re.MULTILINE)
            if category_match:
                categories_str = category_match.group(1)
                blocked_categories = [cat.strip() for cat in categories_str.split(',')]
            
            # Look for VPN status
            vpn_pattern = r'// VPN blocking: (enabled|disabled)'
            vpn_match = re.search(vpn_pattern, view_content, re.MULTILINE)
            if vpn_match:
                vpn_blocked = vpn_match.group(1) == 'enabled'
        
        # If we couldn't determine from comments, make educated guesses
        if not blocked_categories:
            # Check for common domains from each category
            for category, url in CATEGORY_URLS.items():
                if category == 'default':
                    continue
                    
                # Sample domains for each category
                category_samples = {
                    'porn': ['pornhub.com', 'xvideos.com', 'xnxx.com'],
                    'gambling': ['bet365.com', 'pokerstars.com', 'casino.com'],
                    'social': ['facebook.com', 'twitter.com', 'instagram.com'],
                    'fakenews': ['infowars.com', 'breitbart.com']
                }
                
                if category in category_samples:
                    for sample in category_samples[category]:
                        if sample in domains:
                            blocked_categories.append(category)
                            break
        
        # Check for VPN domains if not determined from comments
        if not vpn_match:
            for vpn_domain in VPN_DOMAINS:
                if vpn_domain in domains:
                    vpn_blocked = True
                    vpn_domains_count += 1
        else:
            vpn_domains_count = len(VPN_DOMAINS) if vpn_blocked else 0
        
        # Identify custom domains (this is an approximation)
        # We'll consider domains not in our standard categories as custom
        async with aiohttp.ClientSession() as session:
            all_category_domains = set()
            for category in CATEGORY_URLS.keys():
                category_domains = await fetch_hosts_data(CATEGORY_URLS[category], session)
                all_category_domains.update(category_domains)
            
            # Domains that aren't in our standard categories and aren't VPN domains
            custom_domains = [d for d in domains if d not in all_category_domains and d not in VPN_DOMAINS]
            category_domains_count = len(domains) - len(custom_domains) - vpn_domains_count
        
        return DNSConfigResponse(
            generated_domains_count=len(domains),
            blocked_categories=blocked_categories,
            vpn_blocked=vpn_blocked,
            config_location=str(config_file),
            zone_location=str(zone_file),
            custom_domains=custom_domains,
            category_domains_count=category_domains_count,
            vpn_domains_count=vpn_domains_count
        )
        
    except Exception as e:
        logger.error(f"Error retrieving configuration details for {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve configuration details: {str(e)}"
        )


# Add get-config endpoint
@app.get("/get-config/{user_id}")
async def get_config_endpoint(
    user_id: str,
    token_data: dict = Depends(verify_jwt_token)
):
    """Get DNS configuration for a specific user"""
    config_file = Path(BIND_LOCAL_CONFIG)
    zone_file = Path(ZONE_PATH) / f"{user_id}.rpz.zone"
    
    if not config_file.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="BIND configuration file not found"
        )
    
    if not zone_file.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Zone file for user {user_id} not found"
        )
    
    return {
        "config_file": str(config_file),
        "zone_file": str(zone_file),
        "zone_content": zone_file.read_text()
    }

# Add get-all-configs endpoint 
@app.get("/get-all-configs")
async def get_all_configs_endpoint(
    token_data: dict = Depends(verify_jwt_token)
):
    """Get DNS configuration for all users"""
    config_file = Path(BIND_LOCAL_CONFIG)
    if not config_file.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="BIND configuration file not found"
        )

    return {
        "config_file": str(config_file),
        "zone_files": [
            {
                "zone_file": str(zone_file),
                "zone_content": zone_file.read_text()
            }
            for zone_file in (Path(ZONE_PATH) / f"{user_id}.rpz.zone").glob("*.zone")
        ]
    }


if __name__ == "__main__":
    import uvicorn
    
    # Check system permissions before starting
    issues = check_permissions()
    if issues:
        print("WARNING: Permission issues detected:")
        for issue in issues:
            print(f"  - {issue}")
        print("\nTo fix these issues, consider:")
        print("1. Running as root: sudo python3 main2.py")
        print("2. Adding your user to the bind group: sudo usermod -a -G bind $USER")
        print("3. Setting proper permissions on BIND directories")
        print()
    
    uvicorn.run(app, host="0.0.0.0", port=8000)
