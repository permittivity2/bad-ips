#!/bin/bash
# Bad IPs Installation Script v2.0
# One-line install: bash <(curl -fsSL https://projects.thedude.vip/bad-ips/install.sh)

set -e

# Fix stdin for interactive prompts when piped through curl
exec < /dev/tty || true

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Repository configuration
REPO_URL="https://projects.thedude.vip/apt"
GPG_KEY_URL="https://projects.thedude.vip/apt/silver-linings.gpg.key"

# Configuration paths
CONFIG_DIR="/usr/local/etc"
BADIPS_CONF="$CONFIG_DIR/badips.conf"
DB_CONF="$CONFIG_DIR/badips.d/database.conf"

# Print logo
print_logo() {
    echo -e "${CYAN}"
    cat << 'LOGOEOF'
    ____            __   ____  ____
   / __ )____ _____/ /  /  _/ / __ \____
  / __  / __ `/ __  /   / /  / /_/ / ___/
 / /_/ / /_/ / /_/ /  _/ /  / ____(__  )
/_____/\__,_/\__,_/  /___/ /_/    /____/

  Distributed IP Blocking System
  Silver Linings, LLC
LOGOEOF
    echo -e "${NC}"
}

# Read password with asterisks
read_password() {
    local prompt="$1"
    local password=""
    local char

    echo -n "$prompt" >&2

    while IFS= read -r -s -n1 char < /dev/tty; do
        if [[ $char == $'\0' ]]; then
            break
        elif [[ $char == $'\177' ]] || [[ $char == $'\b' ]]; then
            if [[ ${#password} -gt 0 ]]; then
                password="${password%?}"
                echo -ne '\b \b' >&2
            fi
        else
            password+="$char"
            echo -n '*' >&2
        fi
    done
    echo >&2
    echo "$password"
}

# Check if nftables is available
check_nftables() {
    if ! command -v nft &> /dev/null; then
        echo -e "${RED}Error: nftables (nft) is not installed!${NC}"
        echo ""
        echo "Bad IPs requires nftables for firewall management."
        echo "It cannot work with iptables."
        echo ""
        echo "To install nftables:"
        echo "  sudo apt-get install nftables    # Debian/Ubuntu"
        echo "  sudo dnf install nftables         # Fedora/RHEL"
        echo ""
        return 1
    fi

    # Check if iptables (legacy) is actually in use
    # Modern systems use iptables-nft (compatibility layer over nftables), which is fine
    # We only warn if legacy iptables is actually being used
    local USING_LEGACY_IPTABLES=0

    # Check 1: Is iptables-legacy being used?
    if command -v iptables-legacy &> /dev/null; then
        # Check if there are actual legacy iptables rules
        local LEGACY_RULES=$(iptables-legacy -L -n 2>/dev/null | grep -v "^Chain\|^target\|^$" | wc -l)
        if [ "$LEGACY_RULES" -gt 0 ]; then
            USING_LEGACY_IPTABLES=1
        fi
    fi

    # Check 2: Is iptables pointing to legacy instead of nft?
    if command -v iptables &> /dev/null && ! iptables --version 2>&1 | grep -q "nf_tables"; then
        # iptables exists but doesn't mention nf_tables, might be legacy
        local IPTABLES_RULES=$(iptables -L -n 2>/dev/null | grep -v "^Chain\|^target\|^$" | wc -l)
        if [ "$IPTABLES_RULES" -gt 0 ]; then
            USING_LEGACY_IPTABLES=1
        fi
    fi

    if [ $USING_LEGACY_IPTABLES -eq 1 ]; then
        echo ""
        echo -e "${YELLOW}⚠️  Warning: Legacy iptables rules detected${NC}"
        echo ""
        echo "Bad IPs requires nftables. Your system appears to have active legacy iptables rules."
        echo ""
        echo "To migrate from iptables to nftables:"
        echo "  1. Export your current iptables rules:"
        echo "     sudo iptables-save > /tmp/iptables-rules.txt"
        echo ""
        echo "  2. Convert to nftables format:"
        echo "     sudo iptables-restore-translate -f /tmp/iptables-rules.txt > /tmp/nftables-rules.nft"
        echo ""
        echo "  3. Review and load the nftables rules:"
        echo "     sudo nft -f /tmp/nftables-rules.nft"
        echo ""
        echo "  4. Switch to nftables (Debian/Ubuntu):"
        echo "     sudo update-alternatives --set iptables /usr/sbin/iptables-nft"
        echo "     sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-nft"
        echo ""
        echo "For more information: https://wiki.nftables.org/wiki-nftables/index.php/Moving_from_iptables_to_nftables"
        echo ""
        read -p "Continue with installation anyway? [y/N]: " CONTINUE
        if [[ ! "$CONTINUE" =~ ^[Yy]$ ]]; then
            echo "Installation cancelled."
            exit 1
        fi
    fi

    return 0
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root${NC}"
        echo "Usage: become root then -->> bash <(curl -fsSL https://projects.thedude.vip/bad-ips/install.sh)"
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
        echo -e "${GREEN}✓${NC} Detected: $OS $VER"
    else
        echo -e "${RED}Error: Cannot detect OS${NC}"
        exit 1
    fi

    if [[ "$OS" != "ubuntu" ]] && [[ "$OS" != "debian" ]]; then
        echo -e "${RED}Error: Only Ubuntu and Debian are currently supported${NC}"
        exit 1
    fi
}

# Add GPG key
add_gpg_key() {
    echo ""
    echo -e "${BLUE}Adding Silver Linings, LLC GPG key...${NC}"

    # Remove old keys from both possible locations to avoid conflicts
    rm -f /etc/apt/keyrings/silver-linings.gpg
    rm -f /etc/apt/trusted.gpg.d/silver-linings.gpg

    mkdir -p /etc/apt/keyrings
    if ! curl -fsSL "$GPG_KEY_URL" | gpg --batch --no-tty --dearmor -o /etc/apt/keyrings/silver-linings.gpg 2>&1; then
        echo -e "${RED}✗${NC} Failed to download or install GPG key"
        echo ""
        echo "Please check:"
        echo "  - Internet connectivity"
        echo "  - GPG key URL is accessible: $GPG_KEY_URL"
        exit 1
    fi

    echo -e "${GREEN}✓${NC} GPG key added"
}

# Add repository
add_repository() {
    echo -e "${BLUE}Adding Bad IPs apt repository...${NC}"
    
    echo "deb [signed-by=/etc/apt/keyrings/silver-linings.gpg] $REPO_URL ./" > /etc/apt/sources.list.d/bad-ips.list
    
    echo -e "${GREEN}✓${NC} Repository added"
}

# Update apt
update_apt() {
    echo -e "${BLUE}Updating apt cache...${NC}"
    echo ""

    if ! apt-get update; then
        echo ""
        echo -e "${RED}✗${NC} Failed to update apt cache"
        echo ""
        echo "Common issues:"
        echo "  - Conflicting GPG keys (check /etc/apt/keyrings/ and /etc/apt/trusted.gpg.d/)"
        echo "  - Invalid sources.list entries"
        echo "  - Network connectivity problems"
        echo ""
        echo "To fix GPG key conflicts:"
        echo "  sudo rm -f /etc/apt/trusted.gpg.d/silver-linings.gpg"
        echo "  sudo rm -f /etc/apt/keyrings/silver-linings.gpg"
        echo "  Then run this installer again"
        exit 1
    fi

    echo ""
    echo -e "${GREEN}✓${NC} Apt cache updated"
}

# Install Bad IPs package
install_badips() {
    echo -e "${BLUE}Installing Bad IPs package...${NC}"
    echo ""

    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y bad-ips; then
        echo ""
        echo -e "${RED}✗${NC} Failed to install Bad IPs package"
        echo ""
        echo "Please check:"
        echo "  - Repository is correctly configured"
        echo "  - Package dependencies are available"
        echo "  - Run: apt-cache policy bad-ips"
        exit 1
    fi

    echo ""
    echo -e "${GREEN}✓${NC} Bad IPs installed"
}

# Generate random password
generate_password() {
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 16
}

# Test PostgreSQL connection
test_pg_connection() {
    local host=$1
    local port=$2
    local dbname=$3
    local user=$4
    local password=$5
    local timeout=${6:-15}  # Default 15 second timeout

    timeout "$timeout" bash -c "PGPASSWORD='$password' psql -h '$host' -p '$port' -U '$user' -d '$dbname' -c 'SELECT 1'" > /dev/null 2>&1
    return $?
}

# Test database connection with countdown and retry
test_pg_connection_with_retry() {
    local host=$1
    local port=$2
    local dbname=$3
    local user=$4
    local password=$5
    local max_attempts=3
    local timeout=15

    for attempt in $(seq 1 $max_attempts); do
        if [ $attempt -gt 1 ]; then
            echo ""
            echo -e "${YELLOW}Retry attempt $attempt of $max_attempts...${NC}"
        fi

        echo -n "Testing connection"

        # Start connection test in background
        ( PGPASSWORD="$password" psql -h "$host" -p "$port" -U "$user" -d "$dbname" -c "SELECT 1" > /dev/null 2>&1 ) &
        local pid=$!

        # Countdown timer
        local elapsed=0
        while [ $elapsed -lt $timeout ]; do
            if ! kill -0 $pid 2>/dev/null; then
                # Process finished
                wait $pid
                local result=$?
                echo ""
                if [ $result -eq 0 ]; then
                    echo -e "${GREEN}✓${NC} Connection successful!"
                    return 0
                else
                    echo -e "${RED}✗${NC} Connection failed!"
                    break
                fi
            fi
            echo -n "."
            sleep 1
            elapsed=$((elapsed + 1))
        done

        # Timeout reached
        if kill -0 $pid 2>/dev/null; then
            kill $pid 2>/dev/null
            wait $pid 2>/dev/null
            echo ""
            echo -e "${RED}✗${NC} Connection timeout after ${timeout}s"
        fi

        # Ask for retry if not last attempt
        if [ $attempt -lt $max_attempts ]; then
            echo ""
            echo "Please verify:"
            echo "  - Database host is reachable: $host"
            echo "  - PostgreSQL is running on $host:$port"
            echo "  - Database '$dbname' exists"
            echo "  - User '$user' has access"
            echo "  - Password is correct"
            echo ""
            read -p "Retry connection? [Y/n/q to quit]: " retry
            if [[ "$retry" =~ ^[Qq]$ ]]; then
                exit 1
            elif [[ "$retry" =~ ^[Nn]$ ]]; then
                return 1
            fi
        fi
    done

    echo ""
    echo -e "${RED}Failed to connect after $max_attempts attempts${NC}"
    read -p "Continue anyway? [y/N]: " continue
    if [[ ! "$continue" =~ ^[Yy]$ ]]; then
        exit 1
    fi
    return 1
}

# Check if PostgreSQL is installed
is_postgresql_installed() {
    dpkg -l | grep -q "^ii.*postgresql-[0-9]" 2>/dev/null
}

# Install and setup PostgreSQL
install_postgresql() {
    echo ""
    echo -e "${BLUE}Installing PostgreSQL...${NC}"
    DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql postgresql-contrib > /dev/null 2>&1
    
    # Start PostgreSQL
    systemctl start postgresql
    systemctl enable postgresql > /dev/null 2>&1
    
    echo -e "${GREEN}✓${NC} PostgreSQL installed and started"
}

# Setup PostgreSQL database and user
setup_postgresql_database() {
    local db_user=$1
    local db_password=$2
    local db_name="bad_ips"
    
    echo ""
    echo -e "${BLUE}Setting up PostgreSQL database...${NC}"
    
    # Create user and database as postgres user
    sudo -u postgres psql > /dev/null 2>&1 <<SQLEOF
-- Create user if not exists
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_user WHERE usename = '$db_user') THEN
        CREATE USER $db_user WITH PASSWORD '$db_password';
    END IF;
END
\$\$;

-- Create database if not exists
SELECT 'CREATE DATABASE $db_name OWNER $db_user'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$db_name')\gexec

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE $db_name TO $db_user;
SQLEOF
    
    # Create tables
    PGPASSWORD="$db_password" psql -h localhost -U "$db_user" -d "$db_name" > /dev/null 2>&1 <<'CREATETABLES'
-- Create jailed_ips table
CREATE TABLE IF NOT EXISTS jailed_ips (
    id SERIAL PRIMARY KEY,
    ip inet NOT NULL,
    originating_server VARCHAR(255) NOT NULL,
    originating_service VARCHAR(255),
    detector_name VARCHAR(255),
    pattern_matched TEXT,
    matched_log_line TEXT,
    first_blocked_at BIGINT NOT NULL,
    last_seen_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    block_count INTEGER DEFAULT 1,
    UNIQUE(ip, originating_server)
);

-- Create index for faster queries
CREATE INDEX IF NOT EXISTS idx_jailed_ips_expires ON jailed_ips(expires_at);
CREATE INDEX IF NOT EXISTS idx_jailed_ips_ip ON jailed_ips(ip);
CREATETABLES
    
    echo -e "${GREEN}✓${NC} Database and tables created"
}

# Database configuration wizard
configure_database() {
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}  DATABASE CONFIGURATION${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Bad IPs requires a PostgreSQL database for storing block information."
    echo ""

    # Load existing database config if it exists
    local EXISTING_DB_HOST="localhost"
    local EXISTING_DB_PORT="5432"
    local EXISTING_DB_NAME="bad_ips"
    local EXISTING_DB_USER="bad_ips"
    local EXISTING_DB_PASSWORD=""
    local HAVE_EXISTING_CONFIG=0

    if [ -f "$DB_CONF" ]; then
        echo -e "${CYAN}Found existing database configuration.${NC}"
        EXISTING_DB_HOST=$(awk '/^db_host/ {print $3}' "$DB_CONF" 2>/dev/null || echo "localhost")
        EXISTING_DB_PORT=$(awk '/^db_port/ {print $3}' "$DB_CONF" 2>/dev/null || echo "5432")
        EXISTING_DB_NAME=$(awk '/^db_name/ {print $3}' "$DB_CONF" 2>/dev/null || echo "bad_ips")
        EXISTING_DB_USER=$(awk '/^db_user/ {print $3}' "$DB_CONF" 2>/dev/null || echo "bad_ips")
        EXISTING_DB_PASSWORD=$(awk '/^db_password/ {print $3}' "$DB_CONF" 2>/dev/null)
        HAVE_EXISTING_CONFIG=1
        echo ""
    fi

    # Ask for database host with existing value as default
    read -p "Database hostname or IP address [$EXISTING_DB_HOST]: " DB_HOST
    DB_HOST=${DB_HOST:-$EXISTING_DB_HOST}
    
    # Check if localhost
    if [[ "$DB_HOST" == "localhost" ]] || [[ "$DB_HOST" == "127.0.0.1" ]]; then
        # Localhost scenario
        if ! is_postgresql_installed; then
            # PostgreSQL not installed
            echo ""
            echo "PostgreSQL is not installed on this system."
            echo ""
            read -p "Would you like to install PostgreSQL now? [Y/n]: " INSTALL_PG
            
            if [[ ! "$INSTALL_PG" =~ ^[Nn]$ ]]; then
                install_postgresql
                
                # Get database credentials
                read -p "Database username [$EXISTING_DB_USER]: " DB_USER
                DB_USER=${DB_USER:-$EXISTING_DB_USER}
                
                echo ""
                echo "A random password will be generated for the database user."
                DB_PASSWORD=$(generate_password)
                echo -e "${GREEN}Generated password: ${CYAN}$DB_PASSWORD${NC}"
                echo ""
                
                # Setup database
                setup_postgresql_database "$DB_USER" "$DB_PASSWORD"
                
                DB_PORT=5432
                DB_NAME="bad_ips"
            else
                echo ""
                echo -e "${YELLOW}Installation cancelled. Please install PostgreSQL manually and re-run this installer.${NC}"
                exit 0
            fi
        else
            # PostgreSQL is installed
            echo ""
            echo "PostgreSQL is already installed."
            echo ""

            read -p "Database username [$EXISTING_DB_USER]: " DB_USER
            DB_USER=${DB_USER:-$EXISTING_DB_USER}

            read -p "Database port [$EXISTING_DB_PORT]: " DB_PORT
            DB_PORT=${DB_PORT:-$EXISTING_DB_PORT}

            DB_NAME="$EXISTING_DB_NAME"
            
            # Try to connect
            echo ""

            # Ask about password if we have an existing one
            if [ $HAVE_EXISTING_CONFIG -eq 1 ] && [ -n "$EXISTING_DB_PASSWORD" ]; then
                read -p "Use existing saved password? [Y/n]: " USE_SAVED_PASSWORD
                if [[ "$USE_SAVED_PASSWORD" =~ ^[Nn]$ ]]; then
                    DB_PASSWORD=$(read_password "Enter new password for user '$DB_USER': ")
                else
                    DB_PASSWORD="$EXISTING_DB_PASSWORD"
                fi
            else
                DB_PASSWORD=$(read_password "Enter password for user '$DB_USER': ")
            fi

            echo ""
            echo "Testing connection to existing database..."

            if test_pg_connection "localhost" "$DB_PORT" "$DB_NAME" "$DB_USER" "$DB_PASSWORD"; then
                echo -e "${GREEN}✓${NC} Connection successful!"
                
                # Check if tables exist
                TABLE_COUNT=$(PGPASSWORD="$DB_PASSWORD" psql -h localhost -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'jailed_ips'" 2>/dev/null | tr -d ' ')
                
                if [[ "$TABLE_COUNT" == "0" ]]; then
                    echo ""
                    echo "Database exists but tables are missing. Creating tables..."
                    setup_postgresql_database "$DB_USER" "$DB_PASSWORD"
                fi
            else
                echo -e "${RED}✗${NC} Connection failed!"
                echo ""
                echo "Would you like to:"
                echo "  [1] Try different credentials"
                echo "  [2] Setup database with admin credentials"
                echo "  [3] Exit and configure manually"
                echo ""
                read -p "Select option [1-3]: " CONN_OPTION
                
                case $CONN_OPTION in
                    2)
                        echo ""
                        echo "Please provide PostgreSQL admin credentials to setup the database."
                        read -p "Admin username [postgres]: " ADMIN_USER
                        ADMIN_USER=${ADMIN_USER:-postgres}

                        ADMIN_PASSWORD=$(read_password "Admin password: ")

                        # Re-read DB_USER in case it wasn't set
                        if [ -z "$DB_USER" ]; then
                            read -p "Database username [$EXISTING_DB_USER]: " DB_USER
                            DB_USER=${DB_USER:-$EXISTING_DB_USER}
                        fi
                        
                        # Generate new password for bad_ips user
                        DB_PASSWORD=$(generate_password)
                        echo ""
                        echo -e "${GREEN}Generated password for '$DB_USER': ${CYAN}$DB_PASSWORD${NC}"
                        echo ""
                        
                        setup_postgresql_database "$DB_USER" "$DB_PASSWORD"
                        ;;
                    3)
                        echo ""
                        echo -e "${YELLOW}Installation cancelled.${NC}"
                        echo ""
                        echo "To configure manually:"
                        echo "  1. Create database and user in PostgreSQL"
                        echo "  2. Edit $DB_CONF with connection details"
                        echo "  3. Run: systemctl start bad_ips"
                        exit 0
                        ;;
                    *)
                        echo ""
                        echo "Please try running the installer again with correct credentials."
                        exit 1
                        ;;
                esac
            fi
        fi
    else
        # Remote database scenario
        echo ""
        echo "Configuring remote PostgreSQL database..."
        echo ""

        read -p "Database port [$EXISTING_DB_PORT]: " DB_PORT
        DB_PORT=${DB_PORT:-$EXISTING_DB_PORT}

        read -p "Database name [$EXISTING_DB_NAME]: " DB_NAME
        DB_NAME=${DB_NAME:-$EXISTING_DB_NAME}

        read -p "Database username [$EXISTING_DB_USER]: " DB_USER
        DB_USER=${DB_USER:-$EXISTING_DB_USER}

        # Ask about password if we have an existing one
        if [ $HAVE_EXISTING_CONFIG -eq 1 ] && [ -n "$EXISTING_DB_PASSWORD" ]; then
            read -p "Use existing saved password? [Y/n]: " USE_SAVED_PASSWORD
            if [[ "$USE_SAVED_PASSWORD" =~ ^[Nn]$ ]]; then
                DB_PASSWORD=$(read_password "Enter new database password: ")
            else
                DB_PASSWORD="$EXISTING_DB_PASSWORD"
            fi
        else
            DB_PASSWORD=$(read_password "Database password: ")
        fi

        echo ""
        if test_pg_connection_with_retry "$DB_HOST" "$DB_PORT" "$DB_NAME" "$DB_USER" "$DB_PASSWORD"; then
            # Check if tables exist
            TABLE_COUNT=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'jailed_ips'" 2>/dev/null | tr -d ' ')
            
            if [[ "$TABLE_COUNT" == "0" ]]; then
                echo ""
                echo -e "${YELLOW}Warning: Required tables do not exist in the database.${NC}"
                echo ""
                read -p "Would you like to create the tables automatically? [Y/n]: " CREATE_TABLES
                if [[ "$CREATE_TABLES" =~ ^[Nn]$ ]]; then
                    echo ""
                    echo "The 'jailed_ips' table needs to be created. You can create it with:"
                    echo ""
                    echo "  PGPASSWORD='yourpassword' psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME <<'SQL'"
                    echo "  CREATE TABLE IF NOT EXISTS jailed_ips ("
                    echo "      id SERIAL PRIMARY KEY,"
                    echo "      ip inet NOT NULL,"
                    echo "      originating_server VARCHAR(255) NOT NULL,"
                    echo "      originating_service VARCHAR(255),"
                    echo "      detector_name VARCHAR(255),"
                    echo "      pattern_matched TEXT,"
                    echo "      matched_log_line TEXT,"
                    echo "      first_blocked_at BIGINT NOT NULL,"
                    echo "      last_seen_at BIGINT NOT NULL,"
                    echo "      expires_at BIGINT NOT NULL,"
                    echo "      block_count INTEGER DEFAULT 1,"
                    echo "      UNIQUE(ip, originating_server)"
                    echo "  );"
                    echo "  CREATE INDEX IF NOT EXISTS idx_jailed_ips_expires ON jailed_ips(expires_at);"
                    echo "  CREATE INDEX IF NOT EXISTS idx_jailed_ips_ip ON jailed_ips(ip);"
                    echo "  SQL"
                    echo ""
                    echo "Note: This schema is for PostgreSQL. It may need modifications for other databases."
                else
                    echo ""
                    echo "Creating tables..."
                    local tmpout=$(mktemp)
                    if PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" > "$tmpout" 2>&1 <<'SQL'
CREATE TABLE IF NOT EXISTS jailed_ips (
    id SERIAL PRIMARY KEY,
    ip inet NOT NULL,
    originating_server VARCHAR(255) NOT NULL,
    originating_service VARCHAR(255),
    detector_name VARCHAR(255),
    pattern_matched TEXT,
    matched_log_line TEXT,
    first_blocked_at BIGINT NOT NULL,
    last_seen_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    block_count INTEGER DEFAULT 1,
    UNIQUE(ip, originating_server)
);
CREATE INDEX IF NOT EXISTS idx_jailed_ips_expires ON jailed_ips(expires_at);
CREATE INDEX IF NOT EXISTS idx_jailed_ips_ip ON jailed_ips(ip);
SQL
                    then
                        echo -e "${GREEN}✓${NC} Tables created successfully!"
                    else
                        echo -e "${RED}✗${NC} Failed to create tables"
                        echo ""
                        cat "$tmpout"
                        echo ""
                        echo -e "${YELLOW}Common issue: User lacks CREATE privileges on schema${NC}"
                        echo ""
                        echo "To fix, run as database admin (e.g., postgres user):"
                        echo ""
                        echo "  psql -h $DB_HOST -p $DB_PORT -d $DB_NAME -U postgres <<EOF"
                        echo "  GRANT CREATE ON SCHEMA public TO $DB_USER;"
                        echo "  EOF"
                        echo ""
                        echo "Then run the installer again, or create tables manually."
                        echo ""
                    fi
                    rm -f "$tmpout"
                fi
            fi
        fi
        # If connection failed, test_pg_connection_with_retry already handled retry/exit logic
    fi
    
    # Save database configuration
    echo ""
    echo -e "${BLUE}Saving database configuration...${NC}"
    mkdir -p "$(dirname "$DB_CONF")"
    chmod 750 "$(dirname "$DB_CONF")"
    chown root:"$BADIPS_GROUP" "$(dirname "$DB_CONF")"
    cat > "$DB_CONF" <<DBCONFEOF
# Bad IPs Database Configuration
# This file is automatically generated during installation
# Modify with caution - incorrect settings will prevent Bad IPs from starting

[global]
db_host = $DB_HOST
db_port = $DB_PORT
db_name = $DB_NAME
db_user = $DB_USER
db_password = $DB_PASSWORD
db_ssl_mode = disable
DBCONFEOF

    chmod 640 "$DB_CONF"
    chown root:"$BADIPS_GROUP" "$DB_CONF"
    echo -e "${GREEN}✓${NC} Database configuration saved to $DB_CONF"
}

# Detect running services
detect_services() {
    local detected=()
    
    # Check for common services
    systemctl is-active --quiet postfix.service 2>/dev/null && detected+=("postfix")
    systemctl is-active --quiet dovecot.service 2>/dev/null && detected+=("dovecot")
    systemctl is-active --quiet nginx.service 2>/dev/null && detected+=("nginx")
    systemctl is-active --quiet apache2.service 2>/dev/null && detected+=("apache2")
    systemctl is-active --quiet named.service 2>/dev/null && detected+=("named")
    systemctl is-active --quiet bind9.service 2>/dev/null && detected+=("named")
    systemctl is-active --quiet ssh.service 2>/dev/null && detected+=("ssh")
    systemctl is-active --quiet sshd.service 2>/dev/null && detected+=("ssh")
    
    echo "${detected[@]}"
}

# Configure service monitoring
configure_services() {
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}  SERVICE MONITORING${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    local detected_services=($(detect_services))
    
    if [[ ${#detected_services[@]} -eq 0 ]]; then
        echo "No monitorable services detected."
        echo ""
        echo "Available detectors:"
        echo "  - postfix - mail server"
        echo "  - dovecot - IMAP/POP3"
        echo "  - nginx - web server"
        echo "  - apache2 - web server"
        echo "  - named - DNS server"
        echo "  - ssh - SSH server"
        echo ""
        echo "You can manually enable detectors later in $CONFIG_DIR/badips.d/"
        return
    fi
    
    echo "Detected running services:"
    for svc in "${detected_services[@]}"; do
        echo -e "  ${GREEN}✓${NC} $svc"
    done
    echo ""
    
    echo "These services will be monitored for malicious activity."
    echo "Detectors can be configured in: $CONFIG_DIR/badips.d/"
    echo ""
    
    # All detected services are automatically monitored via the detector config files
    # No additional configuration needed - they're already in /usr/local/etc/badips.d/
}

# Configure never_block_cidrs
configure_never_block() {
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}  TRUSTED NETWORKS - CRITICAL${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Configure networks that should NEVER be blocked."
    echo "This prevents accidentally locking yourself out!"
    echo ""
    echo "You will be asked for both IPv4 and IPv6 trusted networks."
    echo ""

    # IPv4 Configuration
    echo -e "${CYAN}IPv4 Trusted Networks:${NC}"
    echo ""

    # Default safe CIDRs (RFC1918 + localhost + other non-routable)
    DEFAULT_CIDRS="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,169.254.0.0/16,224.0.0.0/4,240.0.0.0/4"

    # Check if badips.conf exists and read existing never_block_cidrs
    if [ -f "$BADIPS_CONF" ]; then
        EXISTING_CIDRS=$(awk '/^never_block_cidrs[[:space:]]*=/ {for(i=3; i<=NF; i++) printf "%s%s", $i, (i<NF ? " " : ""); print ""}' "$BADIPS_CONF" 2>/dev/null | tr -d ' \n\r')
        if [ -n "$EXISTING_CIDRS" ]; then
            DEFAULT_CIDRS="$EXISTING_CIDRS"
            echo -e "${CYAN}Found existing IPv4 trusted networks.${NC}"
            echo ""
        fi
    fi

    echo "Default IPv4 trusted networks (RFC1918 + non-routable):"
    echo "$DEFAULT_CIDRS" | tr ',' '\n' | sed 's/^/  /'
    echo ""

    # Try to detect current SSH connection IP
    if [[ -n "$SSH_CLIENT" ]]; then
        SSH_IP=$(echo "$SSH_CLIENT" | awk '{print $1}')
        if [[ "$SSH_IP" != *":"* ]]; then
            echo -e "${CYAN}Note: You are connected via SSH from: $SSH_IP${NC}"
            echo "Consider adding this IP to trusted networks!"
            echo ""
        fi
    fi

    read -p "Enter comma-separated IPv4 CIDRs to trust [$DEFAULT_CIDRS]: " USER_CIDRS
    NEVER_BLOCK_CIDRS=${USER_CIDRS:-$DEFAULT_CIDRS}

    # Sanitize input: remove newlines, extra spaces, and keep only valid characters
    NEVER_BLOCK_CIDRS=$(echo "$NEVER_BLOCK_CIDRS" | tr -d '\n\r' | tr -s ' ' | xargs)

    echo ""
    echo "IPv4 trusted networks configured:"
    echo "$NEVER_BLOCK_CIDRS" | tr ',' '\n' | sed 's/^/  /'

    # IPv6 Configuration
    echo ""
    echo -e "${CYAN}IPv6 Trusted Networks:${NC}"
    echo ""

    # Default IPv6 safe addresses
    DEFAULT_CIDRS_V6="::1/128,fe80::/10,fc00::/7,ff00::/8,::/128,2001:db8::/32"

    # Check if badips.conf exists and read existing never_block_cidrs_v6
    if [ -f "$BADIPS_CONF" ]; then
        EXISTING_CIDRS_V6=$(awk '/^never_block_cidrs_v6[[:space:]]*=/ {for(i=3; i<=NF; i++) printf "%s%s", $i, (i<NF ? " " : ""); print ""}' "$BADIPS_CONF" 2>/dev/null | tr -d ' \n\r')
        if [ -n "$EXISTING_CIDRS_V6" ]; then
            DEFAULT_CIDRS_V6="$EXISTING_CIDRS_V6"
            echo -e "${CYAN}Found existing IPv6 trusted networks.${NC}"
            echo ""
        fi
    fi

    echo "Default IPv6 trusted networks:"
    echo "  ::1/128       - IPv6 localhost"
    echo "  fe80::/10     - IPv6 link-local addresses"
    echo "  fc00::/7      - IPv6 unique local addresses (private)"
    echo "  ff00::/8      - IPv6 multicast"
    echo "  ::/128        - IPv6 unspecified address"
    echo "  2001:db8::/32 - IPv6 documentation/examples"
    echo ""

    # Try to detect current SSH connection IP (IPv6)
    if [[ -n "$SSH_CLIENT" ]]; then
        SSH_IP=$(echo "$SSH_CLIENT" | awk '{print $1}')
        if [[ "$SSH_IP" == *":"* ]]; then
            echo -e "${CYAN}Note: You are connected via SSH from: $SSH_IP${NC}"
            echo "Consider adding this IP to trusted networks!"
            echo ""
        fi
    fi

    read -p "Enter comma-separated IPv6 CIDRs to trust [$DEFAULT_CIDRS_V6]: " USER_CIDRS_V6
    NEVER_BLOCK_CIDRS_V6=${USER_CIDRS_V6:-$DEFAULT_CIDRS_V6}

    # Sanitize input: remove newlines, extra spaces, and keep only valid characters
    NEVER_BLOCK_CIDRS_V6=$(echo "$NEVER_BLOCK_CIDRS_V6" | tr -d '\n\r' | tr -s ' ' | xargs)

    echo ""
    echo "IPv6 trusted networks configured:"
    echo "$NEVER_BLOCK_CIDRS_V6" | tr ',' '\n' | sed 's/^/  /'
}

# Configure always_block_cidrs
configure_always_block() {
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}  ALWAYS BLOCK NETWORKS - OPTIONAL${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Configure networks that should ALWAYS be blocked."
    echo "These IPs/CIDRs will be permanently blocked at the firewall level."
    echo ""
    echo "Common use cases:"
    echo "  - Known bad actor networks"
    echo "  - Geographic blocking (e.g., countries you don't serve)"
    echo "  - Competitor reconnaissance IPs"
    echo "  - Cloud scanner networks"
    echo ""
    echo "Note: never_block takes precedence over always_block"
    echo ""
    echo "You will be asked for both IPv4 and IPv6 always-block networks."
    echo ""

    # IPv4 Configuration
    echo -e "${CYAN}IPv4 Always-Block Networks:${NC}"
    echo ""

    # Check if badips.conf exists and read existing always_block_cidrs
    DEFAULT_ALWAYS=""
    if [ -f "$BADIPS_CONF" ]; then
        EXISTING_ALWAYS=$(awk '/^always_block_cidrs[[:space:]]*=/ {for(i=3; i<=NF; i++) printf "%s%s", $i, (i<NF ? " " : ""); print ""}' "$BADIPS_CONF" 2>/dev/null | tr -d ' \n\r')
        if [ -n "$EXISTING_ALWAYS" ]; then
            DEFAULT_ALWAYS="$EXISTING_ALWAYS"
            echo -e "${CYAN}Found existing IPv4 always-block configuration:${NC}"
            echo "$DEFAULT_ALWAYS" | tr ',' '\n' | sed 's/^/  /'
            echo ""
        fi
    fi

    read -p "Enter comma-separated IPv4 CIDRs to always block (or press Enter to skip) [$DEFAULT_ALWAYS]: " USER_ALWAYS_CIDRS
    ALWAYS_BLOCK_CIDRS=${USER_ALWAYS_CIDRS:-$DEFAULT_ALWAYS}

    # Sanitize input: remove newlines, extra spaces, and keep only valid characters
    ALWAYS_BLOCK_CIDRS=$(echo "$ALWAYS_BLOCK_CIDRS" | tr -d '\n\r' | tr -s ' ' | xargs)

    if [[ -n "$ALWAYS_BLOCK_CIDRS" ]]; then
        echo ""
        echo "IPv4 always-block networks configured:"
        echo "$ALWAYS_BLOCK_CIDRS" | tr ',' '\n' | sed 's/^/  /'
    else
        echo ""
        echo -e "${CYAN}No IPv4 always-block networks configured${NC}"
    fi

    # IPv6 Configuration
    echo ""
    echo -e "${CYAN}IPv6 Always-Block Networks:${NC}"
    echo ""

    # Check if badips.conf exists and read existing always_block_cidrs_v6
    DEFAULT_ALWAYS_V6=""
    if [ -f "$BADIPS_CONF" ]; then
        EXISTING_ALWAYS_V6=$(awk '/^always_block_cidrs_v6[[:space:]]*=/ {for(i=3; i<=NF; i++) printf "%s%s", $i, (i<NF ? " " : ""); print ""}' "$BADIPS_CONF" 2>/dev/null | tr -d ' \n\r')
        if [ -n "$EXISTING_ALWAYS_V6" ]; then
            DEFAULT_ALWAYS_V6="$EXISTING_ALWAYS_V6"
            echo -e "${CYAN}Found existing IPv6 always-block configuration:${NC}"
            echo "$DEFAULT_ALWAYS_V6" | tr ',' '\n' | sed 's/^/  /'
            echo ""
        fi
    fi

    read -p "Enter comma-separated IPv6 CIDRs to always block (or press Enter to skip) [$DEFAULT_ALWAYS_V6]: " USER_ALWAYS_CIDRS_V6
    ALWAYS_BLOCK_CIDRS_V6=${USER_ALWAYS_CIDRS_V6:-$DEFAULT_ALWAYS_V6}

    # Sanitize input: remove newlines, extra spaces, and keep only valid characters
    ALWAYS_BLOCK_CIDRS_V6=$(echo "$ALWAYS_BLOCK_CIDRS_V6" | tr -d '\n\r' | tr -s ' ' | xargs)

    if [[ -n "$ALWAYS_BLOCK_CIDRS_V6" ]]; then
        echo ""
        echo "IPv6 always-block networks configured:"
        echo "$ALWAYS_BLOCK_CIDRS_V6" | tr ',' '\n' | sed 's/^/  /'
    else
        echo ""
        echo -e "${CYAN}No IPv6 always-block networks configured${NC}"
    fi
}

# Configure service user for privilege separation
configure_service_user() {
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}  SERVICE USER CONFIGURATION${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Bad IPs will run as a non-root user for security (privilege separation)."
    echo ""
    echo "The service user will have:"
    echo "  - No login shell (cannot login directly)"
    echo "  - Limited sudo access (only for nftables inet badips table)"
    echo "  - Access to journalctl and /var/log for monitoring"
    echo ""

    # Prompt for username
    read -p "Service username [badips]: " BADIPS_USER
    BADIPS_USER=${BADIPS_USER:-badips}

    # Validate username format
    if ! [[ "$BADIPS_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
        echo ""
        echo -e "${RED}Error: Invalid username format${NC}"
        echo "Username must:"
        echo "  - Start with a lowercase letter or underscore"
        echo "  - Contain only lowercase letters, numbers, underscores, or hyphens"
        echo ""
        exit 1
    fi

    # Confirm if using non-default username
    if [[ "$BADIPS_USER" != "badips" ]]; then
        echo ""
        echo -e "${YELLOW}⚠️  Using non-default username: $BADIPS_USER${NC}"
        read -p "Continue with username '$BADIPS_USER'? [Y/n]: " CONFIRM_USER
        if [[ "$CONFIRM_USER" =~ ^[Nn]$ ]]; then
            echo "Please run the installer again and choose a different username."
            exit 0
        fi
    fi

    BADIPS_GROUP="$BADIPS_USER"

    # Save to configuration file
    echo ""
    echo -e "${BLUE}Creating service user configuration...${NC}"
    cat > /etc/default/bad_ips <<EOF
# Bad IPs service user configuration
# This file is automatically generated during installation
# The bad_ips service will run as this user for security (privilege separation)

BADIPS_USER=$BADIPS_USER
BADIPS_GROUP=$BADIPS_GROUP
EOF
    chmod 644 /etc/default/bad_ips
    echo -e "${GREEN}✓${NC} Configuration saved to /etc/default/bad_ips"

    # Create user if doesn't exist
    if ! getent passwd "$BADIPS_USER" > /dev/null; then
        echo -e "${BLUE}Creating system user: $BADIPS_USER${NC}"
        if adduser --system --group --no-create-home \
            --home /nonexistent --shell /usr/sbin/nologin \
            "$BADIPS_USER" > /dev/null 2>&1; then
            echo -e "${GREEN}✓${NC} System user '$BADIPS_USER' created"
        else
            echo -e "${RED}✗${NC} Failed to create user '$BADIPS_USER'"
            echo "The package installation will attempt to create the user later."
        fi
    else
        echo -e "${GREEN}✓${NC} User '$BADIPS_USER' already exists"
    fi

    # Add to supplementary groups for log access
    echo -e "${BLUE}Configuring log access permissions...${NC}"

    # Add to systemd-journal group (for journalctl access)
    if getent group systemd-journal > /dev/null 2>&1; then
        if usermod -aG systemd-journal "$BADIPS_USER" > /dev/null 2>&1; then
            echo -e "${GREEN}✓${NC} Added to systemd-journal group (journalctl access)"
        else
            echo -e "${YELLOW}⚠${NC} Could not add to systemd-journal group (will be configured during package installation)"
        fi
    fi

    # Add to adm group (for /var/log access on Debian/Ubuntu)
    if getent group adm > /dev/null 2>&1; then
        if usermod -aG adm "$BADIPS_USER" > /dev/null 2>&1; then
            echo -e "${GREEN}✓${NC} Added to adm group (/var/log access)"
        else
            echo -e "${YELLOW}⚠${NC} Could not add to adm group (will be configured during package installation)"
        fi
    fi

    echo ""
    echo -e "${GREEN}✓${NC} Service user configuration complete"
    echo ""
    echo "Security notes:"
    echo "  - Service runs as: $BADIPS_USER (non-root)"
    echo "  - Limited sudo: Only nftables inet badips table operations"
    echo "  - Config files: Read-only access (root-owned)"
    echo "  - No login shell: Cannot be used for interactive login"
}

# Check if nftables package is installed
check_nftables_package() {
    if ! dpkg -l | grep -q "^ii  nftables"; then
        echo ""
        echo "═══════════════════════════════════════════════════════════"
        echo "  WARNING: nftables package is not installed"
        echo "═══════════════════════════════════════════════════════════"
        echo ""
        echo "Bad IPs requires nftables to block malicious IP addresses."
        echo ""
        read -p "Install nftables now? [Y/n]: " INSTALL_NFT
        if [[ ! "$INSTALL_NFT" =~ ^[Nn]$ ]]; then
            apt-get install -y nftables
            NFT_INSTALLED=1
        else
            echo ""
            echo "Bad IPs will be installed but will NOT be functional."
            echo "To install nftables later: sudo apt-get install nftables"
            NFT_INSTALLED=0
        fi
    else
        NFT_INSTALLED=1
    fi
}

# Check nftables service state
check_nftables_service() {
    local NFT_ENABLED=0
    local NFT_ACTIVE=0

    if systemctl is-enabled --quiet nftables.service 2>/dev/null; then
        NFT_ENABLED=1
    fi

    if systemctl is-active --quiet nftables.service 2>/dev/null; then
        NFT_ACTIVE=1
    fi

    if [ $NFT_ENABLED -eq 0 ] || [ $NFT_ACTIVE -eq 0 ]; then
        echo ""
        echo "═══════════════════════════════════════════════════════════"
        echo "  NOTICE: nftables service is not enabled/running"
        echo "═══════════════════════════════════════════════════════════"
        echo ""

        if [ $NFT_ENABLED -eq 0 ]; then
            echo "Status: nftables.service is DISABLED"
        fi
        if [ $NFT_ACTIVE -eq 0 ]; then
            echo "Status: nftables.service is NOT RUNNING"
        fi

        echo ""
        echo "Bad IPs installation will continue, but the service will be"
        echo "disabled until you enable and start nftables."
        echo ""
        echo "The bad_ips service will be installed but kept disabled."
        echo ""

        read -p "Continue with installation? [Y/n]: " CONTINUE
        if [[ "$CONTINUE" =~ ^[Nn]$ ]]; then
            echo "Installation cancelled."
            exit 0
        fi

        return 1  # nftables not ready
    fi

    return 0  # nftables ready
}

# Backup existing nftables configuration
backup_nftables_config() {
    local BACKUP_TIMESTAMP=$(date +%s)

    if [ -f /etc/nftables.conf ]; then
        echo "Backing up existing nftables configuration..."
        cp /etc/nftables.conf "/etc/nftables.conf.badips.bak.${BACKUP_TIMESTAMP}"
        echo -e "${GREEN}✓${NC} Backup saved: /etc/nftables.conf.badips.bak.${BACKUP_TIMESTAMP}"
    fi

    # Also backup the current ruleset
    nft list ruleset > "/etc/nftables.conf.runtime.bak.${BACKUP_TIMESTAMP}" 2>/dev/null || true
}

# Setup nftables include mechanism
setup_nftables_include() {
    # Create include directory
    mkdir -p /etc/nftables.d

    # Check if include statement exists in /etc/nftables.conf
    if [ -f /etc/nftables.conf ]; then
        if ! grep -q 'include "/etc/nftables.d/\*"' /etc/nftables.conf; then
            echo "" >> /etc/nftables.conf
            echo '# Bad IPs include directory' >> /etc/nftables.conf
            echo 'include "/etc/nftables.d/*"' >> /etc/nftables.conf
            echo -e "${GREEN}✓${NC} Added include statement to /etc/nftables.conf"
        else
            echo -e "${GREEN}✓${NC} Include statement already exists in /etc/nftables.conf"
        fi
    else
        # Create new nftables.conf with include
        cat > /etc/nftables.conf << 'EOF'
#!/usr/sbin/nft -f
# nftables configuration

# Flush ruleset
flush ruleset

# Include configuration files
include "/etc/nftables.d/*"
EOF
        echo -e "${GREEN}✓${NC} Created /etc/nftables.conf with include statement"
    fi
}

# Write Bad IPs nftables configuration file
write_badips_nftables_config() {
    cat > /etc/nftables.d/99-badips.nft <<'EOF'
#!/usr/sbin/nft -f

# ================================================================
# Bad IPs nftables configuration
# Managed automatically by bad_ips package
# Do NOT edit this file – it will be overwritten.
# Configure BadIPs in /usr/local/etc/badips.conf instead.
# ================================================================

table inet badips {

    set badipv4 {
        type ipv4_addr
        flags interval, timeout
        comment "Dynamically blocked IPv4 addresses"
    }

    set badipv6 {
        type ipv6_addr
        flags interval, timeout
        comment "Dynamically blocked IPv6 addresses"
    }

    set never_block {
        type ipv4_addr
        flags interval
        comment "IPv4 networks exempt from blocking"
    }

    set never_block_v6 {
        type ipv6_addr
        flags interval
        comment "IPv6 networks exempt from blocking"
    }

    set always_block {
        type ipv4_addr
        flags interval
        comment "Permanently blocked IPv4"
    }

    set always_block_v6 {
        type ipv6_addr
        flags interval
        comment "Permanently blocked IPv6"
    }

    chain preroute_block {
        type filter hook prerouting priority -150; policy accept;

        # IPv4
        ip saddr @never_block accept
        ip saddr @always_block counter drop
        ip saddr @badipv4 counter drop

        # IPv6
        ip6 saddr @never_block_v6 accept
        ip6 saddr @always_block_v6 counter drop
        ip6 saddr @badipv6 counter drop
    }
}
EOF

    chmod 644 /etc/nftables.d/99-badips.nft
    echo -e "${GREEN}✓${NC} Created /etc/nftables.d/99-badips.nft"
}

# Populate static nftables sets
populate_static_nftables_sets() {
    local NEVER_BLOCK_CIDRS="$1"
    local NEVER_BLOCK_CIDRS_V6="$2"
    local ALWAYS_BLOCK_CIDRS="$3"
    local ALWAYS_BLOCK_CIDRS_V6="$4"

    echo "Populating nftables sets..."

    # Populate IPv4 never_block set
    if [ -n "$NEVER_BLOCK_CIDRS" ]; then
        IFS=',' read -ra CIDRS <<< "$NEVER_BLOCK_CIDRS"
        for cidr in "${CIDRS[@]}"; do
            cidr=$(echo "$cidr" | xargs)  # trim whitespace
            nft add element inet badips never_block { "$cidr" } 2>/dev/null || true
        done
        echo -e "${GREEN}✓${NC} Populated never_block (IPv4) set with ${#CIDRS[@]} entries"
    fi

    # Populate IPv6 never_block set
    if [ -n "$NEVER_BLOCK_CIDRS_V6" ]; then
        IFS=',' read -ra CIDRS <<< "$NEVER_BLOCK_CIDRS_V6"
        for cidr in "${CIDRS[@]}"; do
            cidr=$(echo "$cidr" | xargs)
            nft add element inet badips never_block_v6 { "$cidr" } 2>/dev/null || true
        done
        echo -e "${GREEN}✓${NC} Populated never_block_v6 (IPv6) set with ${#CIDRS[@]} entries"
    fi

    # Populate IPv4 always_block set
    if [ -n "$ALWAYS_BLOCK_CIDRS" ]; then
        IFS=',' read -ra CIDRS <<< "$ALWAYS_BLOCK_CIDRS"
        for cidr in "${CIDRS[@]}"; do
            cidr=$(echo "$cidr" | xargs)
            nft add element inet badips always_block { "$cidr" } 2>/dev/null || true
        done
        echo -e "${GREEN}✓${NC} Populated always_block (IPv4) set with ${#CIDRS[@]} entries"
    fi

    # Populate IPv6 always_block set
    if [ -n "$ALWAYS_BLOCK_CIDRS_V6" ]; then
        IFS=',' read -ra CIDRS <<< "$ALWAYS_BLOCK_CIDRS_V6"
        for cidr in "${CIDRS[@]}"; do
            cidr=$(echo "$cidr" | xargs)
            nft add element inet badips always_block_v6 { "$cidr" } 2>/dev/null || true
        done
        echo -e "${GREEN}✓${NC} Populated always_block_v6 (IPv6) set with ${#CIDRS[@]} entries"
    fi
}

# Reload nftables
reload_nftables() {
    echo "Reloading nftables configuration..."

    # Test configuration first
    if nft -c -f /etc/nftables.conf; then
        # Reload the service
        if systemctl reload nftables.service; then
            echo -e "${GREEN}✓${NC} nftables configuration reloaded successfully"
            return 0
        else
            echo "ERROR: Failed to reload nftables service"
            echo "Your previous configuration is still active."
            return 1
        fi
    else
        echo "ERROR: nftables configuration validation failed"
        echo "Not applying changes. Your previous configuration is still active."
        return 1
    fi
}

# Setup nftables (main function)
setup_nftables() {
    echo ""
    echo -e "${BLUE}Setting up nftables firewall rules...${NC}"

    # Check if nftables is installed
    check_nftables_package

    # Check if nftables service is enabled/active
    if check_nftables_service; then
        NFT_READY=1
    else
        NFT_READY=0
    fi

    # Backup existing configuration
    backup_nftables_config

    # Setup include mechanism
    setup_nftables_include

    # Write Bad IPs configuration file
    write_badips_nftables_config

    # If nftables is ready, reload and populate sets
    if [ $NFT_READY -eq 1 ]; then
        reload_nftables

        # Populate static sets
        populate_static_nftables_sets "$NEVER_BLOCK_CIDRS" "$NEVER_BLOCK_CIDRS_V6" "$ALWAYS_BLOCK_CIDRS" "$ALWAYS_BLOCK_CIDRS_V6"
    else
        echo ""
        echo "Note: nftables service is not active - Bad IPs rules not loaded yet"
        echo "      Enable nftables to activate Bad IPs blocking"
    fi

    echo -e "${GREEN}✓${NC} nftables configured with inet badips table"
}

# Generate main badips.conf
generate_config() {
    echo ""
    echo -e "${BLUE}Generating main configuration...${NC}"
    
    cat > "$BADIPS_CONF" <<CONFEOF
# Bad IPs Configuration
# Generated during installation on $(date)

[global]
# Logging
log_level = info

# How long to block an IP (seconds)
block_duration = 691200  # 8 days

# Network filtering (IPv4)
never_block_cidrs = $NEVER_BLOCK_CIDRS
always_block_cidrs = $ALWAYS_BLOCK_CIDRS

# Network filtering (IPv6)
never_block_cidrs_v6 = $NEVER_BLOCK_CIDRS_V6
always_block_cidrs_v6 = $ALWAYS_BLOCK_CIDRS_V6

# Performance tuning
auto_mode = 1

# Cleanup intervals
cleanup_every_seconds = 3600

# Initial lookback -> how far to initally look back at journal
#                     Files are always read in entirety on initial loading
initial_journal_lookback = 86400

# Sleep time: number of seconds between looking at journalct or log files
sleep_time = 2

# central_db_batch_size: the max batch size to insert into central database of new IPs blocked
#    As new IPs are found, after they have been blocked, each IP is added to a queue (sync_to_central_db_queue)
#    Once the queue has at least central_db_batch_size in it, then that many IPs will be saved to the central database
#   The lower the number, the quicker IPs will be saved the the database and can then be used by other systems
#   The higher the number, the less frequent there are inserts to the database
#   See central_db_queue_timeout to see max wait time.
central_db_batch_size = 20

# central_db_queue_timeout: the timeout to wait for <central_db_batch_size> to be in sync_to_central_db_queue
#  After <central_db_queue_timeout> seconds, no matter how many IPs are in sync_to_central_db_queue, they will be removed and processed
#  The lower the numer, the faster a low count of items will be processed
#  The higher the number, the less stress on the database with low count inserts
central_db_queue_timeout = 5

# heartbeat (seconds):
#  How often to produce a log entry with some cursory info
heartbeat = 300

# graceful_shutdown_timeout (seconds):
#  How long to give each thread an opportunity to be cleared before bypassing the queue and shutting down
#  10 seconds is plenty of time for each thread
graceful_shutdown_timeout = 10

# Public Blocklist Plugin Configurations
# (optional) urls - Comma separated list of URLs to fetch the blocklist from
# (optional) fetch_interval - How often (in seconds) to fetch the blocklist
# (optional) use_cache - 1 to use caching, 0 to not use caching
# (optional) cache_path - Directory path to store cached files (if use_cache is 1)
# (required*) active - 1 to enable this blocklist plugin, 0 to disable it
# Each plugin MUST have
# * a unique name after PublicBlocklistPlugins:
# * at least active = 1 to be used; all other parameters are really at the use of the plugin
[PublicBlocklistPlugins:Spamhaus]
urls = https://www.spamhaus.org/drop/drop.txt, https://www.spamhaus.org/drop/edrop.txt
fetch_interval = 3600
use_cache = 1
cache_path = /var/cache/badips/
active = 1

[PublicBlocklistPlugins:Feodotracker]
urls = https://feodotracker.abuse.ch/downloads/ipblocklist.txt
fetch_interval = 7200
use_cache = 1
cache_path = /var/cache/badips/
active = 0

[PublicBlocklistPlugins:Blocklist_de]
urls = https://lists.blocklist.de/lists/all.txt
fetch_interval = 10800
use_cache = 1
cache_path = /var/cache/badips/
active = 0

[PublicBlocklistPlugins:DNSBL_Info]
urls = https://www.dnsbl.info/dnsbl-list.php?file=dnslist-ipv4.txt
fetch_interval = 14400
use_cache = 1
cache_path = /var/cache/badips/
active = 0

[PublicBlocklistPlugins:Malwaredomainlist]
urls = http://www.malwaredomainlist.com/hostslist/ip.txt
fetch_interval = 21600
use_cache = 1
cache_path = /var/cache/badips/
active = 0
CONFEOF

    chmod 640 "$BADIPS_CONF"
    chown root:"$BADIPS_GROUP" "$BADIPS_CONF"
    echo -e "${GREEN}✓${NC} Configuration saved to $BADIPS_CONF"
}

# Enable and start service
enable_service() {
    echo ""
    echo -e "${BLUE}Enabling and starting bad_ips service...${NC}"
    
    systemctl daemon-reload
    systemctl enable bad_ips.service > /dev/null 2>&1
    systemctl start bad_ips.service
    
    sleep 2
    
    if systemctl is-active --quiet bad_ips.service; then
        echo -e "${GREEN}✓${NC} Service is running"
    else
        echo -e "${YELLOW}⚠${NC} Service failed to start"
        echo ""
        echo "Check logs with: journalctl -u bad_ips.service -n 50"
    fi
}

# Show final status
show_status() {
    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  INSTALLATION COMPLETE${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Bad IPs is now monitoring your system and blocking malicious IPs."
    echo ""
    echo "Configuration:"
    echo "  Main config:     $BADIPS_CONF"
    echo "  Database config: $DB_CONF"
    echo "  Detectors:       $CONFIG_DIR/badips.d/"
    echo ""
    # Read database credentials for display
    local DISPLAY_DB_HOST=$(awk '/^db_host/ {print $3}' "$DB_CONF" 2>/dev/null || echo "localhost")
    local DISPLAY_DB_PORT=$(awk '/^db_port/ {print $3}' "$DB_CONF" 2>/dev/null || echo "5432")
    local DISPLAY_DB_NAME=$(awk '/^db_name/ {print $3}' "$DB_CONF" 2>/dev/null || echo "bad_ips")
    local DISPLAY_DB_USER=$(awk '/^db_user/ {print $3}' "$DB_CONF" 2>/dev/null || echo "bad_ips")
    local DISPLAY_DB_PASSWORD=$(awk '/^db_password/ {print $3}' "$DB_CONF" 2>/dev/null || echo "")

    echo "Useful commands:"
    echo "  Status:      systemctl status bad_ips.service"
    echo "  Logs:        journalctl -u bad_ips.service -f"
    echo "  Blocked IPs: sudo nft list set inet filter badipv4"
    echo "  Database:    PGPASSWORD=\"\$(awk '/db_password/ {print \$3}' $DB_CONF)\" psql -h \"\$(awk '/db_host/ {print \$3}' $DB_CONF)\" -p \"\$(awk '/db_port/ {print \$3}' $DB_CONF)\" -U \"\$(awk '/db_user/ {print \$3}' $DB_CONF)\" -d \"\$(awk '/db_name/ {print \$3}' $DB_CONF)\""
    echo "  Database:    PGPASSWORD=\"$DISPLAY_DB_PASSWORD\" psql -h \"$DISPLAY_DB_HOST\" -p \"$DISPLAY_DB_PORT\" -U \"$DISPLAY_DB_USER\" -d \"$DISPLAY_DB_NAME\""
    echo ""
    echo "Documentation: https://projects.thedude.vip/bad-ips/"
    echo "Support:       https://github.com/permittivity2/bad-ips/issues"
    echo ""
}

# Main installation flow
main() {
    print_logo
    
    echo -e "${BLUE}Bad IPs Installation v2.0${NC}"
    echo ""
    
    check_root
    detect_os
    check_nftables

    echo ""
    add_gpg_key
    add_repository
    update_apt

    # IMPORTANT: Configure service user BEFORE installing package
    # This ensures /etc/default/bad_ips exists when postinst runs
    configure_service_user

    install_badips

    configure_database
    configure_services
    configure_never_block
    configure_always_block

    generate_config
    setup_nftables
    enable_service
    
    show_status
}

# Run main
main
