#!/bin/bash

# Define colors and styles
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'
UNDERLINE='\033[4m'

# Custom banner
echo -e "${CYAN}${BOLD}"
echo "                                                    "
echo "                _        _____                      "
echo "     /\        | |      |  __ \                     "
echo "    /  \  _   _| |_ ___ | |__) |___  ___ ___  _ __  "
echo "   / /\ \| | | | __/ _ \|  _  // _ \/ __/ _ \| '_ \ "
echo "  / ____ \ |_| | || (_) | | \ \  __/ (_| (_) | | | |"
echo " /_/    \_\__,_|\__\___/|_|  \_\___|\___\___/|_| |_|"
echo -e "${NC}"
echo -e "${YELLOW}${BOLD}By: omar samy${NC}"
echo -e "${BLUE}${BOLD}Twitter: @omarsamy10${NC}"
echo -e "===================================================\n"

# Check if the correct number of arguments is provided
if [ "$#" -lt 2 ]; then
    echo -e "${RED}${BOLD}Usage: $0 <target> <output_directory> [-sub]${NC}"
    exit 1
fi

TARGET=$1
OUTPUT_DIR=$2
SUBDOMAIN_ENUM=false

# Check for the -sub flag
if [ "$3" == "-sub" ]; then
    SUBDOMAIN_ENUM=true
fi

echo -e "${CYAN}${BOLD}\n[+] Processing domain: $TARGET${NC}"
echo -e "${CYAN}${BOLD}[+] Output directory: $OUTPUT_DIR${NC}"

# Perform subdomain enumeration if -sub flag is set
if $SUBDOMAIN_ENUM; then
    echo -e "${YELLOW}[+] Running passive subdomain enumeration...${NC}"
    amass enum -active -d $TARGET -o "$OUTPUT_DIR/amassoutput.txt" > /dev/null 2>&1 &
    subfinder -d $TARGET -o "$OUTPUT_DIR/subfinder.txt" > /dev/null 2>&1 &
    sublist3r -d $TARGET -o "$OUTPUT_DIR/sublist3r.txt" > /dev/null 2>&1 &
    # Wait for all passive enumeration tools to finish
    wait

    # Merge and sort results
    cat "$OUTPUT_DIR/amassoutput.txt" | grep "(FQDN)" | awk '{print $1}' >> "$OUTPUT_DIR/amass.txt"
    cat "$OUTPUT_DIR/amass.txt" "$OUTPUT_DIR/subfinder.txt" "$OUTPUT_DIR/sublist3r.txt" | sort -u >> "$OUTPUT_DIR/domains.txt"
    rm "$OUTPUT_DIR/amass.txt" "$OUTPUT_DIR/subfinder.txt" "$OUTPUT_DIR/sublist3r.txt"
    echo -e "${GREEN}[+] Passive subdomain enumeration completed. Results saved to $OUTPUT_DIR/domains.txt${NC}"

    # Filter live domains
    echo -e "${YELLOW}[+] Filtering live domains...${NC}"
    cat "$OUTPUT_DIR/domains.txt" | httpx -silent -o "$OUTPUT_DIR/domain.live" > /dev/null 2>&1
    rm "$OUTPUT_DIR/domains.txt"
    echo -e "${GREEN}[+] Live domains filtered. Results saved to $OUTPUT_DIR/domain.live${NC}"

    # Perform active subdomain enumeration
    echo -e "${YELLOW}[+] Running active subdomain enumeration...${NC}"
    ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u "https://FUZZ.$TARGET" -c -t 50 -mc all -fs 0 >> "$OUTPUT_DIR/ffuf.txt"
    # Merge all subdomains
    cat "$OUTPUT_DIR/domain.live" "$OUTPUT_DIR/ffuf.txt" | sort -u > "$OUTPUT_DIR/domains"
    rm "$OUTPUT_DIR/domain.live"
    echo -e "${GREEN}[+] Active subdomain enumeration completed. Results saved to $OUTPUT_DIR/domains${NC}"
else
    # If -sub flag is not set, skip subdomain enumeration
    echo -e "${YELLOW}[+] Skipping subdomain enumeration as -sub flag is not set.${NC}"
    echo "$TARGET" > "$OUTPUT_DIR/domains"  # Use the main domain directly
fi

# Step 3: URL Discovery and Crawling
echo -e "${YELLOW}[+] Running URL discovery and crawling...${NC}"
cat "$OUTPUT_DIR/domains" | waybackurls >> "$OUTPUT_DIR/wayback.txt" & 
katana -list "$OUTPUT_DIR/domains" -o "$OUTPUT_DIR/katana.txt" > /dev/null 2>&1 &
cat "$OUTPUT_DIR/domains" | waymore >> "$OUTPUT_DIR/waymore.txt" &

# Wait for all URL discovery tools to finish
wait

# Merge all URL results and remove duplicates
cat "$OUTPUT_DIR/wayback.txt" "$OUTPUT_DIR/katana.txt" "$OUTPUT_DIR/waymore.txt" | sort -u | uro >> "$OUTPUT_DIR/urls.txt"
rm "$OUTPUT_DIR/wayback.txt" "$OUTPUT_DIR/katana.txt" "$OUTPUT_DIR/waymore.txt"
echo -e "${GREEN}[+] URL discovery and crawling completed. Results saved to $OUTPUT_DIR/urls.txt${NC}"

echo -e "${MAGENTA}${BOLD}[+] Done processing domain: $TARGET.${NC}"