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

TARGET=$1
# Check for the -sub flag
if [ "$2" == "-sub" ]; then
    SUBDOMAIN_ENUM=true


echo -e "${CYAN}${BOLD}\n[+] Processing domain: $TARGET${NC}"


# Perform subdomain enumeration if -sub flag is set
if $SUBDOMAIN_ENUM; then
    echo -e "${YELLOW}[+] Running passive subdomain enumeration...${NC}"
    amass enum -active -d $TARGET -o amassoutput.txt > /dev/null 2>&1 &
    subfinder -d $TARGET -o subfinder.txt > /dev/null 2>&1 &
    sublist3r -d $TARGET -o sublist3r.txt > /dev/null 2>&1 &
    # Wait for all passive enumeration tools to finish
    wait

    # Merge and sort results
    cat amassoutput.txt | grep "(FQDN)" | awk '{print $1}' >> amass.txt
    cat amass.txt subfinder.txt sublist3r.txt | sort -u >> domains.txt
    rm amass.txt subfinder.txt sublist3r.txt
    echo -e "${GREEN}[+] Passive subdomain enumeration completed. Results saved to domains.txt${NC}"

    # Filter live domains
    echo -e "${YELLOW}[+] Filtering live domains...${NC}"
    cat domains.txt | httpx -silent -o domain.live > /dev/null 2>&1
    rm domains.txt
    echo -e "${GREEN}[+] Live domains filtered. Results saved to domain.live${NC}"

    # Perform active subdomain enumeration
    echo -e "${YELLOW}[+] Running active subdomain enumeration...${NC}"
    ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u "https://FUZZ.$TARGET" -c -t 50 -mc all -fs 0 >> ffuf.txt
    # Merge all subdomains
    cat domain.live ffuf.txt | sort -u >> domains
    rm domain.live
    echo -e "${GREEN}[+] Active subdomain enumeration completed. Results saved to domains${NC}"
else
    # If -sub flag is not set, skip subdomain enumeration
    echo -e "${YELLOW}[+] Skipping subdomain enumeration as -sub flag is not set.${NC}"
    echo "$TARGET" > domains  # Use the main domain directly
fi

# Step 3: URL Discovery and Crawling
echo -e "${YELLOW}[+] Running URL discovery and crawling...${NC}"
cat domains | waybackurls >> wayback.txt & 
katana -list domains -o katana.txt > /dev/null 2>&1 &
cat domains | waymore >> waymore.txt &

# Wait for all URL discovery tools to finish
wait

# Merge all URL results and remove duplicates
cat wayback.txt katana.txt waymore.txt | sort -u | uro >> urls.txt
rm  wayback.txt katana.txt waymore.txt 
echo -e "${GREEN}[+] URL discovery and crawling completed. Results saved to urls.txt${NC}"

echo -e "${MAGENTA}${BOLD}[+] Done processing domain: $TARGET."
