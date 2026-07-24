#!/usr/bin/env bash
set -e

# Colors
GREEN="\033[0;32m"
CYAN="\033[0;36m"
YELLOW="\033[1;33m"
RESET="\033[0m"

echo -e "${CYAN}🐳 Preparing to build the Rulezet container image...${RESET}"

# The Dockerfile does `COPY . .`, so submodules must be checked out on the
# host before building — an uninitialised or stale submodule would silently
# ship an empty (or outdated) directory into the image.
echo -e "${CYAN}📂 Checking git submodules...${RESET}"

sync_submodule() {
    local path="$1"
    local status
    status=$(git submodule status -- "$path" 2>/dev/null)
    if [ -z "$status" ]; then
        echo -e "${YELLOW}⚠ Submodule ${path} not found, skipping.${RESET}"
        return
    fi
    case "${status:0:1}" in
        -)
            echo -e "${CYAN}Initialising ${path}...${RESET}"
            git submodule update --init --recursive "$path"
            echo -e "${GREEN}✔ ${path} initialised.${RESET}"
            ;;
        +)
            echo -e "${CYAN}${path} is out of sync with the pinned commit, updating...${RESET}"
            git submodule update --remote "$path"
            echo -e "${GREEN}✔ ${path} updated.${RESET}"
            ;;
        *)
            echo -e "${GREEN}✔ ${path} up to date.${RESET}"
            ;;
    esac
}

sync_submodule app/modules/rulezet-cast
sync_submodule app/modules/pivotick
sync_submodule app/modules/misp-taxonomies
sync_submodule app/modules/misp-galaxy

# CTI submodule (mitre/cti) — large repo, only clone if not already present.
# Once present, keep it shallow and only re-sync if the pinned commit moved.
if [ ! -f "app/modules/cti/enterprise-attack/enterprise-attack.json" ]; then
    echo -e "${CYAN}🛡️  Cloning MITRE ATT&CK CTI data (shallow, may take a moment)...${RESET}"
    git submodule update --init --depth 1 app/modules/cti
    echo -e "${GREEN}✔ MITRE CTI submodule initialised.${RESET}"
else
    cti_status=$(git submodule status -- app/modules/cti 2>/dev/null)
    if [ "${cti_status:0:1}" = "+" ]; then
        echo -e "${CYAN}app/modules/cti is out of sync with the pinned commit, updating...${RESET}"
        git submodule update --remote --depth 1 app/modules/cti
    fi
    echo -e "${GREEN}✔ MITRE CTI submodule already present.${RESET}"
fi

echo -e "${CYAN}🔨 Building the container image...${RESET}"
if docker compose version >/dev/null 2>&1; then
    docker compose build "$@"
else
    docker build -t rulezet-core "$@" .
fi

echo -e "${GREEN}✅ Build complete.${RESET}"
