"""Viral onboarding endpoint: curl domain/new | sh (VIRAL-01, VIRAL-02, VIRAL-03)."""

from __future__ import annotations

import textwrap

from fastapi import APIRouter, Request
from starlette.responses import PlainTextResponse, RedirectResponse


router = APIRouter()


def _is_cli_client(user_agent: str) -> bool:
    """Return True if the User-Agent looks like a CLI HTTP client.

    Matches curl, wget, HTTPie, fetch, and PowerShell -- the tools people
    use when they run ``curl domain/new | sh``.  Returns False for empty
    strings or browser-like User-Agents.
    """
    if not user_agent:
        return False
    ua_lower = user_agent.lower()
    return any(
        tok in ua_lower
        for tok in ("curl", "wget", "httpie", "fetch", "powershell")
    )


@router.get("/new")
async def viral_new(request: Request):
    """GET /new -- User-Agent detection (VIRAL-01).

    * CLI clients (curl/wget) receive a thin POSIX sh wrapper that downloads
      the full installer to a temp file before executing it.
    * Browsers receive a 302 redirect to the website's /reserve page.
    """
    settings = request.app.state.settings
    user_agent = request.headers.get("user-agent", "")

    if _is_cli_client(user_agent):
        relay_domain = settings.relay_domain
        relay_http_url = settings.relay_http_url

        wrapper = textwrap.dedent(f"""\
            #!/bin/sh
            # UAM Quick Setup -- {relay_domain}
            # This thin wrapper downloads the full installer to prevent partial-download issues.
            set -e
            INSTALLER="$(mktemp)"
            trap 'rm -f "$INSTALLER"' EXIT
            curl -fsSL "{relay_http_url}/new/install.sh" -o "$INSTALLER"
            sh "$INSTALLER"
        """)

        return PlainTextResponse(wrapper, media_type="text/plain")

    return RedirectResponse(
        url=f"{settings.website_url}/reserve", status_code=302
    )


@router.get("/new/install.sh")
async def viral_installer(request: Request):
    """GET /new/install.sh -- Full interactive installer (VIRAL-02, VIRAL-03).

    Returns a POSIX sh script that walks the user through picking an agent
    name, checking availability, creating a reservation, downloading the
    vCard, and running ``uam init --claim``.  The script is auto-branded
    per relay -- domain, relay URL, and signup URL are substituted from
    the relay config with no hardcoded values.
    """
    settings = request.app.state.settings
    relay_domain = settings.relay_domain
    relay_http_url = settings.relay_http_url

    installer = textwrap.dedent(f"""\
        #!/bin/sh
        # UAM Installer -- {relay_domain}
        # Full interactive setup: pick a name, reserve it, claim it.
        # Strict POSIX sh -- no bashisms.
        set -e

        # -----------------------------------------------------------------
        # Banner
        # -----------------------------------------------------------------
        printf "\\n"
        printf "  ===================================\\n"
        printf "  UAM Quick Setup -- %s\\n" "{relay_domain}"
        printf "  ===================================\\n"
        printf "\\n"
        printf "  This script will:\\n"
        printf "    1. Install the UAM CLI (if needed)\\n"
        printf "    2. Let you pick an agent name\\n"
        printf "    3. Reserve it and download your identity card\\n"
        printf "    4. Claim your address so you can send messages\\n"
        printf "\\n"

        # -----------------------------------------------------------------
        # Prerequisites
        # -----------------------------------------------------------------
        if ! command -v curl >/dev/null 2>&1; then
            printf "ERROR: curl is required but not found.\\n"
            printf "Install curl and try again.\\n"
            exit 1
        fi

        if ! command -v python3 >/dev/null 2>&1; then
            printf "ERROR: python3 is required but not found.\\n"
            printf "Install Python 3.8+ first: https://python.org\\n"
            exit 1
        fi

        PIP_CMD=""
        if command -v pip3 >/dev/null 2>&1; then
            PIP_CMD="pip3"
        elif python3 -m pip --version >/dev/null 2>&1; then
            PIP_CMD="python3 -m pip"
        else
            printf "ERROR: pip is required but not found.\\n"
            printf "Install pip: https://pip.pypa.io/en/stable/installation/\\n"
            exit 1
        fi

        # -----------------------------------------------------------------
        # Install UAM CLI if missing
        # -----------------------------------------------------------------
        if ! command -v uam >/dev/null 2>&1; then
            printf "  Installing UAM CLI...\\n"
            $PIP_CMD install uam >/dev/null 2>&1 || true
            if ! command -v uam >/dev/null 2>&1; then
                printf "ERROR: Failed to install UAM CLI.\\n"
                printf "Try manually: pip3 install uam\\n"
                exit 1
            fi
            printf "  UAM CLI installed.\\n"
        else
            printf "  UAM CLI already installed.\\n"
        fi

        # -----------------------------------------------------------------
        # Interactive name selection
        # -----------------------------------------------------------------
        printf "\\n"
        printf "  Choose a name for your agent:\\n"
        printf "  (lowercase letters, numbers, hyphens -- e.g. scout, agent-7)\\n"
        printf "\\n"

        while true; do
            printf "  Name: "
            read agent_name

            # Validate non-empty
            if [ -z "$agent_name" ]; then
                printf "  Name cannot be empty. Try again.\\n"
                continue
            fi

            # Check availability via relay API
            check_url="{relay_http_url}/api/v1/reserve/check/$agent_name"
            response="$(curl -fsSL "$check_url" 2>/dev/null)" || {{
                printf "  ERROR: Could not reach the relay to check availability.\\n"
                exit 1
            }}

            available="$(printf "%s" "$response" | grep -o '"available":[a-z]*' | grep -o 'true\\|false')"

            if [ "$available" = "true" ]; then
                printf "  '%s' is available!\\n\\n" "$agent_name"
                break
            elif [ "$available" = "false" ]; then
                printf "  '%s' is taken. Try another name.\\n" "$agent_name"
            else
                printf "  ERROR: Unexpected response from relay.\\n"
                exit 1
            fi
        done

        # -----------------------------------------------------------------
        # Create reservation
        # -----------------------------------------------------------------
        printf "  Reserving %s...\\n" "$agent_name"
        reserve_url="{relay_http_url}/api/v1/reserve"
        reserve_response="$(curl -fsSL -X POST \\
            -H "Content-Type: application/json" \\
            -d "{{\\"name\\": \\"$agent_name\\"}}" \\
            "$reserve_url" 2>/dev/null)" || {{
            printf "  ERROR: Reservation failed. Try again later.\\n"
            exit 1
        }}

        claim_token="$(printf "%s" "$reserve_response" | grep -o '"claim_token":"[^"]*"' | cut -d'"' -f4)"
        vcf_url="$(printf "%s" "$reserve_response" | grep -o '"vcf_url":"[^"]*"' | cut -d'"' -f4)"

        if [ -z "$claim_token" ]; then
            printf "  ERROR: Could not get claim token from reservation response.\\n"
            printf "  Response: %s\\n" "$reserve_response"
            exit 1
        fi

        printf "  Reserved!\\n"

        # -----------------------------------------------------------------
        # Download vCard
        # -----------------------------------------------------------------
        printf "  Downloading reservation card...\\n"
        curl -fsSL "$vcf_url" -o "$agent_name.vcf" 2>/dev/null || {{
            printf "  ERROR: Failed to download reservation card.\\n"
            exit 1
        }}

        if [ ! -s "$agent_name.vcf" ]; then
            printf "  ERROR: Downloaded card is empty.\\n"
            exit 1
        fi

        printf "  Card saved: %s.vcf\\n" "$agent_name"

        # -----------------------------------------------------------------
        # Claim address
        # -----------------------------------------------------------------
        printf "  Claiming your address...\\n"
        if ! uam init --claim "$agent_name.vcf"; then
            printf "  ERROR: Claim failed. You can retry with:\\n"
            printf "    uam init --claim %s.vcf\\n" "$agent_name"
            exit 1
        fi

        # -----------------------------------------------------------------
        # Success
        # -----------------------------------------------------------------
        printf "\\n"
        printf "  ===================================\\n"
        printf "  Setup complete!\\n"
        printf "  ===================================\\n"
        printf "\\n"
        printf "  Your agent address: %s::%s\\n" "$agent_name" "{relay_domain}"
        printf "  Identity card saved -- share it to spread the word!\\n"
        printf "\\n"
        printf "  Get started:\\n"
        printf "    uam send hello::{relay_domain} 'Hello from %s!'\\n" "$agent_name"
        printf "\\n"
    """)

    return PlainTextResponse(installer, media_type="text/plain")
