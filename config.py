# Global configuration for NyxStrike

_config = {
    "APP_NAME": "NyxStrike",
    "VERSION": "1.4.0",
    "DATA_DIR_NAME": ".nyxstrike_data",  # Root data directory name (relative to cwd, override with VRIKA_DATA_DIR env var)
    "COMMAND_TIMEOUT": 1800,
    "REQUEST_TIMEOUT": 0,
    "COMMAND_INACTIVITY_TIMEOUT": 1800,
    "COMMAND_MAX_RUNTIME": 86400,
    "TOOL_TIMEOUT_OVERRIDES": {
        "hydra": 0,
        "hashcat": 0,
        "john": 0,
        "medusa": 0,
        "patator": 0,
        "ophcrack": 0,
        "wifite": 0,
        "wifite2": 0,
        "aircrack-ng": 0,
        "aircrack_ng": 0,
        "sqlmap": 1800,
        "nuclei": 1800,
        "autorecon": 1800,
        "amass": 1800,
        # Directory / content discovery often exceeds a low global COMMAND_TIMEOUT.
        "dirsearch": 1800,
        "gobuster": 1800,
        "ffuf": 1800,
        "feroxbuster": 1800,
        "wfuzz": 1800,
        "dirb": 1800,
        "dotdotpwn": 1800,
    },
    "CLEAN_TOOL_OUTPUT": True,
    "CPU_NICE_THRESHOLD": 85,  # CPU% above which tool commands are niced down (nice -n 10)
    "LLM_KEEP_ALIVE": 300,    # Legacy slot (unused); reserved for future HTTP keep-alive tuning
    "CACHE_SIZE": 1000,
    "CACHE_TTL": 3600,  # 1 hour
    "TOOL_AVAILABILITY_TTL": 3600,  # 1 hour
    "DEFAULT_API_SERVER_URL": "http://127.0.0.1:8888",
    "MAX_RETRIES": 3,
    "METASPLOIT_SESSION_WAIT": 10,  # Seconds to wait after exploit -j before listing sessions

    # ── LLM client ────────────────────────────────────────────────────────────
    "AI_MODE":                  "openrouter",                     # openrouter | ollama | lmstudio
    "OLLAMA_MODEL":             "gemma4:e2b",                     # model tag when AI_MODE=ollama
    "OLLAMA_URL":               "http://127.0.0.1:11434/v1",       # Ollama OpenAI-compatible base URL
    "LMSTUDIO_MODEL":           "",                                # empty = first loaded model in LM Studio
    "LMSTUDIO_URL":             "http://127.0.0.1:1234/v1",        # LM Studio local server base URL
    "VRIKA_LLM_PROVIDER": "openrouter",                     # openrouter | gemini | openai | anthropic | ollama | lmstudio
    "VRIKA_LLM_MODEL":    "openai/gpt-4.1-mini",          # OpenRouter model id (bare gemini-* names are auto-prefixed)
    "VRIKA_LLM_URL":      "https://openrouter.ai/api/v1",   # OpenRouter base URL (openrouter / openai providers)
    "VRIKA_LLM_API_KEY":  "",                               # or VRIKA_LLM_API_KEY / GOOGLE_API_KEY / OPENROUTER_API_KEY in env
    "VRIKA_LLM_TIMEOUT":  600,                              # seconds
    "VRIKA_LLM_MAX_LOOPS": 9,
    "VRIKA_LLM_THINK":    True,                             # OpenRouter reasoning API + Gemini thinkingConfig.includeThoughts
    "VRIKA_LLM_REASONING_MAX_TOKENS": 1000,                 # OpenRouter reasoning.max_tokens (Gemini thinking_budget); 0 = use enabled/effort
    "VRIKA_LLM_NUM_CTX":  8192,                             # hints max output tokens for Gemini; context sizing for other paths
    "VRIKA_LLM_NUM_CTX_ANALYSE": 16384,                     # analysis / report context hint

    # ── Chat widget ───────────────────────────────────────────────────────────
    "CHAT_PERSONALITY": "nyxstrike",  # active personality preset id (see server_core/intelligence/chat_personalities.py)
    "CHAT_SYSTEM_PROMPT": (
        "You are NyxStrike, an expert penetration testing AI assistant embedded in a "
        "security operations platform. You help operators understand scan results, plan "
        "attacks, interpret findings, and write reports. Be concise, technical, and actionable. "
        "When the user greets you casually or makes small talk, respond naturally and warmly — "
        "you are a teammate, not a robot. Match the tone of the conversation."
    ),
    "CHAT_CUSTOM_PROMPT": "",  # saved custom system prompt (used when CHAT_PERSONALITY == "custom")
    "CHAT_SUMMARIZATION_THRESHOLD": 20,   # non-summarized messages before rolling summary kicks in
    "CHAT_CONTEXT_INJECTION_CHARS": 4000, # max chars of session scan output injected as context

    "WORD_LISTS": {

        # --- Password Lists ---
        "rockyou": {
            "path": "/usr/share/wordlists/rockyou.txt",
            "type": "password",
            "description": "Common password list for brute-force attacks",
            "recommended_for": ["password_cracking", "login_fuzzing"],
            "size": 14344392,
            "tool": ["john", "hydra"],
            "speed": "slow",
            "language": "en",
            "coverage": "broad",
            "format": "txt"
        },
        "john": {
            "path": "/usr/share/wordlists/john.lst",
            "type": "password",
            "description": "John the Ripper password list",
            "recommended_for": ["password_cracking", "john"],
            "size": 3559,
            "tool": ["john"],
            "speed": "fast",
            "language": "en",
            "coverage": "focused",
            "format": "lst"
        },

        # --- Directory Lists ---
        "common_dirb": {
            "path": "/usr/share/wordlists/dirb/common.txt",
            "type": "directory",
            "description": "Common directory names for web discovery",
            "recommended_for": ["dirbusting", "web_content_discovery"],
            "size": 4614,
            "tool": ["dirb"],
            "speed": "medium",
            "language": "en",
            "coverage": "broad",
            "format": "txt"
        },
        "big_dirb": {
            "path": "/usr/share/wordlists/dirb/big.txt",
            "type": "directory",
            "description": "Large directory wordlist for web discovery",
            "recommended_for": ["dirbusting"],
            "size": 20469,
            "tool": ["dirb"],
            "speed": "slow",
            "language": "en",
            "coverage": "broad",
            "format": "txt"
        },
        "small_dirb": {
            "path": "/usr/share/wordlists/dirb/small.txt",
            "type": "directory",
            "description": "Small directory wordlist for quick scans",
            "recommended_for": ["dirbusting"],
            "size": 959,
            "tool": ["dirb"],
            "speed": "fast",
            "language": "en",
            "coverage": "focused",
            "format": "txt"
        },
        "common_dirsearch": {
            "path": "/usr/share/wordlists/dirsearch/common.txt",
            "type": "directory",
            "description": "Common directory names for Dirsearch",
            "recommended_for": ["dirsearch", "web_content_discovery"],
            "size": 2205,
            "tool": ["dirsearch"],
            "speed": "medium",
            "language": "en",
            "coverage": "focused",
            "format": "txt"
        }
    }
}

