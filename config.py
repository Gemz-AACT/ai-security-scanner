# AI Security Scanner Configuration

# Default API settings
DEFAULT_TIMEOUT = 30  # seconds to wait for API response
DEFAULT_MODEL = "llama-3.1-8b-instant"
DEFAULT_API_URL = "https://api.groq.com/openai/v1/chat/completions"

# Vulnerability detection sensitivity
# Higher = more sensitive but more false positives
SENSITIVITY = "medium"  # low, medium, high

# Report settings
REPORT_OUTPUT_DIR = "reports/"
GENERATE_PDF = True
GENERATE_JSON = True

# Scanner info
SCANNER_NAME = "AI Model Security Scanner"
SCANNER_VERSION = "2.00"
SCANNER_AUTHOR = "Maryssa L | github.com/Gemz-AACT"