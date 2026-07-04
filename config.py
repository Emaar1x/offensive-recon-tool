"""
config.py - Shared settings for all modules.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

DEFAULT_TIMEOUT = 10
