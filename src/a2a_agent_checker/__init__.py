"""Check an A2A Agent Card against the v1.0 specification."""
from .card import Finding, validate
from .check import Report, check

__all__ = ["Finding", "Report", "check", "validate"]
__version__ = "0.1.0"
