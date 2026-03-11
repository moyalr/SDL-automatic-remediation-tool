"""Scanner integrations for BlackDuck and Twistlock."""

from security_remediation.scanners.blackduck import BlackDuckScanner
from security_remediation.scanners.twistlock import TwistlockScanner

__all__ = ["BlackDuckScanner", "TwistlockScanner"]
