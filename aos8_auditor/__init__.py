"""ArubaOS 8 controller security hardening auditor: read-only auditing, opt-in remediation.

The package is strictly layered so each piece is testable in isolation and the
future PSIRT/advisory module can reuse everything below the control engine:

    transport  -> collection -> parse/model -> engine -> scoring -> reporting

Golden rule: ``collection`` knows nothing about pass/fail, and ``engine`` knows
nothing about SSH. Nothing outside ``transport`` imports netmiko.
"""

__version__ = "1.0.0"
