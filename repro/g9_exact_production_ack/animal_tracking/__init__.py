"""Bounded public bootstrap for exact Generation-9 acknowledgement validation."""

from animal_tracking._acl_owner_compatibility_fix import (
    install_acl_owner_compatibility_fix,
)
from animal_tracking._security_event_ack_guard import (
    install_security_event_acknowledgement_guard,
)
from animal_tracking._windows_acl_guard import install_windows_acl_guard

__version__ = "0.1.0.dev2"

install_acl_owner_compatibility_fix()
install_windows_acl_guard()
install_security_event_acknowledgement_guard()
del install_acl_owner_compatibility_fix
del install_security_event_acknowledgement_guard
del install_windows_acl_guard
