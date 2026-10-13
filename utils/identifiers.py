WEAKNESS_ID_PATTERN = r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$"
PAYLOAD_FAMILY_KEY_PATTERN = r"^[a-z][a-z0-9]*\.[a-z_]+$"
RELATION_EVENT_ID_PATTERN = (
    r"^REL-EVT-[0-9a-f]{8}-[0-9a-f]{4}-"
    r"[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
RELATION_PROPOSAL_ID_PATTERN = (
    r"^REL-PROP-[0-9a-f]{8}-[0-9a-f]{4}-"
    r"[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
PAYLOAD_EVENT_ID_PATTERN = (
    r"^PAY-EVT-[0-9a-f]{8}-[0-9a-f]{4}-"
    r"[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
PAYLOAD_PROPOSAL_ID_PATTERN = (
    r"^PAY-PROP-[0-9a-f]{8}-[0-9a-f]{4}-"
    r"[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)