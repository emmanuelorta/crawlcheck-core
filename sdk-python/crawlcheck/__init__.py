"""CrawlCheck: resolve a domain, decide an agent action, verify the evidence. https://crawlcheck.io/docs/api"""
from .client import CrawlCheck, CrawlCheckError, VERSION, ACTIONS, RECEIPT_HEADER, normalize_domain, receipt_header, tool_operation, check_decision, ACTION_MAX_LIFETIME_S, MAX_CLOCK_SKEW_S
from .verify import verify_document, canon, key_id, KEY_POLICY, key_policy_from, key_policy_check, apply_key_policy
from .lock import lock_tool_hash, lock_from_tools, check_lock
from .staple import parse_staple, staple_check, staple_from_headers
from .mcp import McpPreflight, McpPreflightRefused, with_preflight
from .revocations import new_revocation_store, apply_revocations, revoked_for
from .tools import agent_tools, tools_for
from .log import new_log_store, log_observe, log_observe_answer, log_heads, log_gossip, log_check, verify_witness_token

__version__ = VERSION
__all__ = ["CrawlCheck", "CrawlCheckError", "verify_document", "canon", "key_id", "KEY_POLICY", "key_policy_from", "key_policy_check", "apply_key_policy", "ACTIONS", "RECEIPT_HEADER", "normalize_domain", "receipt_header", "check_decision", "tool_operation", "ACTION_MAX_LIFETIME_S", "MAX_CLOCK_SKEW_S", "lock_tool_hash", "lock_from_tools", "check_lock", "new_log_store", "log_observe", "log_observe_answer", "log_heads", "log_gossip", "log_check", "verify_witness_token", "parse_staple", "staple_check", "staple_from_headers", "new_revocation_store", "apply_revocations", "revoked_for", "McpPreflight", "McpPreflightRefused", "with_preflight", "agent_tools", "tools_for", "__version__"]
