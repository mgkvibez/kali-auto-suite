"""kaliauto: orchestrate authorized, non-destructive reconnaissance.

Three rules the code enforces rather than documents:

1. Nothing runs without a scope file that names who authorized it.
2. Nothing touches the network without --execute; the default is a plan.
3. Every attempt, including every refusal, lands in an append-only audit log.
"""

__version__ = "0.1.0"
CHECKSET = "v1"

# The whole capability surface. There is no way to add a module from the CLI,
# because a recon tool that accepts arbitrary plugins accepts arbitrary actions.
MODULES = ("dns", "tls", "headers", "ports")
