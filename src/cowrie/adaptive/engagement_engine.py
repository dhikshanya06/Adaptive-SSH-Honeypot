"""
engagement_engine.py - Stub engagement engine for Adaptive SSH Honeypot
Handles bait planting and honeytoken engagement checks.
"""
from __future__ import annotations
from twisted.python import log


class EngagementEngine:
    def __init__(self):
        self.planted = []

    def check_and_plant(self, command: str) -> None:
        """
        Check incoming command and plant bait/honeytokens if appropriate.
        Called from HoneyPotShell for every command the attacker types.
        """
        try:
            cmd = command.strip().lower() if command else ""

            # Trigger bait planting on reconnaissance commands
            if any(kw in cmd for kw in ["ls", "find", "cat", "wget", "curl", "scp"]):
                self._plant_bait(cmd)

        except Exception as e:
            log.msg(f"[ENGAGEMENT] check_and_plant error: {e}")

    def _plant_bait(self, command: str) -> None:
        """Plant honeytoken bait based on command context."""
        try:
            if "ls" in command and command not in self.planted:
                self.planted.append(command)
                log.msg(f"[ENGAGEMENT] Bait opportunity detected for: {command}")
        except Exception as e:
            log.msg(f"[ENGAGEMENT] _plant_bait error: {e}")


# Singleton instance — imported directly by honeypot.py
engagement_engine = EngagementEngine()
