
import sys
import os
import unittest
from unittest.mock import MagicMock, patch

# Setup path
project_root = os.path.abspath("/home/dhikshanya06/Adaptive-SSH-Honeypot")
sys.path.append(os.path.join(project_root, "src"))

# Mock twisted reactor
sys.modules["twisted.internet"] = MagicMock()
from twisted.internet import reactor

from cowrie.adaptive.adaptive_rules import AdaptiveRulesEngine
import cowrie.shell.command
from cowrie.shell.command import HoneyPotCommand

# Mock logger to avoid config issues
cowrie.shell.command.get_adaptive_command_logger = MagicMock(return_value=None)
cowrie.shell.command.get_adaptive_logger = MagicMock(return_value=None)

# Mock log to print errors
def mock_log_msg(msg, **kwargs):
    print(f"LOG: {msg}")
cowrie.shell.command.log = MagicMock()
cowrie.shell.command.log.msg = mock_log_msg

cowrie.shell.command._ADAPTIVE_AVAILABLE = True
cowrie.shell.command.AdaptiveRulesEngine = AdaptiveRulesEngine

class VerifyAsyncDelay(unittest.TestCase):
    def setUp(self):
        self.protocol = MagicMock()
        self.protocol.session_id = "async_sess"
        
        # Reset rules engine
        if AdaptiveRulesEngine._instance:
            AdaptiveRulesEngine._instance._session_state = {}

    def test_start_schedules_callLater(self):
        print("\n--- Testing Async Delay Scheduling ---")
        
        # "sudo" should trigger 2.0s delay
        engine = AdaptiveRulesEngine()
        behavior = engine.get_adaptive_behavior("async_sess", "sudo")
        print(f"DEBUG: behavior for sudo: {behavior}")

        cmd = HoneyPotCommand(self.protocol, "sudo")
        cmd.command_name = "sudo"
        cmd.call = MagicMock()
        cmd.exit = MagicMock()
        
        # Execute start
        cmd.start()
        
        # Verify reactor.callLater was called
        # args: (2.0, cmd.execute)
        call_args = reactor.callLater.call_args
        print(f"Reactor Call Args: {call_args}")
        
        self.assertIsNotNone(call_args)
        delay, func = call_args[0]
        self.assertEqual(delay, 2.0)
        self.assertEqual(func, cmd.execute)
        
        # Verify call() NOT called yet
        cmd.call.assert_not_called()
        cmd.exit.assert_not_called()
        
        print("Executing callback manually...")
        func()
        
        # Verify executed
        cmd.call.assert_called_once()
        cmd.exit.assert_called_once()
        
    def test_no_delay_execution(self):
        print("\n--- Testing Immediate Execution ---")
        
        # "ls" should be 0.0s delay
        cmd = HoneyPotCommand(self.protocol, "ls")
        cmd.command_name = "ls"
        cmd.call = MagicMock()
        reactor.callLater.reset_mock()
        
        cmd.start()
        
        # Verify reactor was NOT called
        reactor.callLater.assert_not_called()
        
        # Verify executed immediately
        cmd.call.assert_called_once()

if __name__ == "__main__":
    unittest.main()
