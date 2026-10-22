"""
Interactive REPL Shell Mode for Ad-Hoc Asset Investigation
Provides interactive CLI prompt to search subdomains, query IP intel, and test endpoints live.
"""

import sys
from modules.cli.ui import TerminalUI

def start_interactive_shell(target_domain: str = None):
    """Starts interactive ShadowSurface CLI shell."""
    TerminalUI.header("SHADOWSURFACE INTERACTIVE INVESTIGATION SHELL")
    print(" Type 'help' for commands, 'exit' or 'quit' to return to terminal.\n")
    current_target = target_domain

    while True:
        try:
            prompt = f"shadowsurface({current_target or 'no-target'})> "
            cmd_line = input(prompt).strip()
            if not cmd_line:
                continue
            parts = cmd_line.split()
            cmd = parts[0].lower()

            if cmd in ["exit", "quit", "q"]:
                print("[*] Exiting interactive shell.")
                break
            elif cmd == "help":
                print(" Available Commands:")
                print("   target <domain>    - Set or switch active investigation domain")
                print("   info               - Show current target details")
                print("   clear              - Clear console screen")
                print("   exit               - Quit shell")
            elif cmd == "target":
                if len(parts) > 1:
                    current_target = parts[1].strip().lower()
                    TerminalUI.success(f"Active target set to: {current_target}")
                else:
                    TerminalUI.warning("Usage: target <domain.com>")
            elif cmd == "info":
                if current_target:
                    TerminalUI.info(f"Target: {current_target}")
                else:
                    TerminalUI.warning("No active target set. Use 'target <domain>'")
            elif cmd == "clear":
                print("\033[H\033[J", end="")
            else:
                TerminalUI.warning(f"Unknown command: '{cmd}'. Type 'help' for commands.")
        except (KeyboardInterrupt, EOFError):
            print("\n[*] Exiting interactive shell.")
            break
