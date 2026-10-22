"""
Rich Terminal UI & Visual Display System
Formats status messages, vulnerability findings, risk meters, and colored summary banners.
"""

from colorama import Fore, Style, init

init(autoreset=True)

class TerminalUI:
    """Provides styled terminal output for reconnaissance tasks."""
    @staticmethod
    def header(title: str):
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'=' * 65}")
        print(f" [*] {title}")
        print(f"{Fore.CYAN}{Style.BRIGHT}{'=' * 65}")

    @staticmethod
    def info(msg: str):
        print(f" {Fore.BLUE}[i]{Style.RESET_ALL} {msg}")

    @staticmethod
    def success(msg: str):
        print(f" {Fore.GREEN}[+]{Style.RESET_ALL} {msg}")

    @staticmethod
    def warning(msg: str):
        print(f" {Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")

    @staticmethod
    def critical(msg: str):
        print(f" {Fore.RED}{Style.BRIGHT}[CRITICAL]{Style.RESET_ALL} {msg}")

    @staticmethod
    def print_risk_meter(score: int, grade: str):
        color = Fore.GREEN if score >= 80 else (Fore.YELLOW if score >= 60 else Fore.RED)
        bar_len = int(score / 5)
        bar = "█" * bar_len + "░" * (20 - bar_len)
        print(f"\n Security Score : {color}{score}/100 [{bar}] (Grade: {grade}){Style.RESET_ALL}")
