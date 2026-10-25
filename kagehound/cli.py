"""
KageHound Command Line Interface.
Unified entry point for secret defense, live verification, breach radar, and dark web intelligence.
"""

import sys
import time
from pathlib import Path

import click
from rich.console import Console

from kagehound import __version__
from kagehound.core.config import load_config
from kagehound.core.models import SecretMatch, VerificationStatus
from kagehound.core.reporter import (
    dispatch_telegram_alert,
    display_darkweb_results,
    display_scan_results,
    export_json,
    export_sarif,
    print_banner,
)
from kagehound.modules.breach.hibp import HIBPClient
from kagehound.modules.breach.hmsl import HMSLClient
from kagehound.modules.darkweb.scout import ThreatScoutCoordinator
from kagehound.modules.guard.hooks import install_hook, uninstall_hook
from kagehound.modules.guard.scanner import Scanner
from kagehound.modules.verifier.engine import VerifierEngine

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="KageHound")
def cli() -> None:
    """🛡️ KageHound: Unified Secret Defense & Threat Intelligence Suite."""


@cli.command("scan")
@click.argument("target_path", default=".", type=click.Path(exists=True))
@click.option("--staged", is_flag=True, help="Scan only staged Git changes (pre-commit mode).")
@click.option("--verify", is_flag=True, help="Verify discovered credentials against vendor APIs.")
@click.option(
    "--entropy", is_flag=True, help="Enable Shannon entropy scanning for unclassified tokens."
)
@click.option("--json-out", type=click.Path(), help="Export findings to a JSON file.")
@click.option(
    "--sarif-out", type=click.Path(), help="Export findings to an OASIS SARIF v2.1.0 file."
)
@click.option(
    "--notify-telegram", is_flag=True, help="Send instant alert to Telegram on leak detection."
)
@click.option(
    "--config", "config_path", type=click.Path(exists=True), help="Path to custom config file."
)
def scan_cmd(
    target_path: str,
    staged: bool,
    verify: bool,
    entropy: bool,
    json_out: str | None,
    sarif_out: str | None,
    notify_telegram: bool,
    config_path: str | None,
) -> None:
    """Scan files, folders, or staged Git changes for sensitive secrets."""
    print_banner()
    cfg = load_config(config_path)

    scanner = Scanner(
        check_entropy=entropy,
        entropy_threshold=cfg.entropy_threshold,
        entropy_min_length=cfg.entropy_min_length,
    )

    start_time = time.time()
    matches: list[SecretMatch] = []
    files_scanned = 0
    p = Path(target_path)

    if staged:
        console.print("[bold cyan]🔍 Scanning staged Git changes...[/bold cyan]")
        matches = scanner.scan_git_staged(p if p.is_dir() else Path.cwd())
        files_scanned = len({m.file_path for m in matches}) if matches else 1
    elif p.is_file():
        console.print(f"[bold cyan]🔍 Scanning file:[/] {p}")
        matches = scanner.scan_file(p)
        files_scanned = 1
    else:
        console.print(f"[bold cyan]🔍 Scanning directory:[/] {p}")
        matches, files_scanned = scanner.scan_directory(p, ignore_patterns=cfg.ignore_paths)

    # Live verification if requested
    if verify and matches:
        console.print(
            "[bold magenta]⚡ Verifying candidate credentials with vendor APIs...[/bold magenta]"
        )
        verifier = VerifierEngine()
        matches = verifier.verify_matches(matches)

    elapsed = time.time() - start_time

    # Display results
    display_scan_results(matches, total_files=files_scanned, elapsed_seconds=elapsed)

    # Exports
    if json_out:
        export_json(matches, json_out)
    if sarif_out:
        export_sarif(matches, sarif_out)

    # Telegram Alert
    if notify_telegram and matches:
        console.print("[bold blue]📱 Dispatching mobile alert via Telegram...[/bold blue]")
        sent = dispatch_telegram_alert(cfg.telegram_bot_token, cfg.telegram_chat_id, matches)
        if sent:
            console.print("[bold green]✅ Telegram alert delivered.[/bold green]")
        else:
            console.print(
                "[dim red]⚠️ Failed to send Telegram alert (check bot token / chat ID).[/dim red]"
            )

    # Exit code: non-zero if leaks detected (useful for CI/CD gates and git hooks)
    if matches:
        sys.exit(1)


@cli.command("verify")
@click.argument("target")
@click.option(
    "--type",
    "verifier_type",
    help="Explicit vendor type (telegram, github, stripe, openai, aws, oci).",
)
@click.option("--only-active", is_flag=True, help="Display only verified active credentials.")
def verify_cmd(target: str, verifier_type: str | None, only_active: bool) -> None:
    """Verify live status of a secret string or all secrets within a file."""
    print_banner()
    verifier = VerifierEngine()
    target_path = Path(target)

    if target_path.is_file():
        console.print(
            f"[bold cyan]🔍 Scanning and verifying secrets inside {target_path}...[/bold cyan]"
        )
        scanner = Scanner()
        matches = scanner.scan_file(target_path)
        if not matches:
            console.print("[green]No secrets found inside file to verify.[/green]")
            return

        verified_matches = verifier.verify_matches(matches)
        if only_active:
            verified_matches = [
                m for m in verified_matches if m.verification.status == VerificationStatus.ACTIVE
            ]

        display_scan_results(verified_matches, total_files=1, elapsed_seconds=0.0)
    else:
        # Direct secret verification
        console.print("[bold cyan]⚡ Verifying secret credential...[/bold cyan]")
        res = verifier.verify_secret(target, verifier_type=verifier_type)

        if (
            res.status_code == VerificationStatus.ACTIVE
            if hasattr(res, "status_code")
            else res.status == VerificationStatus.ACTIVE
        ):
            console.print(f"[bold red]⚡ STATUS: ACTIVE[/bold red] - {res.message}")
        elif res.status == VerificationStatus.INACTIVE:
            console.print(f"[dim green]💀 STATUS: INACTIVE / DEAD[/dim green] - {res.message}")
        else:
            console.print(f"[yellow]❓ STATUS: UNVERIFIABLE[/yellow] - {res.message}")


@cli.group("hook")
def hook_group() -> None:
    """Manage automatic Git pre-commit secret protection."""


@hook_group.command("install")
@click.argument("repo_path", default=".", type=click.Path(exists=True))
def hook_install(repo_path: str) -> None:
    """Install KageHound pre-commit hook into a Git repository."""
    success, msg = install_hook(Path(repo_path))
    if success:
        console.print(f"[bold green]✅ {msg}[/bold green]")
    else:
        console.print(f"[bold red]❌ {msg}[/bold red]")
        sys.exit(1)


@hook_group.command("uninstall")
@click.argument("repo_path", default=".", type=click.Path(exists=True))
def hook_uninstall(repo_path: str) -> None:
    """Uninstall KageHound pre-commit hook from a Git repository."""
    success, msg = uninstall_hook(Path(repo_path))
    if success:
        console.print(f"[bold green]✅ {msg}[/bold green]")
    else:
        console.print(f"[bold red]❌ {msg}[/bold red]")
        sys.exit(1)


@cli.command("check-password")
@click.argument("password", required=False)
@click.option("--interactive", "-i", is_flag=True, help="Prompt securely without terminal history.")
def check_password_cmd(password: str | None, interactive: bool) -> None:
    """Check if password appears in global breach databases via k-Anonymity (HIBP)."""
    print_banner()
    if interactive or not password:
        password = click.prompt("Enter password to check (masked)", hide_input=True)

    console.print(
        "[bold cyan]🔒 Deriving SHA-1 and querying HIBP with 5-character prefix...[/bold cyan]"
    )
    client = HIBPClient()
    is_pwned, count = client.check_password(password)

    if is_pwned:
        console.print(
            f"[bold red]🚨 COMPROMISED:[/] This password appeared in historical breaches [bold red]{count:,}[/] times!"
        )
        console.print(
            "[yellow]💡 Recommendation: Never use this password in production or personal accounts.[/yellow]"
        )
        sys.exit(1)
    else:
        console.print(
            "[bold green]✅ CLEAN:[/] This password was not found in known public breach dumps."
        )


@cli.command("check-secret")
@click.argument("secret", required=False)
@click.option("--interactive", "-i", is_flag=True, help="Prompt securely without terminal history.")
def check_secret_cmd(secret: str | None, interactive: bool) -> None:
    """Check if an API key appears in public breach feeds via HasMySecretLeaked (HMSL)."""
    print_banner()
    if interactive or not secret:
        secret = click.prompt("Enter secret to check (masked)", hide_input=True)

    console.print(
        "[bold cyan]🔒 Deriving scrypt hash and querying HMSL zero-knowledge index...[/bold cyan]"
    )
    client = HMSLClient()
    is_leaked, message = client.check_secret(secret)

    if is_leaked:
        console.print(f"[bold red]🚨 {message}[/bold red]")
        sys.exit(1)
    else:
        console.print(f"[bold green]✅ {message}[/bold green]")


@cli.command("darkweb")
@click.argument("target")
@click.option("--sources", default="ahmia,intelx,pastes", help="Comma-separated threat sources.")
@click.option("--limit", default=10, type=int, help="Max results per source.")
@click.option(
    "--notify-telegram", is_flag=True, help="Send instant alert to Telegram if exposures are found."
)
@click.option(
    "--config", "config_path", type=click.Path(exists=True), help="Path to custom config file."
)
def darkweb_cmd(
    target: str, sources: str, limit: int, notify_telegram: bool, config_path: str | None
) -> None:
    """Search for exposed identifiers across Tor .onion search engines and public pastes."""
    print_banner()
    cfg = load_config(config_path)

    console.print(f"[bold cyan]🕷️ Scouting threat feeds for:[/] {target}")
    scout = ThreatScoutCoordinator(intelx_api_key=cfg.intelx_api_key)
    source_list = [s.strip() for s in sources.split(",")]

    results = scout.scout(target, sources=source_list, limit_per_source=limit)
    display_darkweb_results(results)

    if notify_telegram and results:
        # Alert if dark web leaks found
        console.print("[bold blue]📱 Dispatching mobile alert via Telegram...[/bold blue]")
        # Dispatch brief summary
        if cfg.telegram_bot_token and cfg.telegram_chat_id:
            import requests

            text = (
                f"🚨 *KAGEVIGIL DARK WEB ALERT*\n"
                f"Target: `{target}`\n"
                f"Found *{len(results)}* dark web / paste exposure(s)!\n\n"
            )
            for r in results[:4]:
                text += f"• *[{r.source.upper()}]* {r.title}\n  `{r.url}`\n"
            requests.post(
                f"https://api.telegram.org/bot{cfg.telegram_bot_token}/sendMessage",
                json={"chat_id": cfg.telegram_chat_id, "text": text, "parse_mode": "Markdown"},
                timeout=10,
            )
            console.print("[bold green]✅ Telegram alert delivered.[/bold green]")


if __name__ == "__main__":
    cli()
