"""VAPT Multi-Agent System — CLI Entry Point"""

import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.logging import RichHandler
from loguru import logger

# Setup path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.models import ScanMode, Severity, ScopeConfig
from core.orchestrator import Orchestrator
from core.config import AppConfig
from agents.recon import ReconAgent
from agents.enum_agent import EnumAgent
from agents.vuln_scanner import VulnScannerAgent
from agents.fuzzer import FuzzingAgent
from agents.exploit import ExploitAgent
from agents.intel import IntelAgent
from agents.cloud_agent import CloudAgent
from agents.iot_agent import IoTAgent
from agents.reporter import ReportAgent
from core.scope import ScopeManager

app = typer.Typer(
    name="vapt",
    help="VAPT Multi-Agent System — Professional Penetration Testing Automation",
    no_args_is_help=True,
)
console = Console()

# Modes for selection
MODES = {
    "va": ScanMode.VA_ONLY,
    "full": ScanMode.FULL_VAPT,
    "web": ScanMode.WEB_APP,
    "api": ScanMode.API,
    "cloud": ScanMode.CLOUD,
    "iot": ScanMode.IOT_CCTV,
}


def _setup_logging(verbose: bool = False) -> None:
    """Configure loguru with rich handler."""
    level = "DEBUG" if verbose else "INFO"
    logger.remove()
    logger.add(
        sys.stderr,
        level=level,
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
        colorize=True,
    )


def _register_agents(orchestrator: Orchestrator, scope: ScopeManager, config: AppConfig, mode: ScanMode) -> None:
    """Register all agents needed for the selected mode."""
    profile = config.get_profile(mode.value)
    agent_names = profile.agents

    agent_map = {
        "recon": (AgentType.RECON, lambda: ReconAgent(scope, config)),
        "enum": (AgentType.ENUM, lambda: EnumAgent(scope, config)),
        "vuln_scanner": (AgentType.VULN_SCANNER, lambda: VulnScannerAgent(scope, config)),
        "fuzzer": (AgentType.FUZZER, lambda: FuzzingAgent(scope, config)),
        "exploit": (AgentType.EXPLOIT, lambda: ExploitAgent(scope, config)),
        "intel": (AgentType.INTEL, lambda: IntelAgent(scope, config)),
        "cloud": (AgentType.CLOUD, lambda: CloudAgent(scope, config)),
        "iot_cctv": (AgentType.IOT_CCTV, lambda: IoTAgent(scope, config)),
        "reporter": (AgentType.REPORTER, lambda: ReportAgent(scope, config)),
    }

    for name in agent_names:
        if name in agent_map:
            agent_type, agent_factory = agent_map[name]
            orchestrator.register_agent(agent_type, agent_factory())


@app.command()
def scan(
    target: list[str] = typer.Argument(..., help="Target URL, domain, or IP"),
    mode: str = typer.Option("full", "--mode", "-m", help="Scan mode: va, full, web, api, cloud, iot"),
    name: str = typer.Option("", "--name", "-n", help="Scan name"),
    scope_file: Optional[Path] = typer.Option(None, "--scope", "-s", help="Scope file (one target per line)"),
    out_of_scope: list[str] = typer.Option([], "--oos", help="Out-of-scope domains/IPs"),
    rate_limit: int = typer.Option(50, "--rate-limit", "-r", help="Max requests per second"),
    max_requests: int = typer.Option(50000, "--max-requests", help="Max total requests"),
    config_path: str = typer.Option("config.yaml", "--config", "-c", help="Config file path"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    dashboard: bool = typer.Option(False, "--dashboard", "-d", help="Also start web dashboard"),
    dashboard_port: int = typer.Option(8443, "--dashboard-port", help="Dashboard port"),
):
    """Run a VAPT scan against one or more targets."""
    _setup_logging(verbose)

    if mode not in MODES:
        console.print(f"[red]Unknown mode: {mode}[/red]. Valid: {', '.join(MODES.keys())}")
        raise typer.Exit(1)

    scan_mode = MODES[mode]

    # Load targets from scope file if provided
    if scope_file and scope_file.exists():
        file_targets = scope_file.read_text().strip().splitlines()
        file_targets = [t.strip() for t in file_targets if t.strip() and not t.startswith("#")]
        target = list(set(target + file_targets))

    console.print(Panel(
        f"[bold cyan]VAPT Multi-Agent System[/bold cyan]\n"
        f"Mode: [yellow]{scan_mode.value.upper().replace('_', ' ')}[/yellow]\n"
        f"Targets: [green]{', '.join(target[:5])}{'...' if len(target) > 5 else ''}[/green]\n"
        f"Rate Limit: {rate_limit} req/s | Max Requests: {max_requests}",
        title="Scan Configuration",
        border_style="blue",
    ))

    # Build scope config
    scope_config = ScopeConfig(
        authorized_domains=[t for t in target if not t.startswith("http") and "." in t and not t[0].isdigit()],
        authorized_ips=[t for t in target if t[0].isdigit()],
        out_of_scope=out_of_scope,
        rate_limit=rate_limit,
        max_requests_total=max_requests,
    )

    # If targets look like URLs, add their domains
    for t in target:
        if t.startswith("http"):
            from urllib.parse import urlparse
            p = urlparse(t)
            if p.hostname and p.hostname not in scope_config.authorized_domains:
                scope_config.authorized_domains.append(p.hostname)

    async def _run_scan():
        orchestrator = Orchestrator(config_path=config_path)
        scope = ScopeManager(scope_config)
        _register_agents(orchestrator, scope, orchestrator._config, scan_mode)

        # Set up finding callback for live updates
        def on_finding(f):
            sev_color = {"critical": "red", "high": "red3", "medium": "yellow", "low": "green", "informational": "blue"}.get(f.severity.value, "white")
            console.print(f"  [{sev_color}][{f.severity.value.upper()}][/{sev_color}] {f.title} — {f.target.host}")

        orchestrator.on_finding(on_finding)

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task_id = progress.add_task("[cyan]Running VAPT scan...", total=None)

            result = await orchestrator.start_scan(
                targets=target,
                mode=scan_mode,
                scan_name=name,
                scope_config=scope_config,
            )

            progress.update(task_id, description="[green]Scan complete![/green]")

        # Print summary
        _print_summary(result)
        return result

    result = asyncio.run(_run_scan())

    # Optionally start dashboard
    if dashboard:
        console.print(f"\n[cyan]Starting dashboard on port {dashboard_port}...[/cyan]")
        _start_dashboard(result, dashboard_port)


def _print_summary(scan_result) -> None:
    """Print a rich summary table of findings."""
    console.print("\n")

    # Stats
    grouped = scan_result.findings_by_severity
    table = Table(title="Scan Results Summary", show_header=True, header_style="bold magenta")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    table.add_row("[red]CRITICAL[/red]", str(len(grouped["critical"])))
    table.add_row("[red3]HIGH[/red3]", str(len(grouped["high"])))
    table.add_row("[yellow]MEDIUM[/yellow]", str(len(grouped["medium"])))
    table.add_row("[green]LOW[/green]", str(len(grouped["low"])))
    table.add_row("[blue]INFORMATIONAL[/blue]", str(len(grouped["informational"])))
    table.add_row("[bold]TOTAL[/bold]", f"[bold]{scan_result.total_findings}[/bold]")
    console.print(table)

    # Top findings
    if scan_result.findings:
        console.print("\n[bold]Top Findings:[/bold]")
        sorted_findings = sorted(scan_result.findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.title))
        for f in sorted_findings[:20]:
            sev_icon = {"critical": "[red]", "high": "[red3]", "medium": "[yellow]", "low": "[green]", "informational": "[blue]"}.get(f.severity.value, "")
            console.print(f"  {sev_icon}[{f.severity.value.upper()}]{sev_icon} {f.title} ({f.target.host})")


def _start_dashboard(scan_result, port: int) -> None:
    """Start the web dashboard in a background thread."""
    import threading
    def run():
        import uvicorn
        from web.app import create_app
        app = create_app()
        uvicorn.run(app, host="0.0.0.0", port=port, log_level="warning")
    t = threading.Thread(target=run, daemon=True)
    t.start()


@app.command()
def modes():
    """List available scan modes."""
    table = Table(title="Available Scan Modes")
    table.add_column("Mode", style="cyan")
    table.add_column("Name", style="bold")
    table.add_column("Description")
    table.add_column("Exploitation")

    mode_info = {
        "va": ("Vulnerability Assessment", "Non-intrusive scanning only", "No"),
        "full": ("Full VAPT", "Complete VAPT with exploitation", "Yes"),
        "web": ("Web Application", "Deep web app testing", "Yes"),
        "api": ("API Security", "API endpoint security", "Yes"),
        "cloud": ("Cloud Infrastructure", "Cloud misconfiguration & exposure", "No"),
        "iot": ("IoT & CCTV", "IoT device & camera security", "Yes"),
    }
    for key, (name, desc, expl) in mode_info.items():
        color = "[green]Yes[/green]" if expl == "Yes" else "[yellow]No[/yellow]"
        table.add_row(key, name, desc, color)
    console.print(table)


@app.command()
def list_tools(config_path: str = typer.Option("config.yaml", "--config", "-c")):
    """List configured tools and their status."""
    try:
        config = AppConfig.load(config_path)
    except Exception as e:
        console.print(f"[red]Failed to load config: {e}[/red]")
        return

    table = Table(title="Configured Security Tools")
    table.add_column("Tool", style="cyan")
    table.add_column("Status")
    table.add_column("Docker Image")
    table.add_column("Timeout (s)")

    for name, tool in config.tools.items():
        status = "[green]Enabled[/green]" if tool.enabled else "[red]Disabled[/red]"
        image = tool.docker_image or "[dim]Direct[/dim]"
        table.add_row(name, status, image, str(tool.timeout))
    console.print(table)


@app.command()
def serve(
    port: int = typer.Option(8443, "--port", "-p"),
    config_path: str = typer.Option("config.yaml", "--config", "-c"),
):
    """Start the VAPT web dashboard."""
    _setup_logging()
    console.print(f"[cyan]Starting VAPT Dashboard on port {port}...[/cyan]")
    import uvicorn
    from web.app import create_app
    app = create_app(config_path)
    uvicorn.run(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    app()