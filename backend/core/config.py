"""
VAPT Multi-Agent System — Configuration Loader

Loads and validates ``config.yaml`` (with environment variable overrides
via ``pydantic-settings``) and provides typed, validated access to every
configuration section.
"""

from pathlib import Path
from typing import Optional, Any
import yaml

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


# ────────────────────────────────────────────────────────────────────
# Tool Configuration
# ────────────────────────────────────────────────────────────────────

class ToolConfig(BaseModel):
    """Configuration for a single security tool.

    Attributes:
        enabled:      Whether the tool is available for use.
        docker_image: Docker image name/tag (empty string if not containerised).
        timeout:      Maximum execution time in seconds.
        extra_args:   Additional CLI arguments to always pass.
        settings:     Tool-specific settings preserved verbatim from YAML
                      (e.g. ``ports`` for nmap, ``template_tags`` for nuclei,
                      ``wordlist``/``extensions`` for ffuf, ``level``/``risk``
                      for sqlmap). The base model intentionally does NOT model
                      these as typed fields because they vary per tool; instead
                      they live in this free-form dict so agents can read them
                      via ``tool_config.settings.get("ports")``. This fixes the
                      previous bug where ``from_raw`` silently dropped every
                      tool-specific key.
    """

    enabled: bool = Field(default=True, description="Whether the tool is enabled")
    docker_image: str = Field(default="", description="Docker image identifier")
    timeout: int = Field(default=300, ge=1, description="Timeout in seconds")
    extra_args: list[str] = Field(default_factory=list, description="Additional CLI arguments")
    memory_limit: Optional[str] = Field(
        default=None,
        description="Per-tool container memory limit (e.g. '1536m'). Falls back to "
        "the global DockerConfig.memory_limit when unset. Memory-hungry crawlers "
        "such as Katana need a higher tier than the 512m default to avoid OOM "
        "(exit_code 137) kills.",
    )
    cpu_limit: Optional[float] = Field(
        default=None,
        description="Per-tool container CPU limit (cores). Falls back to the global "
        "DockerConfig.cpu_limit when unset.",
    )
    settings: dict[str, Any] = Field(default_factory=dict, description="Tool-specific settings")

    @classmethod
    def from_raw(cls, data: dict[str, Any]) -> "ToolConfig":
        """Construct a ``ToolConfig`` from a raw dictionary.

        Known fields (enabled / docker_image / timeout / extra_args) are
        consumed directly. Every *other* key (ports, template_tags, wordlist,
        extensions, level, risk, scan_types, ...) is preserved inside the
        ``settings`` dict so agents can still read it. This fixes the bug
        where tool-specific YAML keys were silently discarded.
        """
        known_fields = {f for f in cls.model_fields}
        filtered: dict[str, Any] = {}
        preserved: dict[str, Any] = {}
        for k, v in data.items():
            if k in known_fields:
                filtered[k] = v
            else:
                preserved[k] = v
        if preserved:
            filtered["settings"] = preserved
        return cls(**filtered)


# ────────────────────────────────────────────────────────────────────
# Rate-Limit Configuration
# ────────────────────────────────────────────────────────────────────

class RateLimitConfig(BaseModel):
    """Global rate-limiting and request-throttle configuration.

    Attributes:
        requests_per_second:     Maximum outbound requests per second.
        concurrent_threads:      Maximum concurrent worker threads.
        delay_between_requests:  Fixed delay (seconds) between successive requests.
        waf_detection:           Whether to attempt WAF fingerprinting.
        waf_evasion:             Whether to apply WAF-evasion techniques.
        auto_throttle:           Whether to automatically reduce speed on 429/503.
        max_retries:             Maximum retry attempts on transient failures.
    """

    requests_per_second: int = Field(default=50, ge=1, description="Requests per second")
    concurrent_threads: int = Field(default=10, ge=1, description="Concurrent threads")
    delay_between_requests: float = Field(default=0.1, ge=0.0, description="Delay between requests (s)")
    waf_detection: bool = Field(default=True, description="Enable WAF detection")
    waf_evasion: bool = Field(default=True, description="Enable WAF evasion")
    auto_throttle: bool = Field(default=True, description="Auto-throttle on 429/503")
    max_retries: int = Field(default=3, ge=0, description="Max retry attempts")


# ────────────────────────────────────────────────────────────────────
# Sub-section models
# ────────────────────────────────────────────────────────────────────

class LLMConfig(BaseModel):
    """LLM provider configuration for intelligent analysis and reporting.

    Attributes:
        provider:          LLM provider name (``openai``, ``anthropic``, ``gemini``, etc.).
        model:             Primary model identifier.
        temperature:       Sampling temperature.
        max_tokens:        Maximum tokens per completion.
        api_key_env:       Environment variable holding the API key.
        base_url:          Base URL for local/OpenAI-compatible providers.
        analysis_model:    Model used for vulnerability analysis.
        report_model:      Model used for report generation.
        fallback_providers: List of backup providers tried in order on failure.
    """

    provider: str = Field(default="openai", description="LLM provider")
    model: str = Field(default="gpt-4o", description="Primary model")
    temperature: float = Field(default=0.3, ge=0.0, le=2.0, description="Sampling temperature")
    max_tokens: int = Field(default=4096, ge=1, description="Max tokens per completion")
    api_key_env: str = Field(default="OPENAI_API_KEY", description="Env var for API key")
    base_url: str = Field(default="", description="Base URL for local/OpenAI-compatible providers")
    analysis_model: str = Field(default="gpt-4o", description="Model for analysis")
    report_model: str = Field(default="gpt-4o", description="Model for report writing")
    fallback_providers: list[dict[str, Any]] = Field(default_factory=list, description="Fallback LLM providers")


class DatabaseConfig(BaseModel):
    """Database connection and pool configuration.

    Attributes:
        url:        Database URL. Phase 1 uses SQLite via stdlib sqlite3.
        pool_size:  Reserved for a future PostgreSQL/SQLAlchemy pool.
        max_overflow: Maximum overflow connections beyond pool_size.
    """

    url: str = Field(default="sqlite:///./data/vapt.db", description="DB URL")
    pool_size: int = Field(default=10, ge=1, description="Connection pool size")
    max_overflow: int = Field(default=20, ge=0, description="Max overflow connections")


class RedisConfig(BaseModel):
    """Redis connection configuration.

    Attributes:
        url:        Redis connection URL.
        stream_key: Key name for the task stream.
    """

    url: str = Field(default="redis://localhost:6379/0", description="Redis URL")
    stream_key: str = Field(default="vapt:task_stream", description="Task stream key")


class ReportingConfig(BaseModel):
    """Report generation configuration.

    Attributes:
        formats:            Output formats to generate.
        output_dir:         Directory for generated reports.
        include_poc:        Whether to include proof-of-concept steps.
        include_cvss:       Whether to include CVSS scores.
        include_remediation: Whether to include remediation guidance.
        executive_summary:  Whether to generate an executive summary.
        company_branding:   Whether to apply company branding.
    """

    formats: list[str] = Field(
        default_factory=lambda: ["html", "pdf", "markdown", "json"],
        description="Output formats",
    )
    output_dir: str = Field(default="./reports", description="Output directory")
    include_poc: bool = Field(default=True, description="Include PoC steps")
    include_cvss: bool = Field(default=True, description="Include CVSS scores")
    include_remediation: bool = Field(default=True, description="Include remediation")
    executive_summary: bool = Field(default=True, description="Generate executive summary")
    company_branding: bool = Field(default=False, description="Apply company branding")


class DockerConfig(BaseModel):
    """Docker execution environment configuration.

    Attributes:
        network:      Docker network name for tool containers.
        auto_pull:    Whether to auto-pull missing images.
        cleanup:      Whether to remove containers after execution.
        memory_limit: Per-container memory limit (e.g. ``512m``).
        cpu_limit:    Per-container CPU limit (cores).
    """

    network: str = Field(default="vapt_network", description="Docker network")
    auto_pull: bool = Field(default=True, description="Auto-pull images")
    cleanup: bool = Field(default=True, description="Cleanup containers after run")
    memory_limit: str = Field(default="512m", description="Memory limit per container")
    cpu_limit: float = Field(default=1.0, ge=0.1, description="CPU limit per container")


class LoggingConfig(BaseModel):
    """Logging configuration.

    Attributes:
        level:       Minimum log level.
        file:        Log file path.
        max_size:    Maximum log file size before rotation.
        rotation:    Number of rotated log files to retain.
        json_format: Whether to use JSON structured logging.
    """

    level: str = Field(default="INFO", description="Log level")
    file: str = Field(default="./logs/vapt.log", description="Log file path")
    max_size: str = Field(default="100MB", description="Max log file size")
    rotation: int = Field(default=5, ge=1, description="Number of rotated files")
    json_format: bool = Field(default=True, description="JSON structured logging")


class DashboardAuthConfig(BaseModel):
    """Dashboard authentication configuration."""

    enabled: bool = Field(default=True, description="Enable dashboard auth")
    username: str = Field(default="admin", description="Dashboard username")
    password_env: str = Field(default="VAPT_DASHBOARD_PASSWORD", description="Env var for password")


class DashboardConfig(BaseModel):
    """Web dashboard configuration.

    Attributes:
        host:          Bind address.
        port:          Bind port.
        ssl:           Whether to enable SSL/TLS.
        auth:          Authentication settings.
        cors_origins:  Allowed CORS origins.
    """

    host: str = Field(default="0.0.0.0", description="Bind address")
    port: int = Field(default=8443, ge=1, le=65535, description="Bind port")
    ssl: bool = Field(default=False, description="Enable SSL")
    auth: DashboardAuthConfig = Field(default_factory=DashboardAuthConfig, description="Auth config")
    cors_origins: list[str] = Field(default_factory=lambda: ["*"], description="CORS origins")


class NotificationConfig(BaseModel):
    """Notification configuration for alerts and webhook integrations.

    Attributes:
        webhook_url:          Generic webhook URL.
        slack_webhook:        Slack incoming webhook URL.
        telegram_bot_token:   Telegram bot token.
        telegram_chat_id:     Telegram chat ID for notifications.
        on_critical_found:    Notify when a critical finding is discovered.
        on_scan_complete:     Notify when a scan completes.
    """

    webhook_url: str = Field(default="", description="Generic webhook URL")
    slack_webhook: str = Field(default="", description="Slack webhook URL")
    telegram_bot_token: str = Field(default="", description="Telegram bot token")
    telegram_chat_id: str = Field(default="", description="Telegram chat ID")
    on_critical_found: bool = Field(default=True, description="Notify on critical finding")
    on_scan_complete: bool = Field(default=True, description="Notify on scan completion")


class ProfileConfig(BaseModel):
    """A scan profile defining which agents to run and how.

    Attributes:
        name:        Human-readable profile name.
        agents:      Ordered list of agent types to invoke.
        aggressive:  Whether to use aggressive scanning techniques.
        exploit:     Whether exploitation is enabled.
        focus:       Optional list of focus areas.
        description: Human-readable description.
    """

    name: str = Field(default="", description="Profile name")
    agents: list[str] = Field(default_factory=list, description="Agent types")
    aggressive: bool = Field(default=False, description="Aggressive scanning")
    exploit: bool = Field(default=False, description="Enable exploitation")
    focus: list[str] = Field(default_factory=list, description="Focus areas")
    description: str = Field(default="", description="Profile description")


# ────────────────────────────────────────────────────────────────────
# Environment Variable Overrides
# ────────────────────────────────────────────────────────────────────

class EnvOverrides(BaseSettings):
    """Environment variables that can override YAML configuration values.

    Uses ``pydantic-settings`` to load from environment variables with
    the ``VAPT_`` prefix.

    Attributes:
        vapt_database_url:       Override for database URL.
        vapt_redis_url:          Override for Redis URL.
        vapt_log_level:          Override for log level.
        vapt_default_mode:       Override for default scan mode.
        vapt_openai_api_key:     OpenAI API key.
        vapt_shodan_api_key:     Shodan API key.
        vapt_censys_api_id:      Censys API ID.
        vapt_censys_api_secret:  Censys API secret.
        vapt_llm_provider:       Override primary LLM provider.
        vapt_llm_model:          Override primary LLM model.
        vapt_llm_api_key_env:    Override primary LLM API-key env var.
        vapt_llm_base_url:       Override primary LLM base URL.
    """

    model_config = SettingsConfigDict(
        env_prefix="VAPT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    vapt_database_url: Optional[str] = Field(default=None, alias="VAPT_DATABASE_URL")
    vapt_redis_url: Optional[str] = Field(default=None, alias="VAPT_REDIS_URL")
    vapt_log_level: Optional[str] = Field(default=None, alias="VAPT_LOG_LEVEL")
    vapt_default_mode: Optional[str] = Field(default=None, alias="VAPT_DEFAULT_MODE")
    vapt_openai_api_key: Optional[str] = Field(default=None, alias="VAPT_OPENAI_API_KEY")
    vapt_shodan_api_key: Optional[str] = Field(default=None, alias="VAPT_SHODAN_API_KEY")
    vapt_censys_api_id: Optional[str] = Field(default=None, alias="VAPT_CENSYS_API_ID")
    vapt_censys_api_secret: Optional[str] = Field(default=None, alias="VAPT_CENSYS_API_SECRET")
    vapt_llm_provider: Optional[str] = Field(default=None, alias="VAPT_LLM_PROVIDER")
    vapt_llm_model: Optional[str] = Field(default=None, alias="VAPT_LLM_MODEL")
    vapt_llm_api_key_env: Optional[str] = Field(default=None, alias="VAPT_LLM_API_KEY_ENV")
    vapt_llm_base_url: Optional[str] = Field(default=None, alias="VAPT_LLM_BASE_URL")


# ────────────────────────────────────────────────────────────────────
# Root Application Configuration
# ────────────────────────────────────────────────────────────────────

class AppConfig(BaseModel):
    """Root configuration model that aggregates all config sections.

    Loads from a YAML file and applies environment variable overrides.

    Attributes:
        default_mode:   Default scan mode.
        profiles:       Named scan profiles keyed by mode name.
        rate_limiting:  Global rate-limiting settings.
        tools:          Tool configurations keyed by tool name.
        llm:            LLM provider settings.
        database:       Database connection settings.
        redis:          Redis connection settings.
        reporting:      Report generation settings.
        docker:         Docker execution settings.
        logging:        Logging settings.
        dashboard:      Web dashboard settings.
        notifications:  Notification settings.
        _raw:           Unprocessed raw YAML data (internal).
    """

    default_mode: str = Field(default="full_vapt", description="Default scan mode")
    profiles: dict[str, ProfileConfig] = Field(default_factory=dict, description="Scan profiles")
    rate_limiting: RateLimitConfig = Field(default_factory=RateLimitConfig, description="Rate limiting")
    tools: dict[str, ToolConfig] = Field(default_factory=dict, description="Tool configs")
    llm: LLMConfig = Field(default_factory=LLMConfig, description="LLM config")
    database: DatabaseConfig = Field(default_factory=DatabaseConfig, description="Database config")
    redis: RedisConfig = Field(default_factory=RedisConfig, description="Redis config")
    reporting: ReportingConfig = Field(default_factory=ReportingConfig, description="Reporting config")
    docker: DockerConfig = Field(default_factory=DockerConfig, description="Docker config")
    logging: LoggingConfig = Field(default_factory=LoggingConfig, description="Logging config")
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig, description="Dashboard config")
    notifications: NotificationConfig = Field(default_factory=NotificationConfig, description="Notifications")

    _raw: dict[str, Any] = {}

    @classmethod
    def load(cls, config_path: str | Path = "config.yaml") -> "AppConfig":
        """Load configuration from a YAML file with env-var overrides.

        The loading process:
        1. Read and parse the YAML file.
        2. Load environment variable overrides via ``pydantic-settings``.
        3. Apply overrides on top of YAML values.
        4. Validate and return a typed ``AppConfig`` instance.

        Args:
            config_path: Path to the YAML configuration file.

        Returns:
            A fully validated ``AppConfig`` instance.

        Raises:
            FileNotFoundError: If the config file does not exist.
            yaml.YAMLError:     If the YAML is malformed.
            ValidationError:   If the merged config fails validation.
        """
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")

        with open(path, "r", encoding="utf-8") as fh:
            raw: dict[str, Any] = yaml.safe_load(fh) or {}

        # Apply environment variable overrides
        env = EnvOverrides()
        raw = cls._apply_env_overrides(raw, env)

        # Parse profiles
        profiles_raw = raw.pop("profiles", {})
        profiles: dict[str, ProfileConfig] = {}
        for mode_name, profile_data in profiles_raw.items():
            if isinstance(profile_data, dict):
                profiles[mode_name] = ProfileConfig(**profile_data)

        # Parse tools
        tools_raw = raw.pop("tools", {})
        tools: dict[str, ToolConfig] = {}
        for tool_name, tool_data in tools_raw.items():
            if isinstance(tool_data, dict):
                tools[tool_name] = ToolConfig.from_raw(tool_data)

        # Build the AppConfig with remaining top-level sections
        instance = cls(
            default_mode=raw.pop("default_mode", "full_vapt"),
            profiles=profiles,
            rate_limiting=RateLimitConfig(**raw.pop("rate_limiting", {})),
            tools=tools,
            llm=LLMConfig(**raw.pop("llm", {})),
            database=DatabaseConfig(**raw.pop("database", {})),
            redis=RedisConfig(**raw.pop("redis", {})),
            reporting=ReportingConfig(**raw.pop("reporting", {})),
            docker=DockerConfig(**raw.pop("docker", {})),
            logging=LoggingConfig(**raw.pop("logging", {})),
            dashboard=DashboardConfig(**raw.pop("dashboard", {})),
            notifications=NotificationConfig(**raw.pop("notifications", {})),
        )

        instance._raw = raw  # Store any remaining top-level keys
        return instance

    def get_profile(self, mode: str) -> ProfileConfig:
        """Retrieve a scan profile by mode name.

        Falls back to the ``custom`` profile if the requested mode is
        not found.

        Args:
            mode: The scan mode name (e.g. ``full_vapt``).

        Returns:
            The corresponding ``ProfileConfig``.
        """
        if mode in self.profiles:
            return self.profiles[mode]
        if "custom" in self.profiles:
            return self.profiles["custom"]
        return ProfileConfig(name=f"Auto-generated for {mode}")

    def get_tool_config(self, tool_name: str) -> ToolConfig:
        """Retrieve the configuration for a specific tool.

        Args:
            tool_name: The tool identifier (e.g. ``nuclei``).

        Returns:
            The ``ToolConfig`` for the tool, or a default (disabled)
            config if the tool is not defined.
        """
        if tool_name in self.tools:
            return self.tools[tool_name]
        return ToolConfig(enabled=False, timeout=300)

    @staticmethod
    def _apply_env_overrides(raw: dict[str, Any], env: EnvOverrides) -> dict[str, Any]:
        """Apply environment variable overrides onto the raw YAML dict.

        Args:
            raw: The parsed YAML dictionary.
            env: The ``EnvOverrides`` instance loaded from environment.

        Returns:
            A new dictionary with overrides applied.
        """
        result = dict(raw)

        if env.vapt_database_url:
            result.setdefault("database", {})["url"] = env.vapt_database_url
        if env.vapt_redis_url:
            result.setdefault("redis", {})["url"] = env.vapt_redis_url
        if env.vapt_log_level:
            result.setdefault("logging", {})["level"] = env.vapt_log_level.upper()
        if env.vapt_default_mode:
            result["default_mode"] = env.vapt_default_mode
        if env.vapt_llm_provider:
            result.setdefault("llm", {})["provider"] = env.vapt_llm_provider
        if env.vapt_llm_model:
            llm = result.setdefault("llm", {})
            llm["model"] = env.vapt_llm_model
            llm["analysis_model"] = env.vapt_llm_model
            llm["report_model"] = env.vapt_llm_model
        if env.vapt_llm_api_key_env:
            result.setdefault("llm", {})["api_key_env"] = env.vapt_llm_api_key_env
        if env.vapt_llm_base_url:
            result.setdefault("llm", {})["base_url"] = env.vapt_llm_base_url.rstrip("/")

        return result
