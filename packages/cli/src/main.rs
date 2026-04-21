mod printer;
mod config;
mod ctx;
mod commands;
mod tui;
mod otel;
mod templates;

use clap::{Parser, Subcommand, Args};
use printer::{Format, Printer};

/// Portable trust receipts for agent workflows.
///
/// Treeship signs every action, approval, and handoff in your agent workflow
/// and gives you a verifiable proof chain you can share as a URL.
///
/// Quick start:
///   treeship init
///   treeship wrap -- npm test
///   treeship status
#[derive(Parser)]
#[command(
    name    = "treeship",
    version = env!("CARGO_PKG_VERSION"),
    about   = "Portable trust receipts for agent workflows",
    before_help = "\x1b[1mQuick start\x1b[0m\n  treeship quickstart          guided setup in 90 seconds\n  treeship add                 instrument your AI agents\n  treeship session start       begin recording a session\n  treeship wrap -- <cmd>       record a command\n  treeship session close       finalize and create receipt\n  treeship session report      upload and get shareable URL\n\n  Learn more: docs.treeship.dev",
    after_help = "Docs: https://treeship.dev/docs   Hub: treeship hub attach",
)]
struct Cli {
    /// Config file (default: ~/.treeship/config.json)
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<String>,

    /// Output format: text (default) or json
    #[arg(long, global = true, default_value = "text", value_name = "FORMAT")]
    format: String,

    /// Suppress all output except errors
    #[arg(long, global = true, default_value_t = false)]
    quiet: bool,

    /// Disable color output
    #[arg(long, global = true, default_value_t = false)]
    no_color: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Auto-detect and instrument installed AI agent frameworks
    ///
    /// Checks for Claude Code, Cursor, Cline, Hermes, and OpenClaw.
    /// Adds @treeship/mcp as an MCP server or installs the Treeship
    /// skill file depending on the framework.
    ///
    /// Examples:
    ///   treeship add                    # detect and instrument all
    ///   treeship add claude-code hermes # instrument specific agents
    ///   treeship add --all              # non-interactive, all detected
    ///   treeship add --dry-run          # show what would be done
    Add(AddArgs),

    /// Guided first-time setup in 90 seconds
    ///
    /// Walks through init, session start, wrapping a command, and creating
    /// a receipt. No flags needed.
    Quickstart,

    /// Set up a new Treeship -- generates a keypair and config
    ///
    /// Run this once on each machine. Your signing key is encrypted at
    /// rest and tied to this machine's identity.
    ///
    /// Examples:
    ///   treeship init
    ///   treeship init --name my-agent-server
    ///   treeship init --config /opt/myapp/.treeship/config.json
    Init(InitArgs),

    /// Show ship state: keys, recent artifacts, hub status
    ///
    /// Examples:
    ///   treeship status
    Status,

    /// Wrap any command -- run it and attest the execution
    ///
    /// The wrapped command's stdin/stdout/stderr pass through unchanged.
    /// An action artifact is signed after it completes, capturing the
    /// actor, command, exit code, and elapsed time.
    ///
    /// Examples:
    ///   treeship wrap -- npm test
    ///   treeship wrap -- go build ./...
    ///   treeship wrap --actor agent://ci -- pytest tests/
    ///   treeship wrap --push -- cargo test
    Wrap(WrapArgs),

    /// Sign an attestation artifact
    ///
    /// Examples:
    ///   treeship attest action --actor agent://me --action tool.call
    ///   treeship attest approval --approver human://alice --description "ok to purchase"
    ///   treeship attest handoff --from agent://a --to agent://b --artifacts art_abc,art_def
    #[command(subcommand)]
    Attest(AttestCommand),

    /// Verify an artifact or its full parent chain
    ///
    /// Walks every artifact in the chain back to its root, checks each
    /// Ed25519 signature, re-derives content-addressed IDs, and enforces
    /// approval nonce binding.
    ///
    /// Exit code 0 = pass, 1 = fail.
    ///
    /// Examples:
    ///   treeship verify art_a1b2c3d4e5f6a1b2
    ///   treeship verify art_a1b2c3d4e5f6a1b2 --no-chain
    ///   treeship verify ./export.treeship
    Verify(VerifyArgs),

    /// Create, export, and import artifact bundles
    ///
    /// Bundles group artifacts into a signed, portable package.
    /// Export as a .treeship file to share proof chains.
    ///
    /// Examples:
    ///   treeship bundle create --artifacts art_a1b2,art_c3d4 --tag v1.0
    ///   treeship bundle export art_e5f6 --out release.treeship
    ///   treeship bundle import release.treeship
    #[command(subcommand)]
    Bundle(BundleCommand),

    /// Manage signing keys
    ///
    /// Examples:
    ///   treeship keys list
    #[command(subcommand)]
    Keys(KeysCommand),

    /// Connect to treeship.dev Hub -- push, pull, and share artifacts
    ///
    /// Examples:
    ///   treeship hub attach
    ///   treeship hub push art_a1b2c3d4e5f6a1b2
    ///   treeship hub pull art_a1b2c3d4e5f6a1b2
    ///   treeship hub status
    ///   treeship hub detach
    #[command(subcommand)]
    Hub(HubCommand),

    /// Install shell hooks for automatic attestation
    ///
    /// Detects your shell (zsh, bash, fish) and appends hooks to
    /// your shell config. After install, matching commands are
    /// attested automatically.
    ///
    /// Examples:
    ///   treeship install
    Install,

    /// Remove shell hooks
    ///
    /// Examples:
    ///   treeship uninstall
    Uninstall,

    /// Shell hook handler (called by shell hooks, not by users directly)
    #[command(hide = true)]
    Hook(HookArgs),

    /// View receipt log
    ///
    /// Lists recent receipts from local storage.
    ///
    /// Examples:
    ///   treeship log
    ///   treeship log --tail 50
    ///   treeship log --follow
    Log(LogArgs),

    /// Manage work sessions
    ///
    /// Sessions group a run of agent work into a single unit with a
    /// start artifact, accumulated receipts, and a close artifact.
    ///
    /// Examples:
    ///   treeship session start --name "fix auth bug"
    ///   treeship session status
    ///   treeship session close --summary "fixed JWT expiry"
    #[command(subcommand)]
    Session(SessionCommand),

    /// Inspect and verify .treeship session packages
    ///
    /// Session packages contain a complete Session Receipt with
    /// Merkle proofs, timeline, and agent graph.
    ///
    /// Examples:
    ///   treeship package inspect .treeship/sessions/ssn_abc.treeship
    ///   treeship package verify .treeship/sessions/ssn_abc.treeship
    #[command(subcommand)]
    Package(PackageCommand),

    /// Declare authorized tool scope for this project
    ///
    /// Creates `.treeship/declaration.json` listing which tools agents
    /// are authorized to use. The session receipt compares declared vs
    /// actual tool usage and flags unauthorized calls.
    ///
    /// Examples:
    ///   treeship declare --tools read_file,write_file,bash
    ///   treeship declare --tools read_file --forbidden deploy,rm
    ///   treeship declare --show
    Declare(DeclareArgs),

    /// Register an agent and produce an Agent Identity Certificate
    ///
    /// Creates a .agent package with identity.json, capabilities.json,
    /// declaration.json, and certificate.html.
    ///
    /// Examples:
    ///   treeship agent register --name claude-code --tools read_file,write_file,bash
    ///   treeship agent register --name hermes --tools web_search --model hermes-2 --valid-days 365
    #[command(subcommand)]
    Agent(AgentCommand),

    /// List pending approvals
    ///
    /// Shows actions that are blocked waiting for human approval.
    ///
    /// Examples:
    ///   treeship pending
    Pending,

    /// Approve a pending action
    ///
    /// Approves the Nth pending action (or the first one if N is omitted).
    /// Creates an ApprovalStatement artifact with a single-use nonce.
    ///
    /// Examples:
    ///   treeship approve
    ///   treeship approve 2
    Approve(ApproveArgs),

    /// Deny a pending action
    ///
    /// Denies the Nth pending action (or the first one if N is omitted).
    ///
    /// Examples:
    ///   treeship deny
    ///   treeship deny 2
    Deny(DenyArgs),

    /// Background daemon for automatic file watching
    ///
    /// The daemon watches your project for file changes and automatically
    /// creates signed receipts for changes matching your rules.
    ///
    /// Examples:
    ///   treeship daemon start
    ///   treeship daemon start --foreground
    ///   treeship daemon stop
    ///   treeship daemon status
    #[command(subcommand)]
    Daemon(DaemonCommand),

    /// Diagnostic check -- verify everything is working
    ///
    /// Checks initialization, keys, config, shell hooks, daemon,
    /// Hub connection, storage, and active sessions.
    ///
    /// Examples:
    ///   treeship doctor
    Doctor,

    /// Create a signed checkpoint of the Merkle tree
    ///
    /// Rebuilds the Merkle tree from all local artifacts, signs the
    /// current root, and stores the checkpoint.
    ///
    /// Examples:
    ///   treeship checkpoint
    Checkpoint,

    /// Merkle tree operations
    ///
    /// Generate inclusion proofs, verify proofs offline, and check
    /// the status of the local Merkle tree.
    ///
    /// Examples:
    ///   treeship merkle proof art_abc123
    ///   treeship merkle verify proof.json
    ///   treeship merkle status
    #[command(subcommand)]
    Merkle(MerkleCommand),

    /// Interactive terminal dashboard
    ///
    /// Opens a full-screen TUI showing session status, recent artifacts,
    /// pending approvals, and hub status. Reads only from local storage.
    ///
    /// Examples:
    ///   treeship ui
    Ui,

    /// OpenTelemetry export -- send artifacts as OTel spans
    ///
    /// Requires the `otel` feature flag at build time.
    /// Configure via environment variables:
    ///   TREESHIP_OTEL_ENDPOINT=http://localhost:4318
    ///   TREESHIP_OTEL_AUTH=Bearer sk-...
    ///   TREESHIP_OTEL_SERVICE=my-agent
    ///
    /// Examples:
    ///   treeship otel test
    ///   treeship otel status
    ///   treeship otel export art_abc123
    #[command(subcommand)]
    Otel(OtelCommand),

    /// List available trust templates
    ///
    /// Shows all official templates grouped by category.
    /// Templates are pre-built attestation configurations for common workflows.
    ///
    /// Examples:
    ///   treeship templates
    Templates,

    /// Template management -- preview, apply, validate, save
    ///
    /// Examples:
    ///   treeship template preview github-contributor
    ///   treeship template apply ci-cd-pipeline
    ///   treeship template validate my-template.yaml
    ///   treeship template save --name my-workflow
    #[command(subcommand)]
    Template(TemplateCommand),

    /// Generate a zero-knowledge proof for an artifact
    ///
    /// Circom circuits prove properties of artifacts without revealing data.
    /// Requires: --features zk build flag, snarkjs installed.
    ///
    /// Examples:
    ///   treeship prove --circuit policy-checker --artifact art_xxx --policy ./policy.json
    ///   treeship prove --circuit input-output-binding --artifact art_xxx
    Prove(ProveArgs),

    /// Prove an entire session chain (RISC Zero, background)
    ///
    /// Examples:
    ///   treeship prove-chain ssn_abc123
    ProveChain(ProveChainArgs),

    /// Verify a zero-knowledge proof file
    ///
    /// Examples:
    ///   treeship verify-proof art_xxx.policy-checker.zkproof
    VerifyProof(VerifyProofArgs),

    /// Show ZK configuration, circuit hashes, and notary status
    ///
    /// Examples:
    ///   treeship zk-setup
    ZkSetup,

    /// Print self-hosted TLSNotary setup instructions
    ///
    /// Examples:
    ///   treeship zk-tls-setup
    ZkTlsSetup,

    /// Print version and build info
    Version,
}

#[derive(Args)]
struct ProveArgs {
    /// Circuit to use: policy-checker, input-output-binding, prompt-template
    #[arg(long, required = true)]
    circuit: String,

    /// Artifact ID to prove (or "last" for most recent)
    #[arg(long, required = true)]
    artifact: String,

    /// Policy file (JSON array of allowed actions) -- required for policy-checker
    #[arg(long, value_name = "PATH")]
    policy: Option<String>,
}

#[derive(Args)]
struct ProveChainArgs {
    /// Session ID to prove
    session_id: String,
}

#[derive(Args)]
struct VerifyProofArgs {
    /// Path to the .zkproof file
    file: String,
}

#[derive(Subcommand)]
enum TemplateCommand {
    /// Preview what a template does without applying it
    ///
    /// Examples:
    ///   treeship template preview github-contributor
    Preview {
        /// Template name
        name: String,
    },
    /// Apply a template to the current project
    ///
    /// Examples:
    ///   treeship template apply ci-cd-pipeline
    Apply {
        /// Template name
        name: String,
    },
    /// Validate a custom template YAML file
    ///
    /// Examples:
    ///   treeship template validate my-template.yaml
    Validate {
        /// Path to template YAML file
        file: String,
    },
    /// Save the current project config as a reusable template
    ///
    /// Examples:
    ///   treeship template save --name my-workflow
    Save(TemplateSaveArgs),
}

#[derive(Args)]
struct TemplateSaveArgs {
    /// Template name (slug)
    #[arg(long, value_name = "NAME")]
    name: Option<String>,
}

#[derive(Subcommand)]
enum MerkleCommand {
    /// Generate an inclusion proof for an artifact
    ///
    /// Examples:
    ///   treeship merkle proof art_abc123
    Proof(MerkleProofArgs),

    /// Verify an inclusion proof (fully offline)
    ///
    /// Examples:
    ///   treeship merkle verify proof.json
    ///   treeship merkle verify sha256:7f3a... proof.json
    Verify(MerkleVerifyArgs),

    /// Show Merkle tree status
    Status,

    /// Publish checkpoint and proofs to Hub
    ///
    /// Examples:
    ///   treeship merkle publish
    Publish,
}

#[derive(Subcommand)]
enum DaemonCommand {
    /// Start the background daemon
    Start {
        /// Run in foreground (don't background)
        #[arg(long, default_value_t = false)]
        foreground: bool,
        /// Disable auto-push to Hub (overrides config)
        #[arg(long, default_value_t = false)]
        no_push: bool,
    },
    /// Stop the background daemon
    Stop,
    /// Check daemon status
    Status,
}

// --- init -------------------------------------------------------------------

#[derive(Args)]
struct InitArgs {
    /// Human-readable name for this ship (optional)
    #[arg(long, value_name = "NAME")]
    name: Option<String>,

    /// Apply a trust template (name or file path)
    #[arg(long, value_name = "TEMPLATE")]
    template: Option<String>,

    /// Overwrite an existing config
    #[arg(long, default_value_t = false)]
    force: bool,
}

// --- hook -------------------------------------------------------------------

#[derive(Args)]
struct HookArgs {
    #[command(subcommand)]
    command: HookCommand,
}

#[derive(Subcommand)]
enum HookCommand {
    /// Pre-execution hook (called before command runs)
    Pre {
        /// The command about to run
        command: String,
    },
    /// Post-execution hook (called after command completes)
    Post {
        /// Exit code of the completed command
        exit_code: i32,
        /// The command that ran (optional)
        command: Option<String>,
    },
}

// --- log --------------------------------------------------------------------

#[derive(Args)]
struct LogArgs {
    /// Watch for new receipts in real time
    #[arg(long, default_value_t = false)]
    follow: bool,

    /// Number of recent receipts to show
    #[arg(long, default_value_t = 20)]
    tail: usize,
}

// --- session ----------------------------------------------------------------

#[derive(Subcommand)]
enum SessionCommand {
    /// Start a new work session
    ///
    /// Creates a session manifest and a session-start artifact.
    ///
    /// Examples:
    ///   treeship session start
    ///   treeship session start --name "fix auth bug" --actor agent://coder
    Start(SessionStartArgs),

    /// Show active session info
    ///
    /// With --watch, polls the event log every 2 seconds and renders
    /// a live terminal UI showing agents, events, and security status.
    Status(SessionStatusArgs),

    /// Close the active session
    ///
    /// Examples:
    ///   treeship session close
    ///   treeship session close --summary "fixed JWT expiry bug"
    Close(SessionCloseArgs),

    /// Upload a session receipt to the configured hub
    ///
    /// Reads the .treeship package generated by `session close` and PUTs
    /// the receipt to the hub. Defaults to the most recently closed session
    /// if no session_id is given. Prints the public, permanent receipt URL.
    ///
    /// Examples:
    ///   treeship session report
    ///   treeship session report ssn_01HR
    Report(SessionReportArgs),

    /// Append a structured event to the active session's event log.
    ///
    /// Used by integrations (MCP bridge, A2A bridge, SDKs) to record
    /// tool calls, file operations, and other session activity so it
    /// appears in the receipt timeline and side effects.
    ///
    /// Examples:
    ///   treeship session event --type agent.called_tool --tool read_file --format json
    ///   treeship session event --type agent.wrote_file --file src/main.rs
    Event(SessionEventArgs),
}

#[derive(Args)]
struct SessionStatusArgs {
    /// Watch mode: poll the event log every 2 seconds and render a live TUI
    #[arg(long)]
    watch: bool,

    /// Quiet check: print nothing, exit 0 if a session is active, exit 1 otherwise.
    /// Designed for shell-script gating (hooks, monitors, CI).
    #[arg(long)]
    check: bool,
}

#[derive(Args)]
struct SessionReportArgs {
    /// Session ID to report (defaults to the most recently closed session)
    session_id: Option<String>,
}

#[derive(Args)]
struct SessionEventArgs {
    /// Event type (e.g. agent.called_tool, agent.wrote_file, agent.read_file,
    /// agent.connected_network, agent.decision)
    #[arg(long, value_name = "TYPE")]
    r#type: String,

    /// Tool name (for agent.called_tool events)
    #[arg(long, value_name = "NAME")]
    tool: Option<String>,

    /// File path (for agent.wrote_file / agent.read_file events)
    #[arg(long, value_name = "PATH")]
    file: Option<String>,

    /// Network destination (for agent.connected_network events)
    #[arg(long, value_name = "HOST")]
    destination: Option<String>,

    /// Actor URI (default: reads from session manifest)
    #[arg(long, value_name = "URI")]
    actor: Option<String>,

    /// Agent name for the event
    #[arg(long, value_name = "NAME")]
    agent_name: Option<String>,

    /// Duration in milliseconds
    #[arg(long, value_name = "MS")]
    duration_ms: Option<u64>,

    /// Exit code or error indicator (0 = success)
    #[arg(long, value_name = "CODE")]
    exit_code: Option<i32>,

    /// Artifact ID to reference
    #[arg(long, value_name = "ID")]
    artifact_id: Option<String>,

    /// Arbitrary JSON metadata
    #[arg(long, value_name = "JSON")]
    meta: Option<String>,
}

#[derive(Args)]
struct SessionStartArgs {
    /// Human-readable name for this session
    #[arg(long, value_name = "NAME")]
    name: Option<String>,

    /// Actor URI (default: ship://<your-ship-id>)
    #[arg(long, value_name = "URI")]
    actor: Option<String>,
}

#[derive(Args)]
struct SessionCloseArgs {
    /// Summary of what was accomplished
    #[arg(long, value_name = "TEXT")]
    summary: Option<String>,

    /// One-line headline for the receipt (e.g. "Verifier refactor completed.")
    #[arg(long, value_name = "TEXT")]
    headline: Option<String>,

    /// What should be reviewed before trusting the output
    #[arg(long, value_name = "TEXT")]
    review: Option<String>,
}

// --- package ---------------------------------------------------------------

#[derive(Subcommand)]
enum PackageCommand {
    /// Inspect a .treeship session package
    ///
    /// Shows the full Session Receipt contents: participants, agent graph,
    /// timeline, side effects, and Merkle proof status.
    ///
    /// Examples:
    ///   treeship package inspect .treeship/sessions/ssn_abc.treeship
    Inspect(PackagePathArgs),

    /// Verify a .treeship session package
    ///
    /// Runs local verification checks: receipt parsing, Merkle root
    /// recomputation, inclusion proof validation, and timeline ordering.
    ///
    /// Examples:
    ///   treeship package verify .treeship/sessions/ssn_abc.treeship
    Verify(PackagePathArgs),
}

#[derive(Args)]
struct PackagePathArgs {
    /// Path to the .treeship package directory
    path: std::path::PathBuf,
}

// --- add -------------------------------------------------------------------

#[derive(Args)]
struct AddArgs {
    /// Specific agent frameworks to instrument (e.g. claude-code hermes)
    agents: Vec<String>,

    /// Instrument all detected agents without prompting
    #[arg(long)]
    all: bool,

    /// Show what would be done without making changes
    #[arg(long)]
    dry_run: bool,
}

// --- agent -----------------------------------------------------------------

#[derive(Subcommand)]
enum AgentCommand {
    /// Register an agent and create an Identity Certificate
    Register(AgentRegisterArgs),
}

#[derive(Args)]
struct AgentRegisterArgs {
    /// Agent name (e.g. "claude-code", "hermes")
    #[arg(long, value_name = "NAME")]
    name: String,

    /// Comma-separated list of authorized tool names
    #[arg(long, value_name = "TOOLS", value_delimiter = ',')]
    tools: Vec<String>,

    /// Model name (e.g. "claude-opus-4-6")
    #[arg(long, value_name = "MODEL")]
    model: Option<String>,

    /// Certificate validity in days (default: 365)
    #[arg(long, value_name = "DAYS", default_value = "365")]
    valid_days: u32,

    /// Agent description
    #[arg(long, value_name = "TEXT")]
    description: Option<String>,

    /// Comma-separated list of forbidden actions
    #[arg(long, value_name = "ACTIONS", value_delimiter = ',')]
    forbidden: Vec<String>,

    /// Comma-separated list of actions requiring escalation
    #[arg(long, value_name = "ACTIONS", value_delimiter = ',')]
    escalation: Vec<String>,
}

// --- declare ---------------------------------------------------------------

#[derive(Args)]
struct DeclareArgs {
    /// Comma-separated list of authorized tool names
    #[arg(long, value_name = "TOOLS", value_delimiter = ',')]
    tools: Vec<String>,

    /// Comma-separated list of forbidden tool names
    #[arg(long, value_name = "TOOLS", value_delimiter = ',')]
    forbidden: Vec<String>,

    /// Comma-separated list of tools requiring escalation/approval
    #[arg(long, value_name = "TOOLS", value_delimiter = ',')]
    escalation: Vec<String>,

    /// ISO-8601 timestamp when this declaration expires
    #[arg(long, value_name = "TIMESTAMP")]
    valid_until: Option<String>,

    /// Show the current declaration instead of creating one
    #[arg(long)]
    show: bool,
}

// --- approve / deny ---------------------------------------------------------

#[derive(Args)]
struct ApproveArgs {
    /// Index of the pending approval to approve (default: 1)
    #[arg(value_name = "N")]
    n: Option<usize>,
}

#[derive(Args)]
struct DenyArgs {
    /// Index of the pending approval to deny (default: 1)
    #[arg(value_name = "N")]
    n: Option<usize>,
}

// --- wrap -------------------------------------------------------------------

#[derive(Args)]
struct WrapArgs {
    /// Actor URI (default: ship://<your-ship-id>)
    ///
    /// Examples: agent://researcher  human://alice  ship://my-server
    #[arg(long, value_name = "URI")]
    actor: Option<String>,

    /// Action label (default: executable name)
    ///
    /// Examples: test.run  build.cargo  deploy.production
    #[arg(long, value_name = "LABEL")]
    action: Option<String>,

    /// Parent artifact ID -- links this into a chain
    #[arg(long, value_name = "ID")]
    parent: Option<String>,

    /// Push the artifact to Hub immediately after attesting
    #[arg(long, default_value_t = false)]
    push: bool,

    /// The command to run (everything after --)
    #[arg(last = true, required = true, value_name = "CMD")]
    cmd: Vec<String>,
}

// --- attest -----------------------------------------------------------------

#[derive(Subcommand)]
enum AttestCommand {
    /// Record that an actor performed an action
    ///
    /// Examples:
    ///   treeship attest action --actor agent://researcher --action tool.call
    ///   treeship attest action --actor agent://checkout --action stripe.charge.create \
    ///     --input-digest sha256:abc123 --output-digest sha256:def456 \
    ///     --parent art_a1b2c3d4 --approval-nonce abc123xyz
    Action(AttestActionArgs),

    /// Record that an approver authorized an intent
    ///
    /// A random nonce is generated automatically. The consuming action
    /// must echo this nonce in --approval-nonce to prevent approval reuse.
    ///
    /// Examples:
    ///   treeship attest approval --approver human://alice \
    ///     --description "approve laptop purchase < $1500" --expires 2026-03-26T11:00:00Z
    Approval(AttestApprovalArgs),

    /// Record a work handoff between actors
    ///
    /// Examples:
    ///   treeship attest handoff --from agent://researcher --to agent://checkout \
    ///     --artifacts art_a1b2,art_c3d4 --approvals art_e5f6
    Handoff(AttestHandoffArgs),

    /// Record an external system receipt (webhook, timestamp, confirmation)
    ///
    /// Examples:
    ///   treeship attest receipt --system system://stripe-webhook \
    ///     --kind confirmation --subject art_a1b2 \
    ///     --payload '{"eventId":"evt_abc","status":"succeeded"}'
    Receipt(AttestReceiptArgs),

    /// Record an agent's reasoning and decision context
    ///
    /// Examples:
    ///   treeship attest decision --actor agent://analyst --model claude-opus-4 \
    ///     --tokens-in 8432 --tokens-out 1247 \
    ///     --summary "Contract analysis complete. Standard terms." --confidence 0.91
    Decision(AttestDecisionArgs),

    /// Record an endorsement of an existing artifact
    ///
    /// Used for post-hoc validation, compliance sign-off, countersignatures.
    ///
    /// Examples:
    ///   treeship attest endorsement --endorser human://auditor --subject art_a1b2 --kind validation
    ///   treeship attest endorsement --endorser human://compliance --subject art_c3d4 \
    ///     --kind compliance --rationale "Meets SOC-2 requirements" \
    ///     --expires 2026-12-31T00:00:00Z --policy-ref https://example.com/policy
    Endorsement(AttestEndorsementArgs),
}

#[derive(Args)]
struct AttestActionArgs {
    /// Actor URI -- who performed the action
    #[arg(long, required = true, value_name = "URI")]
    actor: String,

    /// Action label -- what was done
    #[arg(long, required = true, value_name = "LABEL")]
    action: String,

    /// SHA-256 digest of the input consumed
    #[arg(long, value_name = "sha256:HEX")]
    input_digest: Option<String>,

    /// SHA-256 digest of the output produced
    #[arg(long, value_name = "sha256:HEX")]
    output_digest: Option<String>,

    /// URI to referenced content (for large/external payloads)
    #[arg(long, value_name = "URI")]
    content_uri: Option<String>,

    /// Parent artifact ID -- links this into a chain
    #[arg(long, value_name = "ID")]
    parent: Option<String>,

    /// Must match the nonce on the approval authorising this action
    #[arg(long, value_name = "NONCE")]
    approval_nonce: Option<String>,

    /// Extra metadata as a JSON object
    #[arg(long, value_name = r#"'{"key":"val"}'"#)]
    meta: Option<String>,

    /// Write the raw DSSE envelope to a file (- for stdout)
    #[arg(long, value_name = "PATH")]
    out: Option<String>,
}

#[derive(Args)]
struct AttestApprovalArgs {
    /// Approver URI
    #[arg(long, required = true, value_name = "URI")]
    approver: String,

    /// Artifact ID being approved
    #[arg(long, value_name = "ID")]
    subject: Option<String>,

    /// Human-readable description of what was approved
    #[arg(long, value_name = "TEXT")]
    description: Option<String>,

    /// Expiry as ISO 8601 timestamp
    #[arg(long, value_name = "TIMESTAMP")]
    expires: Option<String>,
}

#[derive(Args)]
struct AttestHandoffArgs {
    /// Source actor URI
    #[arg(long, required = true, value_name = "URI")]
    from: String,

    /// Destination actor URI
    #[arg(long, required = true, value_name = "URI")]
    to: String,

    /// Comma-separated artifact IDs being transferred
    #[arg(long, required = true, value_delimiter = ',', value_name = "IDS")]
    artifacts: Vec<String>,

    /// Comma-separated approval IDs the receiver inherits
    #[arg(long, value_delimiter = ',', value_name = "IDS")]
    approvals: Vec<String>,

    /// Comma-separated obligations the receiver must satisfy
    #[arg(long, value_delimiter = ',', value_name = "TEXT")]
    obligations: Vec<String>,
}

#[derive(Args)]
struct AttestReceiptArgs {
    /// System URI -- who produced this receipt
    #[arg(long, required = true, value_name = "URI")]
    system: String,

    /// Receipt kind: confirmation | timestamp | inclusion | webhook
    #[arg(long, required = true, value_name = "KIND")]
    kind: String,

    /// Subject artifact ID
    #[arg(long, value_name = "ID")]
    subject: Option<String>,

    /// Receipt payload as a JSON object
    #[arg(long, value_name = r#"'{"key":"val"}'"#)]
    payload: Option<String>,
}

#[derive(Args)]
struct AttestDecisionArgs {
    /// Actor URI -- who made the decision
    #[arg(long, required = true, value_name = "URI")]
    actor: String,

    /// Model used for inference (e.g. claude-opus-4)
    #[arg(long, value_name = "MODEL")]
    model: Option<String>,

    /// Model version if known
    #[arg(long, value_name = "VERSION")]
    model_version: Option<String>,

    /// Number of input tokens consumed
    #[arg(long, value_name = "N")]
    tokens_in: Option<u64>,

    /// Number of output tokens produced
    #[arg(long, value_name = "N")]
    tokens_out: Option<u64>,

    /// SHA-256 digest of the full prompt
    #[arg(long, value_name = "sha256:HEX")]
    prompt_digest: Option<String>,

    /// Human-readable summary of the decision
    #[arg(long, value_name = "TEXT")]
    summary: Option<String>,

    /// Confidence level 0.0-1.0
    #[arg(long, value_name = "FLOAT")]
    confidence: Option<f64>,

    /// Parent artifact ID -- links this into a chain
    #[arg(long, value_name = "ID")]
    parent: Option<String>,
}

#[derive(Args)]
struct AttestEndorsementArgs {
    /// Endorser URI -- who is endorsing
    #[arg(long, required = true, value_name = "URI")]
    endorser: String,

    /// Subject artifact ID being endorsed
    #[arg(long, required = true, value_name = "ID")]
    subject: String,

    /// Endorsement kind: validation, compliance, countersignature, review
    #[arg(long, required = true, value_name = "KIND")]
    kind: String,

    /// Human-readable rationale for the endorsement
    #[arg(long, value_name = "TEXT")]
    rationale: Option<String>,

    /// Expiration timestamp (RFC 3339)
    #[arg(long, value_name = "TIMESTAMP")]
    expires: Option<String>,

    /// URI to the governing policy document
    #[arg(long, value_name = "URI")]
    policy_ref: Option<String>,

    /// Extra metadata as a JSON object
    #[arg(long, value_name = r#"'{"key":"val"}'"#)]
    meta: Option<String>,

    /// Parent artifact ID -- links this into a chain
    #[arg(long, value_name = "ID")]
    parent: Option<String>,

    /// Write the raw DSSE envelope to a file (- for stdout)
    #[arg(long, value_name = "PATH")]
    out: Option<String>,
}

// --- bundle -----------------------------------------------------------------

#[derive(Subcommand)]
enum BundleCommand {
    /// Create a bundle from a list of artifacts
    ///
    /// Examples:
    ///   treeship bundle create --artifacts art_a1b2,art_c3d4
    ///   treeship bundle create --artifacts art_a1b2,art_c3d4 --tag v1.0
    Create(BundleCreateArgs),

    /// Export a bundle to a portable .treeship file
    ///
    /// Examples:
    ///   treeship bundle export art_e5f6 --out release.treeship
    Export(BundleExportArgs),

    /// Import a .treeship file into local storage
    ///
    /// Examples:
    ///   treeship bundle import release.treeship
    Import(BundleImportArgs),
}

#[derive(Args)]
struct BundleCreateArgs {
    /// Comma-separated artifact IDs to include
    #[arg(long, required = true, value_delimiter = ',', value_name = "IDS")]
    artifacts: Vec<String>,

    /// Human-readable tag for this bundle
    #[arg(long, value_name = "TAG")]
    tag: Option<String>,

    /// Description of what this bundle contains
    #[arg(long, value_name = "TEXT")]
    description: Option<String>,
}

#[derive(Args)]
struct BundleExportArgs {
    /// Bundle artifact ID to export
    bundle_id: String,

    /// Output file path
    #[arg(long, required = true, value_name = "PATH")]
    out: String,
}

#[derive(Args)]
struct BundleImportArgs {
    /// Path to .treeship file
    file: String,
}

// --- verify -----------------------------------------------------------------

#[derive(Args)]
struct VerifyArgs {
    /// What to verify: artifact ID, path to a .treeship/.agent package, or a
    /// receipt URL (http:// or https://). Use the global --quiet for
    /// exit-code-only output and --format json for machine-readable output.
    target: String,

    /// Cross-verify against an Agent Certificate (path to a .agent package
    /// or a URL serving the certificate JSON).
    #[arg(long, value_name = "PATH-OR-URL")]
    certificate: Option<String>,

    /// Verify only this artifact, do not walk the parent chain.
    /// Only applies to the artifact-ID form.
    #[arg(long, default_value_t = false)]
    no_chain: bool,

    /// Maximum chain depth to walk (default: 20).
    /// Only applies to the artifact-ID form.
    #[arg(long, default_value_t = 20, value_name = "N")]
    max_depth: usize,

    /// Show full chain timeline with box-drawn cards.
    /// Only applies to the artifact-ID form.
    #[arg(long, default_value_t = false)]
    full: bool,
}

// --- keys -------------------------------------------------------------------

#[derive(Subcommand)]
enum KeysCommand {
    /// List all signing keys
    List,
}

// --- hub --------------------------------------------------------------------

#[derive(Subcommand)]
enum HubCommand {
    /// Attach to Hub (creates new hub connection or reconnects to existing)
    ///
    /// Examples:
    ///   treeship hub attach
    ///   treeship hub attach --name acme-corp
    ///   treeship hub attach --endpoint http://localhost:8080
    Attach(HubAttachArgs),

    /// Detach active hub connection (keeps keys for reconnect)
    ///
    /// Examples:
    ///   treeship hub detach
    Detach,

    /// List all known hub connections
    ///
    /// Examples:
    ///   treeship hub ls
    Ls,

    /// Show active hub connection status
    ///
    /// Examples:
    ///   treeship hub status
    Status,

    /// Switch active hub connection
    ///
    /// Examples:
    ///   treeship hub use work
    ///   treeship hub use hub_a2b3c4d5e6f7
    Use(HubUseArgs),

    /// Push a signed artifact to Hub
    ///
    /// Examples:
    ///   treeship hub push art_a1b2c3d4
    ///   treeship hub push last --hub acme-corp
    ///   treeship hub push art_a1b2c3d4 --all
    Push(HubPushArgs),

    /// Pull an artifact from Hub into local storage
    ///
    /// Examples:
    ///   treeship hub pull art_a1b2c3d4
    ///   treeship hub pull art_a1b2c3d4 --hub acme-corp
    Pull(HubPullArgs),

    /// Open workspace in browser
    ///
    /// Examples:
    ///   treeship hub open
    ///   treeship hub open --hub acme-corp
    Open(HubOpenArgs),

    /// Remove a hub connection (revokes + deletes local keys)
    ///
    /// Examples:
    ///   treeship hub kill acme-corp
    Kill(HubKillArgs),
}

#[derive(Args)]
struct HubAttachArgs {
    /// Name for this hub connection (default: "default")
    #[arg(long, value_name = "NAME")]
    name: Option<String>,

    /// Hub API endpoint (default: https://api.treeship.dev)
    #[arg(long, value_name = "URL")]
    endpoint: Option<String>,
}

#[derive(Args)]
struct HubUseArgs {
    /// Hub connection name or hub ID to switch to
    name_or_id: String,
}

#[derive(Args)]
struct HubPushArgs {
    /// Artifact ID to push (or "last" for most recent)
    id: String,

    /// Push to a specific hub connection by name or ID
    #[arg(long, value_name = "NAME|ID")]
    hub: Option<String>,

    /// Push to all known hub connections
    #[arg(long)]
    all: bool,
}

#[derive(Args)]
struct HubPullArgs {
    /// Artifact ID to pull
    id: String,

    /// Pull from a specific hub connection by name or ID
    #[arg(long, value_name = "NAME|ID")]
    hub: Option<String>,
}

#[derive(Args)]
struct HubOpenArgs {
    /// Open workspace for a specific hub connection
    #[arg(long, value_name = "NAME|ID")]
    hub: Option<String>,

    /// Print URL only, don't open browser
    #[arg(long)]
    no_open: bool,
}

#[derive(Args)]
struct HubKillArgs {
    /// Hub connection name to remove
    name: String,

    /// Skip confirmation prompt
    #[arg(long)]
    force: bool,
}

// --- merkle -----------------------------------------------------------------

#[derive(Args)]
struct MerkleProofArgs {
    /// Artifact ID to generate proof for
    artifact_id: String,
}

#[derive(Args)]
struct MerkleVerifyArgs {
    /// Path to proof.json file (or expected root hash followed by path)
    ///
    /// If two arguments: first is expected root hash, second is proof file.
    /// If one argument: just the proof file (root taken from proof itself).
    args: Vec<String>,
}

// --- otel -------------------------------------------------------------------

#[derive(Subcommand)]
enum OtelCommand {
    /// Test OTel connectivity -- sends a single test span
    ///
    /// Examples:
    ///   treeship otel test
    Test,

    /// Show current OTel configuration
    ///
    /// Examples:
    ///   treeship otel status
    Status,

    /// Export a specific artifact to OTel
    ///
    /// Examples:
    ///   treeship otel export art_abc123
    Export(OtelExportArgs),

    /// Show how to enable OTel export
    Enable,

    /// Show how to disable OTel export
    Disable,
}

#[derive(Args)]
struct OtelExportArgs {
    /// Artifact ID to export
    id: String,
}

// --- main -------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    let format  = Format::from_str(&cli.format);
    let printer = Printer::new(format, cli.quiet, cli.no_color);

    if let Err(e) = dispatch(&cli, &printer) {
        printer.failure(&e.to_string(), &[]);
        std::process::exit(exit_code(&e.to_string()));
    }
}

fn dispatch(cli: &Cli, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    match &cli.command {

        Command::Ui => tui::run(cli.config.as_deref()),

        Command::Otel(sub) => {
            #[cfg(feature = "otel")]
            {
                match sub {
                    OtelCommand::Test => commands::otel::test_connection(
                        cli.config.as_deref(), printer,
                    )?,
                    OtelCommand::Status => commands::otel::status(printer),
                    OtelCommand::Export(a) => commands::otel::export_artifact(
                        &a.id, cli.config.as_deref(), printer,
                    )?,
                    OtelCommand::Enable => commands::otel::enable(printer),
                    OtelCommand::Disable => commands::otel::disable(printer),
                }
            }
            #[cfg(not(feature = "otel"))]
            {
                let _ = sub; // suppress unused warning
                commands::otel::not_available(printer);
            }
            Ok(())
        }

        Command::Templates => {
            commands::template::list(printer);
            Ok(())
        }

        Command::Template(sub) => match sub {
            TemplateCommand::Preview { name } => commands::template::preview(name, printer),
            TemplateCommand::Apply { name } => commands::template::apply(name, printer),
            TemplateCommand::Validate { file } => commands::template::validate(file, printer),
            TemplateCommand::Save(a) => commands::template::save(a.name.clone(), printer),
        },

        Command::Prove(a) => commands::prove::prove_circuit(
            &a.circuit,
            &a.artifact,
            a.policy.as_deref(),
            cli.config.as_deref(),
            printer,
        ),

        Command::ProveChain(a) => commands::prove::prove_chain(
            &a.session_id,
            cli.config.as_deref(),
            printer,
        ),

        Command::VerifyProof(a) => commands::prove::verify_proof(
            &a.file,
            printer,
        ),

        Command::ZkSetup => commands::zk::setup(printer),
        Command::ZkTlsSetup => commands::zk::tls_notary_setup(printer),

        Command::Version => {
            println!("treeship {} (rust)", env!("CARGO_PKG_VERSION"));
            Ok(())
        }

        Command::Add(a) => commands::add::run(
            a.agents.clone(),
            a.all,
            a.dry_run,
            printer,
        ),

        Command::Quickstart => commands::quickstart::run(
            cli.config.as_deref(),
            printer,
        ),

        Command::Init(a) => commands::init::run(
            a.name.clone(), cli.config.clone(), a.force, a.template.clone(), printer,
        ),

        Command::Status => commands::status::run(cli.config.as_deref(), printer),

        Command::Wrap(a) => commands::wrap::run(
            a.actor.clone(),
            a.action.clone(),
            a.parent.clone(),
            a.push,
            cli.config.as_deref(),
            &a.cmd,
            printer,
        ),

        Command::Install => commands::install::install(printer),

        Command::Uninstall => commands::install::uninstall(printer),

        Command::Hook(a) => match &a.command {
            HookCommand::Pre { command } => commands::hook::pre(command, printer),
            HookCommand::Post { exit_code, command } => commands::hook::post(
                *exit_code,
                command.as_deref(),
                cli.config.as_deref(),
                printer,
            ),
        },

        Command::Log(a) => commands::log::run(
            a.follow,
            a.tail,
            cli.config.as_deref(),
            printer,
        ),

        Command::Session(sub) => match sub {
            SessionCommand::Start(a) => commands::session::start(
                a.name.clone(),
                a.actor.clone(),
                cli.config.as_deref(),
                printer,
            ),
            SessionCommand::Status(a) => {
                if a.check {
                    commands::session::status_check()
                } else if a.watch {
                    commands::session::watch(cli.config.as_deref(), printer)
                } else {
                    commands::session::status(cli.config.as_deref(), printer)
                }
            },
            SessionCommand::Close(a) => commands::session::close(
                a.summary.clone(),
                a.headline.clone(),
                a.review.clone(),
                cli.config.as_deref(),
                printer,
            ),
            SessionCommand::Report(a) => commands::session::report(
                a.session_id.clone(),
                cli.config.as_deref(),
                printer,
            ),
            SessionCommand::Event(a) => commands::session::event(
                &a.r#type,
                a.tool.as_deref(),
                a.file.as_deref(),
                a.destination.as_deref(),
                a.actor.as_deref(),
                a.agent_name.as_deref(),
                a.duration_ms,
                a.exit_code,
                a.artifact_id.as_deref(),
                a.meta.as_deref(),
                printer,
            ),
        },

        Command::Package(sub) => match sub {
            PackageCommand::Inspect(a) => commands::package::inspect(
                a.path.clone(),
                printer,
            ),
            PackageCommand::Verify(a) => commands::package::verify(
                a.path.clone(),
                printer,
            ),
        },

        Command::Declare(a) => {
            if a.show {
                commands::declare::show(printer)
            } else {
                commands::declare::create(a.tools.clone(), a.forbidden.clone(), a.escalation.clone(), a.valid_until.clone(), printer)
            }
        },

        Command::Agent(sub) => match sub {
            AgentCommand::Register(a) => commands::agent::register(
                &a.name,
                a.tools.clone(),
                a.model.clone(),
                a.valid_days,
                a.description.clone(),
                a.forbidden.clone(),
                a.escalation.clone(),
                cli.config.as_deref(),
                printer,
            ),
        },

        Command::Pending => commands::approve::pending(printer),

        Command::Approve(a) => commands::approve::approve(
            a.n,
            cli.config.as_deref(),
            printer,
        ),

        Command::Deny(a) => commands::approve::deny(
            a.n,
            cli.config.as_deref(),
            printer,
        ),

        Command::Daemon(sub) => match sub {
            DaemonCommand::Start { foreground, no_push } => commands::daemon::start(
                cli.config.as_deref(),
                *foreground,
                *no_push,
                printer,
            ),
            DaemonCommand::Stop => commands::daemon::stop(printer),
            DaemonCommand::Status => commands::daemon::status(printer),
        },

        Command::Doctor => commands::doctor::run(cli.config.as_deref(), printer),

        Command::Attest(sub) => match sub {
            AttestCommand::Action(a) => {
                commands::attest::action(commands::attest::ActionArgs {
                    actor:          a.actor.clone(),
                    action:         a.action.clone(),
                    input_digest:   a.input_digest.clone(),
                    output_digest:  a.output_digest.clone(),
                    content_uri:    a.content_uri.clone(),
                    parent_id:      a.parent.clone(),
                    approval_nonce: a.approval_nonce.clone(),
                    meta:           a.meta.clone(),
                    out:            a.out.clone(),
                    config:         cli.config.clone(),
                }, printer)?;
                Ok(())
            }
            AttestCommand::Approval(a) => commands::attest::approval(
                commands::attest::ApprovalArgs {
                    approver:    a.approver.clone(),
                    subject_id:  a.subject.clone(),
                    description: a.description.clone(),
                    expires:     a.expires.clone(),
                    config:      cli.config.clone(),
                },
                printer,
            ),
            AttestCommand::Handoff(a) => commands::attest::handoff(
                commands::attest::HandoffArgs {
                    from:        a.from.clone(),
                    to:          a.to.clone(),
                    artifacts:   a.artifacts.clone(),
                    approvals:   a.approvals.clone(),
                    obligations: a.obligations.clone(),
                    config:      cli.config.clone(),
                },
                printer,
            ),
            AttestCommand::Receipt(a) => commands::attest::receipt(
                commands::attest::ReceiptArgs {
                    system:     a.system.clone(),
                    kind:       a.kind.clone(),
                    subject_id: a.subject.clone(),
                    payload:    a.payload.clone(),
                    config:     cli.config.clone(),
                },
                printer,
            ),
            AttestCommand::Decision(a) => commands::attest::decision(
                commands::attest::DecisionArgs {
                    actor:         a.actor.clone(),
                    model:         a.model.clone(),
                    model_version: a.model_version.clone(),
                    tokens_in:     a.tokens_in,
                    tokens_out:    a.tokens_out,
                    prompt_digest: a.prompt_digest.clone(),
                    summary:       a.summary.clone(),
                    confidence:    a.confidence,
                    parent_id:     a.parent.clone(),
                    config:        cli.config.clone(),
                },
                printer,
            ),
            AttestCommand::Endorsement(a) => commands::attest::endorsement(
                commands::attest::EndorsementArgs {
                    endorser:   a.endorser.clone(),
                    subject_id: a.subject.clone(),
                    kind:       a.kind.clone(),
                    rationale:  a.rationale.clone(),
                    expires:    a.expires.clone(),
                    policy_ref: a.policy_ref.clone(),
                    meta:       a.meta.clone(),
                    parent_id:  a.parent.clone(),
                    out:        a.out.clone(),
                    config:     cli.config.clone(),
                },
                printer,
            ),
        },

        Command::Bundle(sub) => match sub {
            BundleCommand::Create(a) => commands::bundle::create(
                commands::bundle::CreateArgs {
                    artifacts:   a.artifacts.clone(),
                    tag:         a.tag.clone(),
                    description: a.description.clone(),
                    config:      cli.config.clone(),
                },
                printer,
            ),
            BundleCommand::Export(a) => commands::bundle::export(
                commands::bundle::ExportArgs {
                    bundle_id: a.bundle_id.clone(),
                    out:       a.out.clone(),
                    config:    cli.config.clone(),
                },
                printer,
            ),
            BundleCommand::Import(a) => commands::bundle::import(
                commands::bundle::ImportArgs {
                    file:   a.file.clone(),
                    config: cli.config.clone(),
                },
                printer,
            ),
        },

        Command::Verify(a) => {
            // External targets (URL, file path to a .treeship/.agent package)
            // and the cross-verification path go through verify_external.
            // Bare artifact IDs continue through the existing local-storage path.
            if commands::verify_external::is_url(&a.target)
                || commands::verify_external::is_local_path(&a.target)
                || a.certificate.is_some()
            {
                let exit = commands::verify_external::run(
                    &a.target,
                    a.certificate.as_deref(),
                    printer,
                );
                if exit != commands::verify_external::ExternalExit::Ok {
                    std::process::exit(exit.code());
                }
                Ok(())
            } else {
                commands::verify::run(
                    &a.target, a.no_chain, a.max_depth, a.full, cli.config.as_deref(), printer,
                )
            }
        }

        Command::Keys(sub) => match sub {
            KeysCommand::List => commands::keys::list(cli.config.as_deref(), printer),
        },

        Command::Hub(sub) => match sub {
            HubCommand::Attach(a) => commands::hub::attach(
                a.name.as_deref(),
                a.endpoint.as_deref(),
                cli.config.as_deref(),
                printer,
            ),
            HubCommand::Detach => commands::hub::detach(
                cli.config.as_deref(),
                printer,
            ),
            HubCommand::Ls => commands::hub::ls(
                cli.config.as_deref(),
                printer,
            ),
            HubCommand::Status => commands::hub::status(
                cli.config.as_deref(),
                printer,
            ),
            HubCommand::Use(a) => commands::hub::use_hub(
                &a.name_or_id,
                cli.config.as_deref(),
                printer,
            ),
            HubCommand::Push(a) => commands::hub::push(
                &a.id,
                a.hub.as_deref(),
                a.all,
                cli.config.as_deref(),
                printer,
            ),
            HubCommand::Pull(a) => commands::hub::pull(
                &a.id,
                a.hub.as_deref(),
                cli.config.as_deref(),
                printer,
            ),
            HubCommand::Open(a) => commands::hub::open(
                a.hub.as_deref(),
                a.no_open,
                cli.config.as_deref(),
                printer,
            ),
            HubCommand::Kill(a) => commands::hub::kill(
                &a.name,
                a.force,
                cli.config.as_deref(),
                printer,
            ),
        },

        Command::Checkpoint => commands::merkle::checkpoint(
            cli.config.as_deref(),
            printer,
        ),

        Command::Merkle(sub) => match sub {
            MerkleCommand::Proof(a) => commands::merkle::proof(
                &a.artifact_id,
                cli.config.as_deref(),
                printer,
            ),
            MerkleCommand::Verify(a) => {
                let (root, path) = if a.args.len() == 2 {
                    (Some(a.args[0].as_str()), a.args[1].as_str())
                } else if a.args.len() == 1 {
                    (None, a.args[0].as_str())
                } else {
                    return Err("usage: treeship merkle verify [root] <proof.json>".into());
                };
                commands::merkle::verify(root, path, printer)
            },
            MerkleCommand::Status => commands::merkle::status(
                cli.config.as_deref(),
                printer,
            ),
            MerkleCommand::Publish => commands::merkle::publish(
                cli.config.as_deref(),
                printer,
            ),
        },
    }
}

fn exit_code(msg: &str) -> i32 {
    if msg.contains("not initialized") || msg.contains("treeship init") { 3 }
    else if msg.contains("required") || msg.contains("no command given") { 4 }
    else { 1 }
}
