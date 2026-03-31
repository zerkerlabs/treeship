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
    after_help = "Docs: https://treeship.dev/docs   Dock: treeship dock login",
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

    /// Show ship state: keys, recent artifacts, dock status
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
    ///   treeship dock login
    ///   treeship dock push art_a1b2c3d4e5f6a1b2
    ///   treeship dock pull art_a1b2c3d4e5f6a1b2
    ///   treeship dock status
    ///   treeship dock undock
    #[command(subcommand)]
    Dock(DockCommand),

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
    /// pending approvals, and dock status. Reads only from local storage.
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

    /// Print version and build info
    Version,
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
    Status,

    /// Close the active session
    ///
    /// Examples:
    ///   treeship session close
    ///   treeship session close --summary "fixed JWT expiry bug"
    Close(SessionCloseArgs),
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
    /// Artifact ID or path to a .treeship bundle file
    target: String,

    /// Verify only this artifact, do not walk the parent chain
    #[arg(long, default_value_t = false)]
    no_chain: bool,

    /// Maximum chain depth to walk (default: 20)
    #[arg(long, default_value_t = 20, value_name = "N")]
    max_depth: usize,

    /// Show full chain timeline with box-drawn cards
    #[arg(long, default_value_t = false)]
    full: bool,
}

// --- keys -------------------------------------------------------------------

#[derive(Subcommand)]
enum KeysCommand {
    /// List all signing keys
    List,
}

// --- dock -------------------------------------------------------------------

#[derive(Subcommand)]
enum DockCommand {
    /// Authenticate with treeship.dev Hub using device flow
    ///
    /// Generates a fresh Ed25519 dock keypair and links this ship to
    /// the Hub. No session tokens are stored -- every request uses a
    /// DPoP proof signed by the dock key.
    ///
    /// Examples:
    ///   treeship dock login
    ///   treeship dock login --endpoint http://localhost:8080
    Login(DockLoginArgs),

    /// Push a signed artifact to treeship.dev Hub
    ///
    /// Sends the artifact with a DPoP-authenticated request. Returns
    /// a shareable URL and optional Rekor transparency log index.
    ///
    /// Examples:
    ///   treeship dock push art_a1b2c3d4e5f6a1b2
    Push(DockPushArgs),

    /// Pull an artifact from treeship.dev Hub into local storage
    ///
    /// No authentication required -- artifacts are public.
    ///
    /// Examples:
    ///   treeship dock pull art_a1b2c3d4e5f6a1b2
    Pull(DockPullArgs),

    /// Show current dock connection status
    ///
    /// Examples:
    ///   treeship dock status
    Status,

    /// Disconnect from treeship.dev Hub
    ///
    /// Clears dock credentials from config. Does not revoke the dock
    /// keypair on the Hub.
    ///
    /// Examples:
    ///   treeship dock undock
    Undock,
}

#[derive(Args)]
struct DockLoginArgs {
    /// Hub API endpoint (default: https://api.treeship.dev)
    #[arg(long, value_name = "URL")]
    endpoint: Option<String>,
}

#[derive(Args)]
struct DockPushArgs {
    /// Artifact ID to push
    id: String,
}

#[derive(Args)]
struct DockPullArgs {
    /// Artifact ID to pull
    id: String,
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

        Command::Version => {
            println!("treeship {} (rust)", env!("CARGO_PKG_VERSION"));
            Ok(())
        }

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
            SessionCommand::Status => commands::session::status(
                cli.config.as_deref(),
                printer,
            ),
            SessionCommand::Close(a) => commands::session::close(
                a.summary.clone(),
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

        Command::Verify(a) => commands::verify::run(
            &a.target, a.no_chain, a.max_depth, a.full, cli.config.as_deref(), printer,
        ),

        Command::Keys(sub) => match sub {
            KeysCommand::List => commands::keys::list(cli.config.as_deref(), printer),
        },

        Command::Dock(sub) => match sub {
            DockCommand::Login(a) => commands::dock::login(
                a.endpoint.clone(),
                cli.config.as_deref(),
                printer,
            ),
            DockCommand::Push(a) => commands::dock::push(
                &a.id,
                cli.config.as_deref(),
                printer,
            ),
            DockCommand::Pull(a) => commands::dock::pull(
                &a.id,
                None,
                cli.config.as_deref(),
                printer,
            ),
            DockCommand::Status => commands::dock::status(
                cli.config.as_deref(),
                printer,
            ),
            DockCommand::Undock => commands::dock::undock(
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
