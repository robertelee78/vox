//! Operator terminal companion to Add Computer, using the same daemon-wide requests as the app.
use crate::{app::AppError, cli::AccountArgs};
use clap::Subcommand;
use vox_core::node::computer::{operator_only, ComputerStatus};
use vox_core::node::daemonipc::{DaemonClient, DaemonFrame, DaemonRequest};

/// Computer trust commands do not take a node or any identity/room passphrase.
#[derive(Debug, Clone, Subcommand)]
pub enum ComputerCmd {
    /// Release this node to one enrolled computer, or approve its transfer/recovery here.
    Binding {
        /// release requires --destination; transfer accepts its signed release; recover requires removal/fault evidence.
        #[arg(value_parser = ["release", "transfer", "recover", "recover-group"])]
        action: String,
        /// Full node fingerprint; use group for recover-group.
        node: String,
        #[arg(long, default_value = "")]
        destination: String,
        /// Exact frontier from computer status; confirms the identity and causal operation.
        #[arg(long)]
        confirm: String,
        #[command(flatten)]
        account: AccountArgs,
        #[arg(long)]
        json: bool,
    },
    /// Save the app's personal-node selection; use --clear for a headless computer.
    Personal {
        /// A Ready local node; its actor proves the selected identity.
        node: Option<String>,
        #[arg(long, conflicts_with = "node", required_unless_present = "node")]
        clear: bool,
        #[command(flatten)]
        account: AccountArgs,
        #[arg(long)]
        json: bool,
    },
    /// Remove all trust in a computer's nodes, including earlier individual grants.
    Remove {
        /// Full computer fingerprint from computer status.
        computer: String,
        /// Exact frontier from computer status, confirming its computer and affected nodes.
        #[arg(long)]
        confirm: String,
        #[command(flatten)]
        account: AccountArgs,
        #[arg(long)]
        json: bool,
    },
    /// Read computer identity, effective policy and pending confirmations.
    Status {
        #[command(flatten)]
        account: AccountArgs,
        /// Print the same public status record used by Vox.app.
        #[arg(long)]
        json: bool,
    },
    /// Make one expiring invitation, as Add Computer does in Vox.app.
    Invite {
        #[command(flatten)]
        account: AccountArgs,
        #[arg(long)]
        json: bool,
    },
    /// Authenticate this invitation, show the computer and policy, and confirm once.
    Pair {
        /// One-time computer pairing link from Add Computer.
        link: String,
        #[command(flatten)]
        account: AccountArgs,
        /// Authenticate and display the proposal without approving it yet.
        #[arg(long)]
        preview: bool,
        #[arg(long)]
        json: bool,
    },
    /// Confirm the exact operation previously shown by pair --preview or computer status.
    Approve {
        operation: String,
        #[command(flatten)]
        account: AccountArgs,
        #[arg(long)]
        json: bool,
    },
    /// Cancel a pending invitation or uncommitted proposal.
    Cancel {
        operation: String,
        #[command(flatten)]
        account: AccountArgs,
        #[arg(long)]
        json: bool,
    },
}

/// Drive the operator's requested account operation, checking the agent mark before any writes.
pub async fn run(command: ComputerCmd) -> Result<(), AppError> {
    if !matches!(&command, ComputerCmd::Status { .. }) {
        operator_only()?;
    }
    let (account, json, request, prompt) = match command {
        ComputerCmd::Binding {
            action,
            node,
            destination,
            confirm,
            account,
            json,
        } => (
            account,
            json,
            DaemonRequest::ComputerBinding {
                action,
                node,
                destination,
                frontier: confirm,
            },
            false,
        ),
        ComputerCmd::Personal {
            node,
            clear: _,
            account,
            json,
        } => (
            account,
            json,
            DaemonRequest::ComputerPersonal {
                node: node.unwrap_or_default(),
            },
            false,
        ),
        ComputerCmd::Remove {
            computer,
            confirm,
            account,
            json,
        } => (
            account,
            json,
            DaemonRequest::ComputerRemove {
                computer,
                frontier: confirm,
            },
            false,
        ),
        ComputerCmd::Status { account, json } => {
            (account, json, DaemonRequest::ComputerStatus, false)
        }
        ComputerCmd::Invite { account, json } => {
            (account, json, DaemonRequest::ComputerBegin, false)
        }
        ComputerCmd::Pair {
            link,
            account,
            preview,
            json,
        } => (
            account,
            json,
            DaemonRequest::ComputerPreview {
                link: zeroize::Zeroizing::new(link),
            },
            !preview,
        ),
        ComputerCmd::Approve {
            operation,
            account,
            json,
        } => (
            account,
            json,
            DaemonRequest::ComputerApprove { operation },
            false,
        ),
        ComputerCmd::Cancel {
            operation,
            account,
            json,
        } => (
            account,
            json,
            DaemonRequest::ComputerCancel { operation },
            false,
        ),
    };
    let root = vox_core::node::paths::Account::of(
        account.data_dir.as_deref(),
        account.config_dir.as_deref(),
    )?;
    vox_core::node::layout::refuse_old_layout(&root)?;
    crate::daemon_client::ensure_daemon(&root, account.listen, &account.anchors).await?;
    let mut client = DaemonClient::open(&root.socket()).await?;
    let mut status = ask(&mut client, request).await?;
    if prompt {
        show(&status, false)?;
        let proposal = status.pairing.as_ref().ok_or_else(|| {
            AppError::Usage("no authenticated computer was offered for approval".into())
        })?;
        if !proposal.approved_here {
            let operation = proposal.operation_id.clone();
            let yes = tokio::task::spawn_blocking(|| -> std::io::Result<bool> {
                use std::io::Write as _;
                eprint!("Trust this computer with this policy? [y/N] ");
                std::io::stderr().flush()?;
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                Ok(matches!(
                    input.trim().to_ascii_lowercase().as_str(),
                    "y" | "yes"
                ))
            })
            .await
            .map_err(|_| AppError::Usage("computer approval input stopped".into()))??;
            if !yes {
                return Err(AppError::Usage(
                    "computer pairing was not approved; no new local approval was made".into(),
                ));
            }
            status = ask(&mut client, DaemonRequest::ComputerApprove { operation }).await?;
        }
    }
    show(&status, json)
}
async fn ask(
    client: &mut DaemonClient,
    request: DaemonRequest,
) -> Result<ComputerStatus, AppError> {
    match client.request(request).await? {
        DaemonFrame::ComputerStatus(json) => serde_json::from_str(&json)
            .map_err(|_| AppError::Usage("the daemon's computer status could not be read".into())),
        DaemonFrame::ComputerFailed(why) => Err(AppError::Usage(why)),
        _ => Err(AppError::Usage(
            "the daemon did not answer computer management".into(),
        )),
    }
}
fn show(status: &ComputerStatus, json: bool) -> Result<(), AppError> {
    if json {
        println!(
            "{}",
            serde_json::to_string(status).map_err(|e| AppError::Usage(e.to_string()))?
        );
        return Ok(());
    }
    println!(
        "{}  {}\ninstallation {}\ncomputer trust: {}",
        status.this_computer.name,
        status.this_computer.fingerprint,
        status.this_computer.installation,
        status.state
    );
    println!("{}", status.policy);
    if let Some(p) = &status.pairing {
        println!(
            "{}  {}\ninstallation {}\noperation {}\napproved here: {}; approved there: {}",
            p.peer.name,
            p.peer.fingerprint,
            p.peer.installation,
            p.operation_id,
            p.approved_here,
            p.approved_there
        );
    }
    if let Some(link) = &status.invite_link {
        println!(
            "Run in the other computer's own terminal:\n  {}",
            vox_text::shell::command(&["vox", "computer", "pair", link])
        );
    }
    if let Some(id) = &status.invite_id {
        println!(
            "Cancel: {}",
            vox_text::shell::command(&["vox", "computer", "cancel", id])
        );
    }
    for application in &status.applications {
        println!(
            "{}  {}  {}",
            application.computer.name,
            application.computer.fingerprint,
            if application.confirmed {
                "confirmed"
            } else {
                "pending application"
            }
        );
    }
    for node in &status.nodes {
        println!(
            "{}  {}  computer {}  {}",
            node.name,
            node.fingerprint,
            node.computer,
            if node.personal {
                "personal; drives non-personal nodes"
            } else {
                "read; no automatic drive"
            }
        );
    }
    for binding in &status.binding_actions {
        println!(
            "binding {}: {}  {}  manager {}",
            binding.action, binding.name, binding.node, binding.computer
        );
    }
    for removed in &status.removed {
        println!(
            "removed: {}  {}; no claim that unreachable data or keyrings were erased",
            removed.name, removed.fingerprint
        );
    }
    println!("Removal confirmation frontier: {}", status.frontier);
    for pending in &status.pending_nodes {
        println!("pending: {pending}");
    }
    if let Some(why) = &status.problem {
        println!("pending: {why}");
    }
    Ok(())
}
