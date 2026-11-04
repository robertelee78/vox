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
        #[arg(value_parser = ["release", "transfer", "recover"])]
        action: String,
        /// Full node fingerprint.
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
        /// Include full identities, revisions and diagnostic evidence.
        #[arg(long)]
        details: bool,
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
    /// Review and finish local retirement of a removed computer group.
    Retire {
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
    let details = matches!(&command, ComputerCmd::Status { details: true, .. });
    let retire = matches!(&command, ComputerCmd::Retire { .. });
    let include_invitation = matches!(&command, ComputerCmd::Invite { .. });
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
        ComputerCmd::Status { account, json, .. } => {
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
        ComputerCmd::Retire { account, json } => {
            (account, json, DaemonRequest::ComputerStatus, false)
        }
    };
    let root = vox_core::node::paths::Account::of(
        account.data_dir.as_deref(),
        account.config_dir.as_deref(),
    )?;
    vox_core::node::layout::refuse_old_layout(&root)?;
    crate::daemon_client::ensure_daemon(&root, account.listen, &account.anchors).await?;
    let mut client = DaemonClient::open(&root.socket()).await?;
    let mut status = ask(&mut client, request).await?;
    if retire {
        let review = status.retirement.clone().ok_or_else(|| {
            AppError::Usage("there is no removed computer group to retire locally".into())
        })?;
        eprintln!("Retiring this group removes covered local Read, Drive and individual grants. Computer/node identities, local data and signed history remain. Unreachable computers may retain access and data.");
        for item in &review.affected {
            eprintln!("  {item}");
        }
        if !confirm("Retire this reviewed group on this computer? [y/N] ").await? {
            return Err(AppError::Usage(
                "local retirement declined; no trust was changed".into(),
            ));
        }
        let mut retirement = DaemonClient::open(&root.socket()).await?;
        status = ask(
            &mut retirement,
            DaemonRequest::ComputerBinding {
                action: "recover-group".into(),
                node: review.review_id,
                destination: String::new(),
                frontier: review.frontier,
            },
        )
        .await?;
    }
    if prompt {
        show(&status, false, json, false, false)?;
        if let Some(conflict) = status.conflict.clone() {
            let yes = confirm("Retire this computer's reviewed old group locally? [y/N] ").await?;
            if !yes {
                return Err(AppError::Usage(
                    "group replacement declined; no trust was changed".into(),
                ));
            }
            let mut replacement = DaemonClient::open(&root.socket()).await?;
            status = ask(
                &mut replacement,
                DaemonRequest::ComputerBinding {
                    action: "replace-group".into(),
                    node: conflict.review_id,
                    destination: String::new(),
                    frontier: conflict.frontier,
                },
            )
            .await?;
            if conflict.inviter_approved {
                eprintln!("On {}, wait until the signed incomplete proposal expires at Unix ms {}; closing it cannot withdraw a signature retained elsewhere.", conflict.peer.name, conflict.expires_ms);
            }
            eprintln!("On {}, close the old proposal with:\n  {}\nIf it was signed after review, wait until expiry before closing; closing cannot withdraw a retained signature. Then create a fresh invitation with:\n  {}\nBring that fresh invitation here and approve on both computers.",
                conflict.peer.name,
                vox_text::shell::command(&["vox", "computer", "cancel", &conflict.operation_id]),
                vox_text::shell::command(&["vox", "computer", "invite"]));
            return show(&status, json, false, details, false);
        }
        let proposal = status.pairing.as_ref().ok_or_else(|| {
            AppError::Usage("no authenticated computer was offered for approval".into())
        })?;
        if !proposal.approved_here {
            let operation = proposal.operation_id.clone();
            let yes = confirm("Trust this computer with this policy? [y/N] ").await?;
            if !yes {
                return Err(AppError::Usage(
                    "computer pairing was not approved; no new local approval was made".into(),
                ));
            }
            // A daemon control connection answers one opening request. Preview consumed it;
            // approval uses a fresh authenticated connection after the person's confirmation.
            let mut approval = DaemonClient::open(&root.socket()).await?;
            status = ask(&mut approval, DaemonRequest::ComputerApprove { operation }).await?;
        }
    }
    show(&status, json, false, details, include_invitation)
}
async fn confirm(prompt: &'static str) -> Result<bool, AppError> {
    tokio::task::spawn_blocking(move || -> std::io::Result<bool> {
        use std::io::Write as _;
        eprint!("{prompt}");
        std::io::stderr().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        Ok(matches!(
            input.trim().to_ascii_lowercase().as_str(),
            "y" | "yes"
        ))
    })
    .await
    .map_err(|_| AppError::Usage("computer approval input stopped".into()))?
    .map_err(Into::into)
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
fn show(
    status: &ComputerStatus,
    json: bool,
    to_stderr: bool,
    details: bool,
    include_invitation: bool,
) -> Result<(), AppError> {
    if json {
        println!(
            "{}",
            serde_json::to_string(status).map_err(|e| AppError::Usage(e.to_string()))?
        );
        return Ok(());
    }
    // The interactive JSON path still needs the same human review, but not on JSON stdout.
    macro_rules! println {
        ($($arg:tt)*) => {
            if to_stderr {
                eprintln!($($arg)*);
            } else {
                std::println!($($arg)*);
            }
        };
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    if details || status.pairing.is_some() {
        println!(
            "{}  {}\ninstallation {}\ncomputer trust: {}\npolicy revision {}",
            status.this_computer.name,
            status.this_computer.fingerprint,
            status.this_computer.installation,
            status.state,
            status.revision
        );
    } else {
        println!(
            "{} · computer trust: {}",
            status.this_computer.name, status.state
        );
    }
    println!("{}", status.policy);
    if let Some(conflict) = &status.conflict {
        println!("Authenticated computer {} · {}\ninstallation {} is already in a different established group.",
            conflict.peer.name, conflict.peer.fingerprint, conflict.peer.installation);
        println!(
            "Current group: {}\nProposed group: {}",
            conflict.current_group, conflict.proposed_group
        );
        println!("Replacing locally revokes covered group Read and personal-to-managed-node Drive, including covered individual grants. Computer/node identities, local data and signed history remain. Unreachable computers may retain access and data; this does not erase or revoke them remotely.");
        for item in &conflict.affected {
            println!("  {item}");
        }
        if conflict.inviter_approved {
            println!("The inviter already signed the proposal; wait until Unix ms {} before closing it there. Closing cannot withdraw an already-recorded signature.", conflict.expires_ms);
        }
        if conflict.expires_ms <= now_ms {
            println!("The proposal expired. On {}, close it with {} and create a fresh invitation with {}.",
                conflict.peer.name,
                vox_text::shell::command(&["vox", "computer", "cancel", &conflict.operation_id]),
                vox_text::shell::command(&["vox", "computer", "invite"]));
        } else {
            println!(
                "To replace, review this invitation interactively on {}.",
                status.this_computer.name
            );
        }
        println!("To keep the current group and close this review on {}, run {}. This does not withdraw the invitation or signature on {}.",
            status.this_computer.name,
            vox_text::shell::command(&["vox", "computer", "cancel", &conflict.operation_id]),
            conflict.peer.name);
    }
    if status.retirement.is_some() {
        println!("This computer was removed from its previous group. Review and finish its local retirement with: vox computer retire");
    }
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
        match &p.proposed_group {
            Some(group) => println!("Joins existing computer group: {group}"),
            None => println!("Creates a new computer group."),
        }
        if p.expires_ms <= now_ms {
            println!(
                "This incomplete attempt has expired. Close it on this computer: {}",
                vox_text::shell::command(&["vox", "computer", "cancel", &p.operation_id])
            );
            if p.approved_here {
                println!("Closing locally does not withdraw signed approval or remove trust on the other computer.");
            }
        } else if !p.approved_here {
            println!(
                "After reviewing this computer and policy, approve on {} ({}) here: {}",
                status.this_computer.name,
                status.this_computer.fingerprint,
                vox_text::shell::command(&["vox", "computer", "approve", &p.operation_id])
            );
        } else if !p.approved_there {
            println!(
                "Approved here. Approval from {} ({}) has not reached this computer. \
                 On that computer, review and approve in its terminal with {}, or in Vox's \
                 My Computers window.",
                p.peer.name,
                p.peer.fingerprint,
                vox_text::shell::command(&["vox", "computer", "approve", &p.operation_id])
            );
        } else {
            println!("Both approvals are recorded; enrollment has not completed here yet.");
        }
    }
    if let Some(link) = status.invite_link.as_ref().filter(|_| include_invitation) {
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
    for line in &status.topology {
        println!("Policy: {line}");
    }
    if !details {
        for application in &status.applications {
            let applied = if application.confirmed {
                "application confirmed"
            } else {
                "application pending"
            };
            let connectivity =
                if application.computer.fingerprint == status.this_computer.fingerprint {
                    "this computer"
                } else if application.exchange_in_flight {
                    "exchange in progress; current connectivity unknown"
                } else if application.exchange_failures > 0 {
                    "last exchange failed; current connectivity unknown"
                } else if application.last_exchange_ms.is_some() {
                    "previously exchanged; current connectivity unknown"
                } else {
                    "connectivity unknown"
                };
            println!("{}: {applied}; {connectivity}", application.computer.name);
        }
        for pending in &status.pending_nodes {
            println!("Pending application: {pending}");
        }
        if let Some(why) = &status.problem {
            println!("Current problem: {why}");
        }
        println!("For full identities and diagnostics: vox computer status --details");
        return Ok(());
    }
    for application in &status.applications {
        // The last exchange this daemon started and the last it answered, each with the policy
        // revision it sent and the one it stood at after merging: which exchange carried a
        // change (ADR-038 FX-28).
        let mut carried = String::new();
        for (what, record) in [
            ("started", application.last_started_exchange),
            ("answered", application.last_answered_exchange),
        ] {
            if let Some(r) = record {
                carried.push_str(&format!(
                    "; last exchange {what} {} s ago sent revision {}, merged to revision {}",
                    now_ms.saturating_sub(r.at_ms) / 1000,
                    r.sent_revision,
                    r.merged_revision
                ));
            }
        }
        let exchanged = match application.last_exchange_ms {
            Some(at) => {
                let ago = now_ms.saturating_sub(at) / 1000;
                format!(
                    "; exchanged {} time(s) in {} attempt(s) since the daemon started, last {ago} s ago{}{}",
                    application.exchanges,
                    application.exchange_attempts,
                    if application.exchange_failures > 0 {
                        format!(", {} failed in a row", application.exchange_failures)
                    } else {
                        String::new()
                    },
                    if application.exchange_in_flight {
                        "; exchange in flight"
                    } else {
                        ""
                    }
                )
            }
            None => format!(
                "; not exchanged since the daemon started{}{}",
                if application.exchange_failures > 0 {
                    format!(
                        ", {} attempt(s) failed in a row",
                        application.exchange_failures
                    )
                } else {
                    String::new()
                },
                if application.exchange_in_flight {
                    "; exchange in flight"
                } else {
                    ""
                }
            ),
        };
        let convergence = application.missed_revision.map_or_else(
            || format!("; convergence {}", application.convergence_state),
            |revision| {
                format!(
                    "; convergence {}, missed revision {revision}, repaired late {}",
                    application.convergence_state, application.repaired_late
                )
            },
        );
        println!(
            "{}  {}  {}{convergence}{exchanged}{carried}",
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
        // A node of this computer says at which policy revision its binding was derived and
        // when: current when it names the status's revision, stale otherwise (ADR-038 FX-28).
        let binding = match (node.binding_revision, node.binding_derived_ms) {
            (Some(revision), Some(at)) => format!(
                "; binding derived at policy revision {revision}{}, {} s ago",
                if revision == status.revision {
                    " (current)"
                } else {
                    " (stale)"
                },
                now_ms.saturating_sub(at) / 1000
            ),
            (Some(revision), None) => format!(
                "; binding derived at policy revision {revision}{}",
                if revision == status.revision {
                    " (current)"
                } else {
                    " (stale)"
                }
            ),
            (None, _) if node.computer == status.this_computer.fingerprint => {
                "; binding not derived since the daemon started".to_owned()
            }
            (None, _) => String::new(),
        };
        println!(
            "{}  {}  computer {}  {}{binding}",
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
    for missed in &status.application_misses {
        println!(
            "application late: {}  {}  revision {}",
            missed.name.as_deref().unwrap_or("unnamed node"),
            missed.node,
            missed.revision
        );
    }
    if let Some(why) = &status.problem {
        println!("pending: {why}");
    }
    Ok(())
}
