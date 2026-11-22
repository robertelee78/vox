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
        confirm: Option<String>,
        /// Keep the removed computer's nodes in their rooms.
        #[arg(long)]
        keep_rooms: bool,
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
            keep_rooms,
            account,
            json,
        } => {
            return remove(computer, confirm, keep_rooms, account, json).await;
        }
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
                eprintln!("On {}, the signed incomplete proposal can be closed now; its retained signature can still be used elsewhere until Unix ms {}.", conflict.peer.name, conflict.expires_ms);
            }
            eprintln!("On {}, close the old proposal now with:\n  {}\nClosing cannot withdraw a signature retained elsewhere; close it on both computers. Then create a fresh invitation with:\n  {}\nBring that fresh invitation here and approve on both computers.",
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

async fn remove(
    target: String,
    confirmed: Option<String>,
    keep_rooms: bool,
    account: AccountArgs,
    json: bool,
) -> Result<(), AppError> {
    let root = vox_core::node::paths::Account::of(
        account.data_dir.as_deref(),
        account.config_dir.as_deref(),
    )?;
    vox_core::node::layout::refuse_old_layout(&root)?;
    crate::daemon_client::ensure_daemon(&root, account.listen, &account.anchors).await?;
    let mut client = DaemonClient::open(&root.socket()).await?;
    let status = ask(&mut client, DaemonRequest::ComputerStatus).await?;
    let matches: Vec<_> = status
        .computers
        .iter()
        .filter(|computer| computer.fingerprint == target || computer.name == target)
        .collect();
    let [computer] = matches.as_slice() else {
        return Err(AppError::Usage("name one active computer by its unique name or full fingerprint from vox computer status --details".into()));
    };
    let target = computer.fingerprint.clone();
    let mut preview = DaemonClient::open(&root.socket()).await?;
    let status = ask(
        &mut preview,
        DaemonRequest::ComputerRemove {
            computer: target.clone(),
            frontier: String::new(),
            keep_rooms,
            rooms: None,
        },
    )
    .await?;
    let rooms = status.removal_rooms.clone();
    if confirmed.is_none() {
        eprintln!(
            "Remove computer {} ({}) and its nodes:",
            computer.name, target
        );
        for node in status.nodes.iter().filter(|node| node.computer == target) {
            eprintln!(
                "  {} ({}) loses computer Read and Drive and will not be offered for trust again.",
                node.name, node.fingerprint
            );
        }
        for row in &rooms {
            eprintln!(
                "  {} in room {}: {}.",
                vox_core::node::link::b32_encode(&row.member),
                vox_core::node::link::b32_encode(&row.room),
                if keep_rooms {
                    "keep membership"
                } else if row.command_node == [0; 32] {
                    "check membership and authority when this room opens"
                } else if row.local_node == row.command_node {
                    "evict through vox room remove-member"
                } else {
                    "ask the creator or an admin to remove this member"
                }
            );
        }
        eprintln!("Received data is not erased; unreachable computers apply the removal later. Only the room creator can readmit an evicted member.");
        if !confirm("Remove this computer with these room choices? [y/N] ").await? {
            return Err(AppError::Usage(
                "computer removal declined; nothing was removed".into(),
            ));
        }
    }
    let mut client = DaemonClient::open(&root.socket()).await?;
    let status = ask(
        &mut client,
        DaemonRequest::ComputerRemove {
            computer: target,
            frontier: confirmed.unwrap_or(status.frontier),
            keep_rooms,
            rooms: Some(rooms),
        },
    )
    .await?;
    show(&status, json, false, false, false)
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
    match status.state.as_str() {
        "individual" => {
            println!("This computer is not in a group.");
            println!("Next: vox computer invite — add another computer.");
        }
        "needs-approval" => {
            println!("This computer needs your pairing approval.");
            if let Some(pairing) = &status.pairing {
                println!(
                    "Next: {}",
                    vox_text::shell::command(&[
                        "vox",
                        "computer",
                        "approve",
                        &pairing.operation_id
                    ])
                );
            }
        }
        "waiting" => {
            if status
                .pairing
                .as_ref()
                .is_some_and(|pairing| pairing.approved_here)
            {
                println!("This computer approved pairing; the other approval has not arrived.");
            } else {
                println!("This computer is waiting for pairing.");
            }
            if let Some(operation) = status
                .pairing
                .as_ref()
                .map(|pairing| pairing.operation_id.as_str())
                .or(status.invite_id.as_deref())
            {
                println!(
                    "Next: {} — close this attempt here, or finish approval on the other computer.",
                    vox_text::shell::command(&["vox", "computer", "cancel", operation])
                );
            }
        }
        "confirmed" => {
            let peers: Vec<_> = status
                .computers
                .iter()
                .filter(|computer| computer.fingerprint != status.this_computer.fingerprint)
                .map(|computer| computer.name.as_str())
                .collect();
            println!("This computer is in a group with {}.", peers.join(", "));
            println!("Next: vox computer invite — add a computer; vox computer status --details — review this group.");
        }
        "removed" => {
            println!("This computer was removed from its group.");
            println!("Next: vox computer retire — review and finish local retirement.");
        }
        "group-conflict" => {
            println!("This computer has a pairing proposal from another group.");
            if let Some(conflict) = &status.conflict {
                println!(
                    "Next: {} — keep this group and close the proposal.",
                    vox_text::shell::command(&[
                        "vox",
                        "computer",
                        "cancel",
                        &conflict.operation_id
                    ])
                );
            }
        }
        "expired" => {
            println!("This computer's group change did not finish; the last convergence deadline was missed.");
            println!("Next: vox computer status --details — read the failed computer and cause; pairing again does not erase that miss.");
        }
        "applying" => {
            println!("This computer is in a group; application is still pending.");
            println!("Next: vox computer status --details — read which nodes or computers are pending and why.");
        }
        _ => {
            println!("This computer's trust cannot be applied safely.");
            println!("Next: vox computer status --details — read the retained authority or storage failure.");
        }
    }
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
    for removal in &status.removals {
        if removal.keep_rooms {
            println!(
                "Computer {} removed; room memberships kept (--keep-rooms).",
                removal.computer
            );
        }
        for node in &removal.unchecked_nodes {
            let acting = format!("fp:{node}");
            println!(
                "Rooms on locked node {node} have not been checked yet. Next: {}",
                vox_text::shell::command(&["vox", "node", "unlock", &acting])
            );
        }
        for row in &removal.pending {
            let room = vox_core::node::link::b32_encode(&row.room);
            let node = vox_core::node::link::b32_encode(&row.member);
            if row.command_node == [0; 32] {
                let acting = format!("fp:{}", vox_core::node::link::b32_encode(&row.local_node));
                println!("Room {room}, node {node}: membership removal waits until this room opens. Next: {}",
                    vox_text::shell::command(&["vox", "room", "open", &room, "--node", &acting]));
                continue;
            }
            let acting = format!("fp:{}", vox_core::node::link::b32_encode(&row.command_node));
            if row.member == row.command_node {
                println!("Room {room}, node {node}: no local node may evict the room creator. On that node: {}",
                    vox_text::shell::command(&["vox", "room", "leave", &room, "--node", &acting]));
                continue;
            }
            println!(
                "Room {room}, node {node}: {}. Next: {}",
                if row.command_node == row.local_node {
                    "removal pending; it resumes when this room can proceed"
                } else {
                    "no local node may evict; ask the creator or an admin"
                },
                vox_text::shell::command(&[
                    "vox",
                    "room",
                    "remove-member",
                    &room,
                    &node,
                    "--node",
                    &acting
                ])
            );
        }
    }
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
            println!("The inviter already signed the proposal. Closing it here cannot withdraw that signature on the other computer.");
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
