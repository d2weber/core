use anyhow::Result;
use deltachat::chat::{Chat, ChatId};
use deltachat::constants::Chattype;
use deltachat::contact::ContactId;
use deltachat::context::Context;
use deltachat::message::Message;
use deltachat::relay_bot::{
    get_canonical_msg_for_reaction, get_help_text, get_verified_role, handle_command,
    init_bot_tables, is_leave_message, relay_incoming_reaction, relay_message,
    remove_member_from_broadcast, set_role, Role,
};
use deltachat::securejoin::get_securejoin_qr;
use deltachat::stock_str::StockStrings;
use deltachat::EventType;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("warn,deltachat_relay_bot=debug,deltachat::relay_bot=info")
    });
    if let Ok(journald) = tracing_journald::layer() {
        tracing_subscriber::registry()
            .with(filter)
            .with(journald)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    info!("Relay bot starting...");
    let dbpath: PathBuf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "relay_bot.db".to_owned())
        .into();
    let ctx = Context::new(&dbpath, 0, Default::default(), StockStrings::new()).await?;

    init_bot_tables(&ctx).await?;

    if !ctx.is_configured().await? {
        ctx.add_transport_from_qr("dcaccount:https://nine.testrun.org/new")
            .await?;
        ctx.set_config(deltachat::config::Config::Bot, Some("1"))
            .await?;
        assert!(ctx.is_configured().await?);
        info!("Configured new account.");

        let qr = get_securejoin_qr(&ctx, None).await?;
        info!("Waiting for initial admin to scan QR code:\n{}", qr);

        let events = ctx.get_event_emitter();
        ctx.start_io().await;

        while let Some(event) = events.recv().await {
            if let EventType::SecurejoinInviterProgress {
                contact_id,
                progress,
                chat_id: _,
                chat_type: _,
            } = event.typ
            {
                if progress >= 1000 {
                    set_role(&ctx, contact_id, Role::Admin).await?;
                    let contact = deltachat::contact::Contact::get_by_id(&ctx, contact_id).await?;
                    info!("Admin set: {}", contact.get_name_n_addr());
                    break;
                }
            }
        }
        ctx.stop_io().await;
    }

    info!("Contact bot\n{}", get_securejoin_qr(&ctx, None).await?);
    let events = ctx.get_event_emitter();
    ctx.start_io().await;

    while let Some(event) = events.recv().await {
        if let Err(e) = handle_event(&ctx, event.typ).await {
            tracing::error!("Event error: {:#}", e);
        }
    }
    Ok(())
}

async fn handle_event(ctx: &Context, typ: EventType) -> Result<()> {
    match typ {
        EventType::IncomingMsg { chat_id, msg_id } => {
            let msg = Message::load_from_db(ctx, msg_id).await?;
            let from = msg.get_from_id();
            if from == ContactId::SELF {
                return Ok(());
            }
            let chat = Chat::load_from_db(ctx, chat_id).await?;
            if chat.get_type() == Chattype::BlindGroup {
                if is_leave_message(&msg) {
                    remove_member_from_broadcast(ctx, chat_id, from).await?;
                } else if handle_command(ctx, chat_id, from, &msg).await? {
                } else {
                    relay_message(ctx, chat_id, from, &msg).await?;
                }
            } else if chat.get_type() == Chattype::Single {
                if !handle_command(ctx, chat_id, from, &msg).await? {
                    send_help(ctx, chat_id, from).await?;
                }
            }
        }
        EventType::ReactionsChanged {
            chat_id,
            msg_id,
            contact_id,
        } => {
            if contact_id == ContactId::SELF {
                return Ok(());
            }
            let chat = Chat::load_from_db(ctx, chat_id).await?;
            let msg = Message::load_from_db(ctx, msg_id).await?;
            if chat.get_type() == Chattype::BlindGroup {
                let reactions = deltachat::reaction::get_msg_reactions(ctx, msg_id).await?;
                let reaction = reactions.get(contact_id);
                let target_msg_id = if let Some(canonical) =
                    get_canonical_msg_for_reaction(ctx, msg.rfc724_mid()).await?
                {
                    canonical.get_id()
                } else {
                    msg_id
                };
                relay_incoming_reaction(ctx, chat_id, contact_id, target_msg_id, reaction.as_str())
                    .await?;
            }
        }
        _ => {}
    }
    Ok(())
}

async fn send_help(ctx: &Context, chat_id: ChatId, from: ContactId) -> Result<()> {
    let role = get_verified_role(ctx, from).await?;
    let mut text = get_help_text(false, role);
    text.push_str("\n\nRooms:");

    let chatlist = deltachat::chatlist::Chatlist::try_load(ctx, 0, None, None).await?;
    let mut has_rooms = false;
    for (cid, _) in chatlist.iter() {
        let c = Chat::load_from_db(ctx, *cid).await?;
        if c.get_type() != Chattype::BlindGroup {
            continue;
        }
        let qr = deltachat::securejoin::get_securejoin_qr(ctx, Some(*cid)).await?;
        text.push_str(&format!("\n- {}: {}", c.get_name(), qr));
        has_rooms = true;
    }
    if !has_rooms {
        text.push_str(" None yet.");
    }

    let mut msg = Message::new_text(text);
    deltachat::chat::send_msg(ctx, chat_id, &mut msg).await?;
    Ok(())
}
