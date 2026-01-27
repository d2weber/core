//! Relay bot for BlindGroup broadcasts.
//!
//! When relaying messages with quotes, different recipients may need different message-ids:
//! - Original sender: quote references their original mid (in their 1:1 chat with bot)
//! - Others: quote references the relayed mid (what they received)
//!
//! This requires sending separate messages to different recipients, each with unique mids.
//! Reactions are tracked centrally in `relay_reactions` and aggregated counts are distributed,
//! excluding each user's own reaction from what they see.

use crate::chat::{ChatId, remove_from_chat_contacts_table, send_msg};
use crate::contact::{Contact, ContactId};
use crate::context::Context;
use crate::message::Message;
use crate::mimeparser::SystemMessage;
use anyhow::Result;

use crate::log::warn;

/// Role levels for bot permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(i32)]
pub enum Role {
    /// Regular user.
    User = 0,
    /// Moderator.
    Mod = 50,
    /// Administrator.
    Admin = 100,
}

impl Role {
    /// Check if role has moderator permissions.
    pub fn has_mod(self) -> bool {
        self >= Role::Mod
    }
    /// Check if role has admin permissions.
    pub fn has_admin(self) -> bool {
        self >= Role::Admin
    }
}

impl TryFrom<i32> for Role {
    type Error = anyhow::Error;
    fn try_from(v: i32) -> Result<Self> {
        match v {
            0..=49 => Ok(Role::User),
            50..=99 => Ok(Role::Mod),
            100 => Ok(Role::Admin),
            _ => Err(anyhow::anyhow!("Invalid role value: {}", v)),
        }
    }
}

/// Initialize bot tables in database.
pub async fn init_bot_tables(ctx: &Context) -> Result<()> {
    ctx.sql.execute("CREATE TABLE IF NOT EXISTS bot_roles (contact_id INTEGER PRIMARY KEY, role INTEGER NOT NULL)", ()).await?;
    ctx.sql.execute("CREATE TABLE IF NOT EXISTS relay_mappings (relayed_mid TEXT PRIMARY KEY, sender_id INTEGER NOT NULL, original_mid TEXT NOT NULL)", ()).await?;
    ctx.sql
        .execute(
            "CREATE INDEX IF NOT EXISTS relay_mappings_original ON relay_mappings(original_mid)",
            (),
        )
        .await?;
    ctx.sql.execute("CREATE TABLE IF NOT EXISTS relay_reactions (msg_id INTEGER NOT NULL, contact_id INTEGER NOT NULL, emoji TEXT NOT NULL, PRIMARY KEY (msg_id, contact_id))", ()).await?;
    migrate_relay_info_from_config(ctx).await?;
    Ok(())
}

async fn migrate_relay_info_from_config(ctx: &Context) -> Result<()> {
    let rows: Vec<(String, String)> = ctx
        .sql
        .query_map(
            "SELECT keyname, value FROM config WHERE keyname LIKE 'relay_info_%'",
            (),
            |row| Ok((row.get(0)?, row.get(1)?)),
            |rows| rows.collect::<Result<Vec<_>, _>>().map_err(Into::into),
        )
        .await?;
    for (key, val) in rows {
        let relayed_mid = key.strip_prefix("relay_info_").unwrap_or(&key);
        let mut parts = val.splitn(2, ':');
        if let (Some(id_str), Some(original_mid)) = (parts.next(), parts.next()) {
            if let Ok(sender_id) = id_str.parse::<u32>() {
                ctx.sql.execute("INSERT OR IGNORE INTO relay_mappings (relayed_mid, sender_id, original_mid) VALUES (?, ?, ?)", (relayed_mid, sender_id, original_mid)).await.ok();
            }
        }
    }
    ctx.sql.execute("DELETE FROM config WHERE keyname LIKE 'relay_info_%' OR keyname LIKE 'relay_reverse_%'", ()).await?;
    Ok(())
}

/// Set role for a contact.
pub async fn set_role(ctx: &Context, contact_id: ContactId, role: Role) -> Result<()> {
    ctx.sql
        .execute(
            "INSERT OR REPLACE INTO bot_roles (contact_id, role) VALUES (?, ?)",
            (contact_id, role as i32),
        )
        .await?;
    info!(ctx, "Set role {:?} for contact {}", role, contact_id);
    Ok(())
}

async fn get_role(ctx: &Context, contact_id: ContactId) -> Role {
    let v: i32 = ctx
        .sql
        .query_get_value(
            "SELECT role FROM bot_roles WHERE contact_id=?",
            (contact_id,),
        )
        .await
        .ok()
        .flatten()
        .unwrap_or(0);
    Role::try_from(v)
        .inspect_err(|e| warn!(ctx, "Invalid role for {}: {}", contact_id, e))
        .unwrap_or(Role::User)
}

/// Remove role for a contact.
pub async fn remove_role(ctx: &Context, contact_id: ContactId) -> Result<()> {
    ctx.sql
        .execute("DELETE FROM bot_roles WHERE contact_id=?", (contact_id,))
        .await?;
    info!(ctx, "Removed role for contact {}", contact_id);
    Ok(())
}

/// Get role for a contact, checking verification status.
pub async fn get_verified_role(ctx: &Context, contact_id: ContactId) -> Result<Role> {
    let contact = Contact::get_by_id(ctx, contact_id).await?;
    if !contact.is_verified(ctx).await? {
        info!(
            ctx,
            "Contact {} not verified, denying role check", contact_id
        );
        return Ok(Role::User);
    }
    Ok(get_role(ctx, contact_id).await)
}

async fn readd_contact(ctx: &Context, chat_id: ChatId, contact_id: ContactId) -> Result<()> {
    ctx.sql.execute("UPDATE chats_contacts SET add_timestamp=remove_timestamp WHERE chat_id=? AND contact_id=?", (chat_id, contact_id)).await?;
    Ok(())
}

async fn send_to_subset<F, Fut>(
    ctx: &Context,
    chat_id: ChatId,
    exclude: &[ContactId],
    send_fn: F,
) -> Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    for c in exclude {
        remove_from_chat_contacts_table(ctx, chat_id, *c).await?;
    }
    let res = send_fn().await;
    for c in exclude {
        readd_contact(ctx, chat_id, *c).await?;
    }
    res
}

/// Remove a member from a blind group broadcast
pub async fn remove_member_from_broadcast(
    ctx: &Context,
    broadcast_id: ChatId,
    contact_id: ContactId,
) -> Result<()> {
    info!(
        ctx,
        "Removing contact {} from broadcast {}", contact_id, broadcast_id
    );
    remove_from_chat_contacts_table(ctx, broadcast_id, contact_id).await
}

/// Check if a message is a leave request (member removing themselves)
pub fn is_leave_message(msg: &Message) -> bool {
    msg.param.get_cmd() == SystemMessage::MemberRemovedFromGroup
}

async fn store_relay_info(
    ctx: &Context,
    relayed_mid: &str,
    sender: ContactId,
    original_mid: &str,
) -> Result<()> {
    ctx.sql.execute("INSERT OR REPLACE INTO relay_mappings (relayed_mid, sender_id, original_mid) VALUES (?, ?, ?)", (relayed_mid, sender, original_mid)).await?;
    Ok(())
}

async fn get_relayed_mid(ctx: &Context, original_mid: &str) -> Result<Option<String>> {
    ctx.sql
        .query_get_value(
            "SELECT relayed_mid FROM relay_mappings WHERE original_mid=?",
            (original_mid,),
        )
        .await
}

/// Get original message-id and sender from relayed mid
pub async fn get_original_info(
    ctx: &Context,
    relayed_mid: &str,
) -> Result<Option<(ContactId, String)>> {
    ctx.sql
        .query_row_optional(
            "SELECT sender_id, original_mid FROM relay_mappings WHERE relayed_mid=?",
            (relayed_mid,),
            |row| Ok((ContactId::new(row.get(0)?), row.get(1)?)),
        )
        .await
}

/// Get relayed message from original message-id
pub async fn get_relayed_msg(ctx: &Context, original_mid: &str) -> Result<Option<Message>> {
    if let Some(relayed_mid) = get_relayed_mid(ctx, original_mid).await? {
        if let Some(msg_id) = crate::message::rfc724_mid_exists(ctx, &relayed_mid).await? {
            return Ok(Some(Message::load_from_db(ctx, msg_id).await?));
        }
    }
    Ok(None)
}

/// Get the canonical (relayed) message for reaction tracking, looking up by either original or relayed mid
pub async fn get_canonical_msg_for_reaction(ctx: &Context, mid: &str) -> Result<Option<Message>> {
    if let Some(msg) = get_relayed_msg(ctx, mid).await? {
        return Ok(Some(msg));
    }
    if get_original_info(ctx, mid).await?.is_some() {
        if let Some(msg_id) = crate::message::rfc724_mid_exists(ctx, mid).await? {
            return Ok(Some(Message::load_from_db(ctx, msg_id).await?));
        }
    }
    Ok(None)
}

/// Get the original sender and their message-id for a relayed message
pub async fn get_relay_info(
    ctx: &Context,
    msg_id: crate::message::MsgId,
) -> Result<Option<(ContactId, String)>> {
    let msg = Message::load_from_db(ctx, msg_id).await?;
    get_original_info(ctx, &msg.rfc724_mid).await
}

enum QuoteMapping {
    RelayedToOriginal {
        orig_sender: ContactId,
        orig_mid: String,
    },
    OriginalToRelayed {
        relayed_mid: String,
    },
}

/// Relay a message to a blind group broadcast preserving sender and content
pub async fn relay_message(
    ctx: &Context,
    broadcast_id: ChatId,
    from: ContactId,
    original_msg: &Message,
) -> Result<()> {
    let sender = Contact::get_by_id(ctx, from).await?;
    info!(
        ctx,
        "Relaying {:?} from {} to broadcast {}",
        original_msg.get_viewtype(),
        sender.get_display_name(),
        broadcast_id
    );

    let original_mid = original_msg.rfc724_mid.clone();
    let quoted = original_msg.quoted_message(ctx).await?;

    let quote_mapping = if let Some(q) = &quoted {
        if let Some((orig_sender, orig_mid)) = get_original_info(ctx, &q.rfc724_mid).await? {
            Some(QuoteMapping::RelayedToOriginal {
                orig_sender,
                orig_mid,
            })
        } else if let Some(relayed_mid) = get_relayed_mid(ctx, &q.rfc724_mid).await? {
            Some(QuoteMapping::OriginalToRelayed { relayed_mid })
        } else {
            None
        }
    } else {
        None
    };

    match quote_mapping {
        Some(QuoteMapping::RelayedToOriginal {
            orig_sender,
            orig_mid,
        }) => {
            if orig_sender != from {
                if let Some(orig_msg_id) = crate::message::rfc724_mid_exists(ctx, &orig_mid).await?
                {
                    let orig_quoted = Message::load_from_db(ctx, orig_msg_id).await?;
                    let mut msg_for_orig = build_relay_msg(ctx, original_msg, &sender).await?;
                    msg_for_orig.set_quote(ctx, Some(&orig_quoted)).await?;
                    let exclude: Vec<_> = get_broadcast_members(ctx, broadcast_id)
                        .await?
                        .into_iter()
                        .filter(|m| *m != orig_sender)
                        .collect();
                    send_to_subset(ctx, broadcast_id, &exclude, || async {
                        send_msg(ctx, broadcast_id, &mut msg_for_orig)
                            .await
                            .map(|_| ())
                    })
                    .await?;
                }
            }
            let others: Vec<_> = get_broadcast_members(ctx, broadcast_id)
                .await?
                .into_iter()
                .filter(|m| *m != orig_sender && *m != from)
                .collect();
            if !others.is_empty() {
                let mut msg_for_others = build_relay_msg(ctx, original_msg, &sender).await?;
                if let Some(q) = &quoted {
                    msg_for_others.set_quote(ctx, Some(q)).await?;
                }
                send_to_subset(ctx, broadcast_id, &[orig_sender, from], || async {
                    send_msg(ctx, broadcast_id, &mut msg_for_others).await?;
                    store_relay_info(ctx, &msg_for_others.rfc724_mid, from, &original_mid).await
                })
                .await?;
            }
        }
        Some(QuoteMapping::OriginalToRelayed { relayed_mid }) => {
            let others: Vec<_> = get_broadcast_members(ctx, broadcast_id)
                .await?
                .into_iter()
                .filter(|m| *m != from)
                .collect();
            if !others.is_empty() {
                let mut msg_for_others = build_relay_msg(ctx, original_msg, &sender).await?;
                if let Some(relayed_msg_id) =
                    crate::message::rfc724_mid_exists(ctx, &relayed_mid).await?
                {
                    let relayed_quoted = Message::load_from_db(ctx, relayed_msg_id).await?;
                    msg_for_others.set_quote(ctx, Some(&relayed_quoted)).await?;
                }
                send_to_subset(ctx, broadcast_id, &[from], || async {
                    send_msg(ctx, broadcast_id, &mut msg_for_others).await?;
                    store_relay_info(ctx, &msg_for_others.rfc724_mid, from, &original_mid).await
                })
                .await?;
            }
        }
        None => {
            let mut msg = build_relay_msg(ctx, original_msg, &sender).await?;
            if let Some(q) = &quoted {
                msg.set_quote(ctx, Some(q)).await?;
            }
            send_to_subset(ctx, broadcast_id, &[from], || async {
                send_msg(ctx, broadcast_id, &mut msg).await?;
                store_relay_info(ctx, &msg.rfc724_mid, from, &original_mid).await
            })
            .await?;
        }
    }
    Ok(())
}

async fn build_relay_msg(
    ctx: &Context,
    original_msg: &Message,
    sender: &Contact,
) -> Result<Message> {
    let mut msg = Message::new(original_msg.get_viewtype());
    let txt = original_msg.get_text();
    if !txt.is_empty() {
        msg.set_text(txt.to_string());
    }
    if let Some(file) = original_msg.get_file(ctx) {
        msg.set_file_and_deduplicate(
            ctx,
            &file,
            original_msg.get_filename().as_deref(),
            original_msg.param.get(crate::param::Param::MimeType),
        )?;
    }
    msg.param.set(
        crate::param::Param::OverrideSenderDisplayname,
        sender.get_display_name(),
    );
    Ok(msg)
}

/// Get list of members in a blind group broadcast
pub async fn get_broadcast_members(ctx: &Context, broadcast_id: ChatId) -> Result<Vec<ContactId>> {
    crate::chat::get_chat_contacts(ctx, broadcast_id).await
}

/// Delete a blind group and notify all members.
pub async fn delete_blind_group(ctx: &Context, broadcast_id: ChatId) -> Result<()> {
    let members = get_broadcast_members(ctx, broadcast_id).await?;
    for contact_id in members {
        crate::chat::remove_contact_from_chat(ctx, broadcast_id, contact_id).await?;
    }

    // Use manual SQL instead of `ChatId::delete()` because that would delete
    // pending smtp jobs before removal notifications are sent.
    ctx.sql
        .execute(
            "UPDATE msgs SET chat_id=? WHERE chat_id=?",
            (crate::constants::DC_CHAT_ID_TRASH, broadcast_id),
        )
        .await?;
    ctx.sql
        .execute(
            "DELETE FROM chats_contacts WHERE chat_id=?",
            (broadcast_id,),
        )
        .await?;
    ctx.sql
        .execute("DELETE FROM chats WHERE id=?", (broadcast_id,))
        .await?;
    Ok(())
}

/// Request deletion of a relayed message for all recipients.
pub async fn request_message_deletion(
    ctx: &Context,
    broadcast_id: ChatId,
    target_msg_id: crate::message::MsgId,
) -> Result<()> {
    use crate::param::Param;
    let target = Message::load_from_db(ctx, target_msg_id).await?;
    let mut del_msg = Message::new_text("Message deleted by moderator".to_string());
    del_msg
        .param
        .set(Param::DeleteRequestFor, target.rfc724_mid.clone());
    send_msg(ctx, broadcast_id, &mut del_msg).await?;
    crate::message::delete_msgs(ctx, &[target_msg_id]).await?;
    info!(
        ctx,
        "Requested deletion of message {} in broadcast {}", target_msg_id, broadcast_id
    );
    Ok(())
}

/// Set room avatar.
pub async fn set_room_avatar(
    ctx: &Context,
    chat_id: ChatId,
    path: Option<&std::path::Path>,
) -> Result<()> {
    crate::chat::set_chat_profile_image(
        ctx,
        chat_id,
        path.map(|p| p.to_str().unwrap_or("")).unwrap_or(""),
    )
    .await?;
    info!(ctx, "Set room avatar for {}", chat_id);
    Ok(())
}

/// Set bot display name.
pub async fn set_bot_displayname(ctx: &Context, name: &str) -> Result<()> {
    ctx.set_config(crate::config::Config::Displayname, Some(name))
        .await?;
    info!(ctx, "Set bot display name to {}", name);
    Ok(())
}

/// Set bot avatar.
pub async fn set_bot_avatar(ctx: &Context, path: Option<&std::path::Path>) -> Result<()> {
    let val = path.and_then(|p| p.to_str());
    ctx.set_config(crate::config::Config::Selfavatar, val)
        .await?;
    info!(ctx, "Set bot avatar");
    Ok(())
}

async fn find_room_by_name(ctx: &Context, name: &str) -> Result<Option<ChatId>> {
    let chatlist = crate::chatlist::Chatlist::try_load(ctx, 0, Some(name), None).await?;
    for (cid, _) in chatlist.iter() {
        let c = crate::chat::Chat::load_from_db(ctx, *cid).await?;
        if c.get_type() == crate::constants::Chattype::BlindGroup && c.get_name() == name {
            return Ok(Some(*cid));
        }
    }
    Ok(None)
}

/// Generate help text based on context and permissions.
pub fn get_help_text(in_room: bool, role: Role) -> String {
    let mut s = String::new();
    if role.has_mod() {
        s.push_str("/room_new <name> - Create room\n/room_del <name> - Delete room\n");
    }
    if in_room {
        s.push_str("/room - Info & members\n/room_history - Recent messages\n");
        if role.has_mod() {
            s.push_str("/room_avatar - Set/remove avatar\n/del - Delete message (reply)\n");
        }
    }
    if role.has_admin() {
        s.push_str("/admin_mod <addr>\n/admin_unmod <addr>\n/admin_name <name>\n/admin_avatar\n");
    }
    if s.is_empty() {
        s.push_str("No commands available");
    }
    s.trim_end().to_string()
}

async fn get_room_history(ctx: &Context, chat_id: ChatId, limit: usize) -> Result<String> {
    let msgs = crate::chat::get_chat_msgs(ctx, chat_id).await?;
    let recent: Vec<_> = msgs.iter().rev().take(limit).collect();
    let mut lines = Vec::new();
    for item in recent.iter().rev() {
        if let crate::chat::ChatItem::Message { msg_id } = item {
            let m = Message::load_from_db(ctx, *msg_id).await?;
            if m.is_info() || m.hidden {
                continue;
            }
            let sender = if let Some((orig, _)) = get_relay_info(ctx, *msg_id).await? {
                Contact::get_by_id(ctx, orig)
                    .await?
                    .get_display_name()
                    .to_string()
            } else {
                "?".to_string()
            };
            lines.push(format!(
                "{}: {}",
                sender,
                m.get_text().chars().take(50).collect::<String>()
            ));
        }
    }
    Ok(if lines.is_empty() {
        "No messages yet".to_string()
    } else {
        lines.join("\n")
    })
}

/// Handle command. Returns true if handled, false if not a command.
pub async fn handle_command(
    ctx: &Context,
    chat_id: ChatId,
    from: ContactId,
    msg: &Message,
) -> Result<bool> {
    let text = msg.get_text();
    let Some(text) = text.strip_prefix('/') else {
        return Ok(false);
    };
    let mut parts = text.splitn(3, &['_', ' '][..]);
    let cmd = parts.next().unwrap_or("");
    let arg1 = parts.next().unwrap_or("").trim();
    let arg2 = parts.next().unwrap_or("").trim();

    let chat = crate::chat::Chat::load_from_db(ctx, chat_id).await?;
    let in_room = chat.get_type() == crate::constants::Chattype::BlindGroup;
    let role = get_verified_role(ctx, from).await?;
    let quoted = msg.quoted_message(ctx).await?;

    let response: String = match (cmd, arg1, arg2) {
        ("room", "new", name) if role.has_mod() && !name.is_empty() => {
            match crate::chat::create_unique_blind_group(ctx, name.to_string()).await {
                Ok(room_id) => {
                    let qr = crate::securejoin::get_securejoin_qr(ctx, Some(room_id)).await?;
                    format!("Room '{}' created\n{}", name, qr)
                }
                Err(e) => format!("Failed: {}", e),
            }
        }
        ("room", "new", _) if role.has_mod() => "Usage: /room_new <name>".to_string(),
        ("room", "del", name) if role.has_mod() && !name.is_empty() => {
            if let Some(room_id) = find_room_by_name(ctx, name).await? {
                delete_blind_group(ctx, room_id).await?;
                format!("Room '{}' deleted", name)
            } else {
                format!("Room '{}' not found", name)
            }
        }
        ("room", "del", _) if role.has_mod() => "Usage: /room_del <name>".to_string(),
        ("room", "avatar", "remove") if in_room && role.has_mod() => {
            set_room_avatar(ctx, chat_id, None).await?;
            "Room avatar removed".to_string()
        }
        ("room", "avatar", _) if in_room && role.has_mod() => {
            if let Some(file) = msg.get_file(ctx) {
                set_room_avatar(ctx, chat_id, Some(&file)).await?;
                "Room avatar updated".to_string()
            } else {
                "Attach an image or: /room_avatar_remove".to_string()
            }
        }
        // ("room", "name", name) if in_room && role.has_mod() && !name.is_empty() => { rename_room(ctx, chat_id, name).await?; format!("Room renamed to '{}'", name) }
        // ("room", "name", _) if in_room && role.has_mod() => "Usage: /room_name <newname>".to_string(),
        ("room", "history", n) if in_room => {
            get_room_history(ctx, chat_id, n.parse().unwrap_or(10)).await?
        }
        ("room", _, _) if in_room => {
            let cmds = if role.has_mod() {
                "/room_new, /room_del, /room_avatar, /room_history"
            } else {
                "/room_history"
            };
            let members = get_broadcast_members(ctx, chat_id).await?;
            let mut addrs = Vec::new();
            for c in &members {
                addrs.push(Contact::get_by_id(ctx, *c).await?.get_addr().to_string());
            }
            format!(
                "Commands: {}\nMembers ({}): {}",
                cmds,
                members.len(),
                addrs.join(", ")
            )
        }

        ("del", "", "") if in_room && role.has_mod() => {
            if let Some(q) = quoted {
                let target_id = if let Some(relayed) = get_relayed_msg(ctx, &q.rfc724_mid).await? {
                    relayed.get_id()
                } else {
                    q.get_id()
                };
                request_message_deletion(ctx, chat_id, target_id).await?;
                "Message deleted".to_string()
            } else {
                "Reply to a message to delete it".to_string()
            }
        }
        ("del", _, _) if role.has_mod() => {
            "Reply to a message with /del (only in rooms)".to_string()
        }

        // ("ban", addr, "") if role.has_mod() && !addr.is_empty() => {
        //     match Contact::lookup_id_by_addr(ctx, addr, crate::contact::Origin::Unknown).await? {
        //         Some(id) => { Contact::block(ctx, id).await?; if in_room { remove_member_from_broadcast(ctx, chat_id, id).await?; } format!("{} banned", addr) }
        //         None => format!("Contact '{}' not found", addr)
        //     }
        // }
        // ("ban", "", "") if in_room && role.has_mod() => {
        //     if let Some(q) = &quoted {
        //         if let Some((orig_sender, _)) = get_relay_info(ctx, q.get_id()).await? {
        //             let c = Contact::get_by_id(ctx, orig_sender).await?;
        //             Contact::block(ctx, orig_sender).await?;
        //             remove_member_from_broadcast(ctx, chat_id, orig_sender).await?;
        //             format!("Banned {}", c.get_display_name())
        //         } else { "Cannot identify sender".to_string() }
        //     } else { "Reply to a message or: /ban_addr@example.org".to_string() }
        // }
        // ("ban", _, _) if role.has_mod() => "Reply to a message or: /ban_addr@example.org".to_string(),

        // ("unban", addr, "") if role.has_mod() && !addr.is_empty() => {
        //     match Contact::lookup_id_by_addr(ctx, addr, crate::contact::Origin::Unknown).await? {
        //         Some(id) => { Contact::unblock(ctx, id).await?; format!("{} unbanned", addr) }
        //         None => format!("Contact '{}' not found", addr)
        //     }
        // }
        // ("unban", _, _) if role.has_mod() => "Usage: /unban_addr@example.org".to_string(),

        // ("bans", "", "") if role.has_mod() => get_bans_list(ctx).await?,
        ("admin", "mod", addr) if role.has_admin() && !addr.is_empty() => {
            match Contact::lookup_id_by_addr(ctx, addr, crate::contact::Origin::Unknown).await? {
                Some(id) => {
                    set_role(ctx, id, Role::Mod).await?;
                    format!("{} is now a moderator", addr)
                }
                None => format!("Contact '{}' not found", addr),
            }
        }
        ("admin", "unmod", addr) if role.has_admin() && !addr.is_empty() => {
            match Contact::lookup_id_by_addr(ctx, addr, crate::contact::Origin::Unknown).await? {
                Some(id) => {
                    remove_role(ctx, id).await?;
                    format!("{} is no longer a moderator", addr)
                }
                None => format!("Contact '{}' not found", addr),
            }
        }
        ("admin", "name", name) if role.has_admin() && !name.is_empty() => {
            set_bot_displayname(ctx, name).await?;
            format!("Bot name set to '{}'", name)
        }
        ("admin", "avatar", "remove") if role.has_admin() => {
            set_bot_avatar(ctx, None).await?;
            "Bot avatar removed".to_string()
        }
        ("admin", "avatar", _) if role.has_admin() => {
            if let Some(file) = msg.get_file(ctx) {
                set_bot_avatar(ctx, Some(&file)).await?;
                "Bot avatar updated".to_string()
            } else {
                "Attach an image to /admin_avatar or: /admin_avatar_remove".to_string()
            }
        }
        ("admin", _, _) if role.has_admin() => {
            "Commands: /admin_mod <addr>, /admin_unmod <addr>, /admin_name <name>, /admin_avatar"
                .to_string()
        }

        _ => get_help_text(in_room, role),
    };

    let mut reply = Message::new_text(response);
    reply.set_quote(ctx, Some(msg)).await?;
    if in_room {
        let exclude: Vec<_> = get_broadcast_members(ctx, chat_id)
            .await?
            .into_iter()
            .filter(|m| *m != from)
            .collect();
        send_to_subset(ctx, chat_id, &exclude, || async {
            send_msg(ctx, chat_id, &mut reply).await.map(|_| ())
        })
        .await?;
    } else {
        send_msg(ctx, chat_id, &mut reply).await?;
    }
    Ok(true)
}

async fn store_relay_reaction(
    ctx: &Context,
    msg_id: crate::message::MsgId,
    contact_id: ContactId,
    emoji: &str,
) -> Result<()> {
    if emoji.is_empty() {
        ctx.sql
            .execute(
                "DELETE FROM relay_reactions WHERE msg_id=? AND contact_id=?",
                (msg_id, contact_id),
            )
            .await?;
    } else {
        ctx.sql.execute("INSERT OR REPLACE INTO relay_reactions (msg_id, contact_id, emoji) VALUES (?, ?, ?)", (msg_id, contact_id, emoji)).await?;
    }
    Ok(())
}

async fn get_relay_reaction(
    ctx: &Context,
    msg_id: crate::message::MsgId,
    contact_id: ContactId,
) -> Result<Option<String>> {
    ctx.sql
        .query_get_value(
            "SELECT emoji FROM relay_reactions WHERE msg_id=? AND contact_id=?",
            (msg_id, contact_id),
        )
        .await
}

fn format_reaction_counts(counts: &std::collections::BTreeMap<String, i32>) -> String {
    let mut sorted: Vec<(String, i32)> = counts
        .iter()
        .map(|(k, v)| (k.clone(), *v))
        .filter(|(_, c)| *c > 0)
        .collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    sorted
        .iter()
        .map(|(e, c)| {
            if *c > 1 {
                format!("{}{}", e, c)
            } else {
                e.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

async fn get_reaction_counts(
    ctx: &Context,
    msg_id: crate::message::MsgId,
) -> Result<std::collections::BTreeMap<String, i32>> {
    let rows: Vec<String> = ctx
        .sql
        .query_map(
            "SELECT emoji FROM relay_reactions WHERE msg_id=?",
            (msg_id,),
            |row| Ok(row.get::<_, String>(0)?),
            |rows| rows.collect::<Result<Vec<_>, _>>().map_err(Into::into),
        )
        .await?;
    let mut counts = std::collections::BTreeMap::new();
    for emoji in rows {
        *counts.entry(emoji).or_insert(0) += 1;
    }
    Ok(counts)
}

#[cfg(test)]
async fn get_aggregated_relay_reactions(
    ctx: &Context,
    msg_id: crate::message::MsgId,
) -> Result<String> {
    Ok(format_reaction_counts(
        &get_reaction_counts(ctx, msg_id).await?,
    ))
}

async fn get_reactors(ctx: &Context, msg_id: crate::message::MsgId) -> Result<Vec<ContactId>> {
    ctx.sql
        .query_map(
            "SELECT contact_id FROM relay_reactions WHERE msg_id=?",
            (msg_id,),
            |row| Ok(ContactId::new(row.get(0)?)),
            |rows| rows.collect::<Result<Vec<_>, _>>().map_err(Into::into),
        )
        .await
}

/// Relay an incoming reaction to a blind group broadcast
pub async fn relay_incoming_reaction(
    ctx: &Context,
    broadcast_id: ChatId,
    from: ContactId,
    target_msg_id: crate::message::MsgId,
    reaction: &str,
) -> Result<()> {
    use crate::param::Param;
    info!(
        ctx,
        "Relaying reaction '{}' from {} on msg {} to broadcast {}",
        reaction,
        from,
        target_msg_id,
        broadcast_id
    );
    store_relay_reaction(ctx, target_msg_id, from, reaction).await?;
    let counts = get_reaction_counts(ctx, target_msg_id).await?;
    let aggregated = format_reaction_counts(&counts);
    let target_msg = Message::load_from_db(ctx, target_msg_id).await?;
    let relay_info = get_relay_info(ctx, target_msg_id).await?;
    let mut reactors = get_reactors(ctx, target_msg_id).await?;
    if let Some((os, _)) = &relay_info {
        if !reactors.contains(os) {
            reactors.push(*os);
        }
    }
    let reaction_text = if aggregated.is_empty() {
        " ".to_string()
    } else {
        aggregated.clone()
    };
    let mut reaction_msg = Message::new_text(reaction_text);
    reaction_msg.param.set_int(Param::Reaction, 1);
    reaction_msg.in_reply_to = Some(target_msg.rfc724_mid.clone());
    reaction_msg.hidden = true;
    send_to_subset(ctx, broadcast_id, &reactors, || async {
        send_msg(ctx, broadcast_id, &mut reaction_msg)
            .await
            .map(|_| ())
    })
    .await?;
    for reactor in reactors {
        if reactor == from {
            continue;
        }
        let their_reaction = get_relay_reaction(ctx, target_msg_id, reactor).await?;
        let their_text = if let Some(emoji) = their_reaction {
            let mut their_counts = counts.clone();
            *their_counts.entry(emoji).or_insert(1) -= 1;
            format_reaction_counts(&their_counts)
        } else {
            aggregated.clone()
        };
        let text = if their_text.is_empty() {
            " ".to_string()
        } else {
            their_text
        };
        let mut msg = Message::new_text(text);
        msg.param.set_int(Param::Reaction, 1);
        let reply_mid = if let Some((os, orig_mid)) = &relay_info {
            if reactor == *os {
                orig_mid.clone()
            } else {
                target_msg.rfc724_mid.clone()
            }
        } else {
            target_msg.rfc724_mid.clone()
        };
        msg.in_reply_to = Some(reply_mid);
        msg.hidden = true;
        let exclude: Vec<_> = get_broadcast_members(ctx, broadcast_id)
            .await?
            .into_iter()
            .filter(|m| *m != reactor)
            .collect();
        send_to_subset(ctx, broadcast_id, &exclude, || async {
            send_msg(ctx, broadcast_id, &mut msg).await.map(|_| ())
        })
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::{add_contact_to_chat, create_unique_blind_group, remove_contact_from_chat};
    use crate::message::Viewtype;
    use crate::test_utils::TestContextManager;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_create_room_requires_mod() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let bot = tcm.alice().await;
        let admin = tcm.bob().await;
        let user = tcm.fiona().await;
        tcm.execute_securejoin(&admin, &bot).await;
        tcm.execute_securejoin(&user, &bot).await;

        init_bot_tables(&bot).await?;
        let admin_contact = bot.add_or_lookup_contact(&admin).await.id;
        let user_contact = bot.add_or_lookup_contact(&user).await.id;
        set_role(&bot, admin_contact, Role::Admin).await?;

        assert!(
            !get_verified_role(&bot, user_contact).await?.has_mod(),
            "Non-mod should not have mod permissions"
        );
        assert!(
            get_verified_role(&bot, admin_contact).await?.has_mod(),
            "Admin should have mod permissions"
        );
        assert!(
            get_verified_role(&bot, admin_contact).await?.has_admin(),
            "Admin should have admin permissions"
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_relay_bot_flow() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let bot = tcm.alice().await;
        bot.set_config(crate::config::Config::Bot, Some("1"))
            .await?;
        let user1 = tcm.bob().await;
        let user2 = tcm.fiona().await;

        tcm.execute_securejoin(&user1, &bot).await;
        tcm.execute_securejoin(&user2, &bot).await;

        init_bot_tables(&bot).await?;
        let broadcast_id = create_unique_blind_group(&bot, "lobby".to_string()).await?;
        let user1_contact = bot.add_or_lookup_contact(&user1).await.id;
        let user2_contact = bot.add_or_lookup_contact(&user2).await.id;
        add_contact_to_chat(&bot, broadcast_id, user1_contact).await?;
        add_contact_to_chat(&bot, broadcast_id, user2_contact).await?;

        let members = get_broadcast_members(&bot, broadcast_id).await?;
        println!("Broadcast members: {:?}", members);
        assert_eq!(members.len(), 2);

        let user1_chat = user1.get_chat(&bot).await;
        let mut user1_msg = Message::new_text("Hello from user1".to_string());
        crate::chat::send_msg(&user1, user1_chat.id, &mut user1_msg).await?;
        let user1_sent = user1.pop_sent_msg().await;
        let bot_received_user1 = bot.recv_msg(&user1_sent).await;

        relay_message(&bot, broadcast_id, user1_contact, &bot_received_user1).await?;
        let sent = bot.pop_sent_msg().await;
        println!("Recipients: {:?}", sent.recipients);

        let user2_msg = user2.recv_msg(&sent).await;
        println!("User2 received: '{}'", user2_msg.text);

        let mut reply_msg = Message::new_text("Reply to first".to_string());
        reply_msg.set_quote(&user2, Some(&user2_msg)).await?;
        crate::chat::send_msg(&user2, user2_msg.chat_id, &mut reply_msg).await?;
        let reply_sent = user2.pop_sent_msg().await;
        let bot_received = bot.recv_msg(&reply_sent).await;
        let has_quote = bot_received.quoted_message(&bot).await?.is_some();
        println!("Bot received reply, has quote: {}", has_quote);
        assert!(has_quote, "Bot should receive reply with quote");

        relay_message(&bot, broadcast_id, user2_contact, &bot_received).await?;
        let relayed = bot.pop_sent_msg().await;
        println!("First msg recipients: {:?}", relayed.recipients);
        let user1_received = user1.recv_msg(&relayed).await;
        let user1_has_quote = user1_received.quoted_text().is_some();
        println!(
            "User1 received: '{}', has quote: {}",
            user1_received.text, user1_has_quote
        );
        assert!(user1_has_quote, "Reply should preserve quote");
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_relay_image() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let bot = tcm.alice().await;
        let user1 = tcm.bob().await;
        let user2 = tcm.fiona().await;
        tcm.execute_securejoin(&user1, &bot).await;
        tcm.execute_securejoin(&user2, &bot).await;

        let broadcast_id = create_unique_blind_group(&bot, "lobby".to_string()).await?;
        let user1_contact = bot.add_or_lookup_contact(&user1).await.id;
        let user2_contact = bot.add_or_lookup_contact(&user2).await.id;
        add_contact_to_chat(&bot, broadcast_id, user1_contact).await?;
        add_contact_to_chat(&bot, broadcast_id, user2_contact).await?;

        let file = user1.get_blobdir().join("test.png");
        tokio::fs::write(&file, include_bytes!("../test-data/image/avatar64x64.png")).await?;
        let mut img_msg = Message::new(Viewtype::Image);
        img_msg.set_file_and_deduplicate(&user1, &file, Some("test.png"), None)?;

        let user1_chat = user1.get_chat(&bot).await;
        crate::chat::send_msg(&user1, user1_chat.id, &mut img_msg).await?;
        let sent = user1.pop_sent_msg().await;
        let bot_received = bot.recv_msg(&sent).await;

        relay_message(&bot, broadcast_id, user1_contact, &bot_received).await?;
        let relayed = bot.pop_sent_msg().await;
        let user2_received = user2.recv_msg(&relayed).await;

        assert_eq!(user2_received.get_viewtype(), Viewtype::Image);
        assert!(user2_received.get_text().is_empty());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_relay_image_with_text() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let bot = tcm.alice().await;
        let user1 = tcm.bob().await;
        let user2 = tcm.fiona().await;
        tcm.execute_securejoin(&user1, &bot).await;
        tcm.execute_securejoin(&user2, &bot).await;

        let broadcast_id = create_unique_blind_group(&bot, "lobby".to_string()).await?;
        let user1_contact = bot.add_or_lookup_contact(&user1).await.id;
        let user2_contact = bot.add_or_lookup_contact(&user2).await.id;
        add_contact_to_chat(&bot, broadcast_id, user1_contact).await?;
        add_contact_to_chat(&bot, broadcast_id, user2_contact).await?;

        let file = user1.get_blobdir().join("test.png");
        tokio::fs::write(&file, include_bytes!("../test-data/image/avatar64x64.png")).await?;
        let mut img_msg = Message::new(Viewtype::Image);
        img_msg.set_text("Check out this image!".to_string());
        img_msg.set_file_and_deduplicate(&user1, &file, Some("test.png"), None)?;

        let user1_chat = user1.get_chat(&bot).await;
        crate::chat::send_msg(&user1, user1_chat.id, &mut img_msg).await?;
        let sent = user1.pop_sent_msg().await;
        let bot_received = bot.recv_msg(&sent).await;

        relay_message(&bot, broadcast_id, user1_contact, &bot_received).await?;
        let relayed = bot.pop_sent_msg().await;
        let user2_received = user2.recv_msg(&relayed).await;

        assert_eq!(user2_received.get_viewtype(), Viewtype::Image);
        assert_eq!(user2_received.get_text(), "Check out this image!");
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_leave_blind_group() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let bot = tcm.alice().await;
        let user1 = tcm.bob().await;
        let user2 = tcm.fiona().await;
        tcm.execute_securejoin(&user1, &bot).await;
        tcm.execute_securejoin(&user2, &bot).await;

        let broadcast_id = create_unique_blind_group(&bot, "lobby".to_string()).await?;
        let user1_contact = bot.add_or_lookup_contact(&user1).await.id;
        let user2_contact = bot.add_or_lookup_contact(&user2).await.id;
        add_contact_to_chat(&bot, broadcast_id, user1_contact).await?;
        add_contact_to_chat(&bot, broadcast_id, user2_contact).await?;

        relay_to_broadcast(&bot, broadcast_id, user2_contact, "Welcome", "orig-2@test").await?;
        let sent = bot.pop_sent_msg().await;
        let user1_msg = user1.recv_msg(&sent).await;
        let user1_chat_id = user1_msg.chat_id;

        assert_eq!(get_broadcast_members(&bot, broadcast_id).await?.len(), 2);

        remove_contact_from_chat(&user1, user1_chat_id, crate::contact::ContactId::SELF).await?;
        let leave_sent = user1.pop_sent_msg().await;
        let leave_msg = bot.recv_msg(&leave_sent).await;

        assert!(is_leave_message(&leave_msg), "Should detect leave message");
        remove_member_from_broadcast(&bot, broadcast_id, user1_contact).await?;
        assert_eq!(get_broadcast_members(&bot, broadcast_id).await?.len(), 1);

        relay_to_broadcast(
            &bot,
            broadcast_id,
            user2_contact,
            "User1 is gone",
            "orig-3@test",
        )
        .await?;
        let sent2 = bot.pop_sent_msg().await;
        assert!(
            !sent2.recipients.contains("bob"),
            "User1 should not receive messages after leaving"
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_relay_reaction_removal() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let bot = tcm.alice().await;
        let user1 = tcm.bob().await;
        let user2 = tcm.fiona().await;
        tcm.execute_securejoin(&user1, &bot).await;
        tcm.execute_securejoin(&user2, &bot).await;

        let broadcast_id = create_unique_blind_group(&bot, "lobby".to_string()).await?;
        let user1_contact = bot.add_or_lookup_contact(&user1).await.id;
        let user2_contact = bot.add_or_lookup_contact(&user2).await.id;
        add_contact_to_chat(&bot, broadcast_id, user1_contact).await?;
        add_contact_to_chat(&bot, broadcast_id, user2_contact).await?;

        relay_to_broadcast(&bot, broadcast_id, user1_contact, "Test", "orig-4@test").await?;
        let sent = bot.pop_sent_msg().await;
        let bot_msg_id = sent.sender_msg_id;
        let user2_msg = user2.recv_msg(&sent).await;

        crate::reaction::send_reaction(&user2, user2_msg.id, "👍").await?;
        let reaction_sent = user2.pop_sent_msg().await;
        bot.recv_msg_hidden(&reaction_sent).await;

        crate::reaction::send_reaction(&user2, user2_msg.id, "").await?;
        let removal_sent = user2.pop_sent_msg().await;
        bot.recv_msg_hidden(&removal_sent).await;

        let agg = get_aggregated_relay_reactions(&bot, bot_msg_id).await?;
        assert_eq!(agg, "");
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_relay_reaction() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let bot = tcm.alice().await;
        let user1 = tcm.bob().await;
        let user2 = tcm.fiona().await;
        tcm.execute_securejoin(&user1, &bot).await;
        tcm.execute_securejoin(&user2, &bot).await;

        let broadcast_id = create_unique_blind_group(&bot, "lobby".to_string()).await?;
        let user1_contact = bot.add_or_lookup_contact(&user1).await.id;
        let user2_contact = bot.add_or_lookup_contact(&user2).await.id;
        add_contact_to_chat(&bot, broadcast_id, user1_contact).await?;
        add_contact_to_chat(&bot, broadcast_id, user2_contact).await?;

        relay_to_broadcast(
            &bot,
            broadcast_id,
            user1_contact,
            "Hello everyone",
            "orig-5@test",
        )
        .await?;
        let sent = bot.pop_sent_msg().await;
        let bot_msg_id = sent.sender_msg_id;
        user2.recv_msg(&sent).await;

        relay_incoming_reaction(&bot, broadcast_id, user2_contact, bot_msg_id, "👍").await?;
        bot.pop_sent_msg().await;

        relay_incoming_reaction(&bot, broadcast_id, user1_contact, bot_msg_id, "👍").await?;
        let agg = get_aggregated_relay_reactions(&bot, bot_msg_id).await?;
        assert_eq!(agg, "👍2");
        bot.pop_sent_msg().await;

        relay_incoming_reaction(&bot, broadcast_id, user2_contact, bot_msg_id, "❤️").await?;
        let agg2 = get_aggregated_relay_reactions(&bot, bot_msg_id).await?;
        assert_eq!(agg2, "❤️ 👍");

        relay_incoming_reaction(&bot, broadcast_id, user1_contact, bot_msg_id, "").await?;
        let agg3 = get_aggregated_relay_reactions(&bot, bot_msg_id).await?;
        assert_eq!(agg3, "❤️");
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_relay_excludes_sender() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let bot = tcm.alice().await;
        let user1 = tcm.bob().await;
        let user2 = tcm.fiona().await;
        tcm.execute_securejoin(&user1, &bot).await;
        tcm.execute_securejoin(&user2, &bot).await;

        let broadcast_id = create_unique_blind_group(&bot, "lobby".to_string()).await?;
        let user1_contact = bot.add_or_lookup_contact(&user1).await.id;
        let user2_contact = bot.add_or_lookup_contact(&user2).await.id;
        add_contact_to_chat(&bot, broadcast_id, user1_contact).await?;
        add_contact_to_chat(&bot, broadcast_id, user2_contact).await?;

        relay_to_broadcast(
            &bot,
            broadcast_id,
            user1_contact,
            "Hello from user1",
            "orig-6@test",
        )
        .await?;
        let sent = bot.pop_sent_msg().await;
        assert!(
            !sent.recipients.contains("bob"),
            "Sender should not receive their own message"
        );
        assert!(
            sent.recipients.contains("fiona"),
            "Other members should receive message"
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_reaction_excludes_sender() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let bot = tcm.alice().await;
        let user1 = tcm.bob().await;
        let user2 = tcm.fiona().await;
        tcm.execute_securejoin(&user1, &bot).await;
        tcm.execute_securejoin(&user2, &bot).await;

        let broadcast_id = create_unique_blind_group(&bot, "lobby".to_string()).await?;
        let user1_contact = bot.add_or_lookup_contact(&user1).await.id;
        let user2_contact = bot.add_or_lookup_contact(&user2).await.id;
        add_contact_to_chat(&bot, broadcast_id, user1_contact).await?;
        add_contact_to_chat(&bot, broadcast_id, user2_contact).await?;

        relay_to_broadcast(&bot, broadcast_id, user1_contact, "Test", "orig-7@test").await?;
        let sent = bot.pop_sent_msg().await;
        let bot_msg_id = sent.sender_msg_id;
        user2.recv_msg(&sent).await;

        let orig = get_relay_info(&bot, bot_msg_id).await?;
        assert!(orig.is_some(), "Relay info should be stored");
        assert_eq!(
            orig.unwrap().0,
            user1_contact,
            "Original sender should be stored"
        );
        relay_incoming_reaction(&bot, broadcast_id, user2_contact, bot_msg_id, "👍").await?;
        let msg = bot.pop_sent_msg().await;
        assert!(
            msg.recipients.contains("bob"),
            "Original sender should receive reaction"
        );
        user1.recv_msg_hidden(&msg).await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_original_sender_reacts_own_message() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let bot = tcm.alice().await;
        let user1 = tcm.bob().await;
        let user2 = tcm.fiona().await;
        tcm.execute_securejoin(&user1, &bot).await;
        tcm.execute_securejoin(&user2, &bot).await;

        let broadcast_id = create_unique_blind_group(&bot, "lobby".to_string()).await?;
        let user1_contact = bot.add_or_lookup_contact(&user1).await.id;
        let user2_contact = bot.add_or_lookup_contact(&user2).await.id;
        add_contact_to_chat(&bot, broadcast_id, user1_contact).await?;
        add_contact_to_chat(&bot, broadcast_id, user2_contact).await?;

        let user1_chat = user1.get_chat(&bot).await;
        let mut orig_msg = crate::message::Message::new_text("Hello".to_string());
        crate::chat::send_msg(&user1, user1_chat.id, &mut orig_msg).await?;
        let sent_to_bot = user1.pop_sent_msg().await;
        let bot_received = bot.recv_msg(&sent_to_bot).await;

        relay_message(&bot, broadcast_id, user1_contact, &bot_received).await?;
        let relayed = bot.pop_sent_msg().await;
        user2.recv_msg(&relayed).await;

        let target_msg_id =
            if let Some(relayed) = get_relayed_msg(&bot, &bot_received.rfc724_mid).await? {
                relayed.get_id()
            } else {
                bot_received.id
            };
        relay_incoming_reaction(&bot, broadcast_id, user1_contact, target_msg_id, "👍").await?;
        let reaction_relayed = bot.pop_sent_msg().await;
        assert!(
            reaction_relayed.recipients.contains("fiona"),
            "User2 should receive original sender's reaction"
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_reaction_count_excludes_each_user() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let bot = tcm.alice().await;
        let user1 = tcm.bob().await;
        let user2 = tcm.fiona().await;
        tcm.execute_securejoin(&user1, &bot).await;
        tcm.execute_securejoin(&user2, &bot).await;

        let broadcast_id = create_unique_blind_group(&bot, "lobby".to_string()).await?;
        let user1_contact = bot.add_or_lookup_contact(&user1).await.id;
        let user2_contact = bot.add_or_lookup_contact(&user2).await.id;
        add_contact_to_chat(&bot, broadcast_id, user1_contact).await?;
        add_contact_to_chat(&bot, broadcast_id, user2_contact).await?;

        relay_to_broadcast(&bot, broadcast_id, user1_contact, "Test", "orig-8@test").await?;
        let sent = bot.pop_sent_msg().await;
        let bot_msg_id = sent.sender_msg_id;
        user2.recv_msg(&sent).await;

        relay_incoming_reaction(&bot, broadcast_id, user2_contact, bot_msg_id, "👍").await?;
        let r1 = bot.pop_sent_msg().await;
        assert!(
            !r1.recipients.contains("fiona"),
            "user2's reaction should not go to user2"
        );
        let r1_msg = Message::load_from_db(&bot, r1.sender_msg_id).await?;
        assert_eq!(r1_msg.text, "👍", "First reaction should show 👍");
        user1.recv_msg_hidden(&r1).await;

        relay_incoming_reaction(&bot, broadcast_id, user1_contact, bot_msg_id, "👍").await?;
        let r2 = bot.pop_sent_msg().await;
        assert!(r2.recipients.contains("fiona"), "user2 should get reaction");
        let r2_msg = Message::load_from_db(&bot, r2.sender_msg_id).await?;
        assert_eq!(
            r2_msg.text, "👍",
            "user2 should see count=1 (their own excluded)"
        );
        user2.recv_msg_hidden(&r2).await;

        let agg = get_aggregated_relay_reactions(&bot, bot_msg_id).await?;
        assert_eq!(agg, "👍2", "Bot should track both reactions");
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_blind_group_qr_join() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let bot = tcm.alice().await;
        let user = tcm.bob().await;

        let broadcast_id = create_unique_blind_group(&bot, "lobby".to_string()).await?;
        let qr = crate::securejoin::get_securejoin_qr(&bot, Some(broadcast_id)).await?;
        assert!(qr.contains("g=lobby"), "QR should contain group name");
        assert!(qr.contains("x="), "QR should contain grpid");

        tcm.execute_securejoin(&user, &bot).await;
        let user_contact = bot.add_or_lookup_contact(&user).await.id;
        crate::chat::add_contact_to_chat(&bot, broadcast_id, user_contact).await?;

        let members = get_broadcast_members(&bot, broadcast_id).await?;
        assert_eq!(members.len(), 1, "User should be added to BlindGroup");
        assert_eq!(members[0], user_contact);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_blind_group_securejoin_flow() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let bot = tcm.alice().await;
        let user = tcm.bob().await;

        let broadcast_id = create_unique_blind_group(&bot, "lobby".to_string()).await?;
        let qr = crate::securejoin::get_securejoin_qr(&bot, Some(broadcast_id)).await?;
        tcm.exec_securejoin_qr(&user, &bot, &qr).await;

        let members = get_broadcast_members(&bot, broadcast_id).await?;
        assert_eq!(members.len(), 1, "User should be auto-added via SecureJoin");

        let user_chatlist = crate::chatlist::Chatlist::try_load(&user, 0, None, None).await?;
        let mut user_group_chat = None;
        for (cid, _) in user_chatlist.iter() {
            let c = crate::chat::Chat::load_from_db(&user, *cid).await?;
            if c.get_name() == "lobby" && c.get_type() == crate::constants::Chattype::Group {
                user_group_chat = Some(c);
                break;
            }
        }
        let user_chat = user_group_chat.expect("User should see BlindGroup as regular Group");
        assert!(
            user_chat.can_send(&user).await?,
            "User should be able to send to the group"
        );

        let mut msg = Message::new_text("Hello from user".to_string());
        crate::chat::send_msg(&user, user_chat.id, &mut msg).await?;
        let sent = user.pop_sent_msg().await;
        let bot_received = bot.recv_msg(&sent).await;
        assert_eq!(bot_received.get_text(), "Hello from user");
        assert_eq!(bot_received.get_chat_id(), broadcast_id);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_second_user_joins_blind_group() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let bot = tcm.alice().await;
        let user1 = tcm.bob().await;
        let user2 = tcm.fiona().await;

        let broadcast_id = create_unique_blind_group(&bot, "lobby".to_string()).await?;
        let qr = crate::securejoin::get_securejoin_qr(&bot, Some(broadcast_id)).await?;
        tcm.exec_securejoin_qr(&user1, &bot, &qr).await;
        assert_eq!(get_broadcast_members(&bot, broadcast_id).await?.len(), 1);

        let qr2 = crate::securejoin::get_securejoin_qr(&bot, Some(broadcast_id)).await?;
        tcm.exec_securejoin_qr(&user2, &bot, &qr2).await;
        assert_eq!(get_broadcast_members(&bot, broadcast_id).await?.len(), 2);

        let user2_chatlist = crate::chatlist::Chatlist::try_load(&user2, 0, None, None).await?;
        let mut user2_group = None;
        for (cid, _) in user2_chatlist.iter() {
            let c = crate::chat::Chat::load_from_db(&user2, *cid).await?;
            if c.get_name() == "lobby" && c.get_type() == crate::constants::Chattype::Group {
                user2_group = Some(c);
                break;
            }
        }
        let user2_chat = user2_group.expect("User2 should see group");
        assert!(
            user2_chat.can_send(&user2).await?,
            "User2 should be able to send"
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_dm_after_blind_group_join() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let bot = tcm.alice().await;
        let user = tcm.bob().await;

        let broadcast_id = create_unique_blind_group(&bot, "lobby".to_string()).await?;
        let qr = crate::securejoin::get_securejoin_qr(&bot, Some(broadcast_id)).await?;
        tcm.exec_securejoin_qr(&user, &bot, &qr).await;

        let bot_chat = user.get_chat(&bot).await;
        let mut msg = Message::new_text("/help".to_string());
        crate::chat::send_msg(&user, bot_chat.id, &mut msg).await?;
        let sent = user.pop_sent_msg().await;
        let events = bot.get_event_emitter();
        bot.recv_msg(&sent).await;

        let mut got_incoming = false;
        while let Ok(event) =
            tokio::time::timeout(std::time::Duration::from_millis(100), events.recv()).await
        {
            if let Some(ev) = event {
                if matches!(ev.typ, crate::EventType::IncomingMsg { .. }) {
                    got_incoming = true;
                    break;
                }
            }
        }
        assert!(
            got_incoming,
            "Should receive IncomingMsg event for 1:1 message after BlindGroup join"
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_duplicate_blind_group_rejected() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let bot = tcm.alice().await;
        create_unique_blind_group(&bot, "lobby".to_string()).await?;
        let result = create_unique_blind_group(&bot, "lobby".to_string()).await;
        assert!(result.is_err(), "Duplicate room name should be rejected");
        assert!(result.unwrap_err().to_string().contains("already exists"));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_delete_blind_group() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let bot = tcm.alice().await;
        let user = tcm.bob().await;
        tcm.execute_securejoin(&user, &bot).await;

        let broadcast_id = create_unique_blind_group(&bot, "testroom".to_string()).await?;
        let user_contact = bot.add_or_lookup_contact(&user).await.id;
        add_contact_to_chat(&bot, broadcast_id, user_contact).await?;
        assert_eq!(get_broadcast_members(&bot, broadcast_id).await?.len(), 1);

        delete_blind_group(&bot, broadcast_id).await?;

        let chatlist = crate::chatlist::Chatlist::try_load(&bot, 0, None, None).await?;
        for (cid, _) in chatlist.iter() {
            assert_ne!(
                *cid, broadcast_id,
                "Deleted blind group should not appear in chatlist"
            );
        }
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_delete_blind_group_notifies_members() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let bot = tcm.alice().await;
        let user1 = tcm.bob().await;
        let user2 = tcm.fiona().await;
        tcm.execute_securejoin(&user1, &bot).await;
        tcm.execute_securejoin(&user2, &bot).await;
        init_bot_tables(&bot).await?;

        let broadcast_id = create_unique_blind_group(&bot, "testroom".to_string()).await?;
        let user1_contact = bot.add_or_lookup_contact(&user1).await.id;
        let user2_contact = bot.add_or_lookup_contact(&user2).await.id;
        add_contact_to_chat(&bot, broadcast_id, user1_contact).await?;
        add_contact_to_chat(&bot, broadcast_id, user2_contact).await?;

        relay_to_broadcast(&bot, broadcast_id, user1_contact, "Hello", "orig-del@test").await?;
        let sent = bot.pop_sent_msg().await;
        user2.recv_msg(&sent).await;

        delete_blind_group(&bot, broadcast_id).await?;

        let mut removal_count = 0;
        while let Some(_) = bot
            .pop_sent_msg_opt(std::time::Duration::from_millis(200))
            .await
        {
            removal_count += 1;
        }
        assert!(
            removal_count >= 2,
            "Should send at least 2 removal messages, got {}",
            removal_count
        );

        let chatlist = crate::chatlist::Chatlist::try_load(&bot, 0, None, None).await?;
        for (cid, _) in chatlist.iter() {
            assert!(
                *cid != broadcast_id,
                "Deleted blind group should not appear in chatlist"
            );
        }
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_reply_quote_references() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let bot = tcm.alice().await;
        bot.set_config(crate::config::Config::Bot, Some("1"))
            .await?;
        let alice = tcm.bob().await;
        let bob = tcm.fiona().await;
        tcm.execute_securejoin(&alice, &bot).await;
        tcm.execute_securejoin(&bob, &bot).await;

        let broadcast_id = create_unique_blind_group(&bot, "lobby".to_string()).await?;
        let alice_contact = bot.add_or_lookup_contact(&alice).await.id;
        let bob_contact = bot.add_or_lookup_contact(&bob).await.id;
        add_contact_to_chat(&bot, broadcast_id, alice_contact).await?;
        add_contact_to_chat(&bot, broadcast_id, bob_contact).await?;

        let alice_chat = alice.get_chat(&bot).await;
        let mut alice_msg = Message::new_text("Hello from Alice".to_string());
        crate::chat::send_msg(&alice, alice_chat.id, &mut alice_msg).await?;
        let alice_sent = alice.pop_sent_msg().await;
        let alice_original_mid = Message::load_from_db(&alice, alice_sent.sender_msg_id)
            .await?
            .rfc724_mid
            .clone();
        let bot_received_alice = bot.recv_msg(&alice_sent).await;

        relay_message(&bot, broadcast_id, alice_contact, &bot_received_alice).await?;
        let relayed_alice = bot.pop_sent_msg().await;
        let relayed_alice_mid = Message::load_from_db(&bot, relayed_alice.sender_msg_id)
            .await?
            .rfc724_mid
            .clone();
        let bob_received_alice = bob.recv_msg(&relayed_alice).await;

        let mut bob_reply = Message::new_text("Bob's reply".to_string());
        bob_reply.set_quote(&bob, Some(&bob_received_alice)).await?;
        crate::chat::send_msg(&bob, bob_received_alice.chat_id, &mut bob_reply).await?;
        let bob_sent = bob.pop_sent_msg().await;
        let bot_received_bob = bot.recv_msg(&bob_sent).await;
        let quoted_by_bob = bot_received_bob.quoted_message(&bot).await?;
        assert!(quoted_by_bob.is_some(), "Bot should see Bob's quote");
        assert_eq!(
            quoted_by_bob.unwrap().rfc724_mid,
            relayed_alice_mid,
            "Bob quotes the relayed mid"
        );

        relay_message(&bot, broadcast_id, bob_contact, &bot_received_bob).await?;
        let relayed_bob = bot.pop_sent_msg().await;
        let alice_received = alice.recv_msg(&relayed_bob).await;
        let alice_quoted = alice_received.quoted_message(&alice).await?;
        assert!(
            alice_quoted.is_some(),
            "Alice should see quote in Bob's reply"
        );
        assert_eq!(
            alice_quoted.unwrap().rfc724_mid,
            alice_original_mid,
            "Alice should see HER ORIGINAL mid"
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_reply_quote_bob_replies_to_own() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let bot = tcm.alice().await;
        bot.set_config(crate::config::Config::Bot, Some("1"))
            .await?;
        let alice = tcm.bob().await;
        let bob = tcm.fiona().await;
        tcm.execute_securejoin(&alice, &bot).await;
        tcm.execute_securejoin(&bob, &bot).await;

        let broadcast_id = create_unique_blind_group(&bot, "lobby".to_string()).await?;
        let alice_contact = bot.add_or_lookup_contact(&alice).await.id;
        let bob_contact = bot.add_or_lookup_contact(&bob).await.id;
        add_contact_to_chat(&bot, broadcast_id, alice_contact).await?;
        add_contact_to_chat(&bot, broadcast_id, bob_contact).await?;

        let bob_chat = bob.get_chat(&bot).await;
        let mut bob_msg1 = Message::new_text("Bob's first message".to_string());
        crate::chat::send_msg(&bob, bob_chat.id, &mut bob_msg1).await?;
        let bob_sent1 = bob.pop_sent_msg().await;
        let bot_received1 = bot.recv_msg(&bob_sent1).await;

        relay_message(&bot, broadcast_id, bob_contact, &bot_received1).await?;
        let relayed1 = bot.pop_sent_msg().await;
        let relayed1_mid = Message::load_from_db(&bot, relayed1.sender_msg_id)
            .await?
            .rfc724_mid
            .clone();
        alice.recv_msg(&relayed1).await;

        let bob_local_msg1 = Message::load_from_db(&bob, bob_msg1.id).await?;
        let mut bob_reply = Message::new_text("Bob replies to himself".to_string());
        bob_reply.set_quote(&bob, Some(&bob_local_msg1)).await?;
        crate::chat::send_msg(&bob, bob_chat.id, &mut bob_reply).await?;
        let bob_sent2 = bob.pop_sent_msg().await;
        let bot_received2 = bot.recv_msg(&bob_sent2).await;

        relay_message(&bot, broadcast_id, bob_contact, &bot_received2).await?;
        let relayed2 = bot.pop_sent_msg().await;
        let alice_received = alice.recv_msg(&relayed2).await;
        let alice_quoted = alice_received.quoted_message(&alice).await?;
        assert!(
            alice_quoted.is_some(),
            "Alice should see quote in Bob's self-reply"
        );
        let alice_quoted_mid = alice_quoted.unwrap().rfc724_mid.clone();
        assert_eq!(
            alice_quoted_mid, relayed1_mid,
            "Alice should see Bob's PREVIOUS relayed message referenced"
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_room_command_stats() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let bot = tcm.alice().await;
        let mod_user = tcm.bob().await;
        tcm.execute_securejoin(&mod_user, &bot).await;

        init_bot_tables(&bot).await?;
        let mod_contact = bot.add_or_lookup_contact(&mod_user).await.id;
        set_role(&bot, mod_contact, Role::Mod).await?;

        let broadcast_id = create_unique_blind_group(&bot, "statsroom".to_string()).await?;
        add_contact_to_chat(&bot, broadcast_id, mod_contact).await?;

        let cmd_msg = Message::new_text("/room".to_string());
        let handled = handle_command(&bot, broadcast_id, mod_contact, &cmd_msg).await?;
        assert!(handled);
        let sent = bot.pop_sent_msg().await;
        let response = Message::load_from_db(&bot, sent.sender_msg_id)
            .await?
            .get_text();
        assert!(response.contains("Members (1)"));
        Ok(())
    }
}
