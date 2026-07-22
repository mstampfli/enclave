# Workspaces -- design & plan

Status: **IMPLEMENTED** (M0-M6, 2026-07). This document is now the design record;
the shipped feature follows the phased roadmap in section 10, and each milestone's
tests are cited in ARCHITECTURE.md roadmap item 8 and THREAT_MODEL.md "Workspaces".
The scale items once listed as future (durable + paginated history, invite codes,
concurrent-add robustness) all shipped in M6. Decisions locked with the user:
**scrollback history**, **full structure** (roles + private channels +
categories), **medium-community scale** (up to a few hundred members).

A workspace is a Discord/Slack-style container: named text and voice channels,
grouped into categories, with members, roles, and invites. It is E2E encrypted
end to end -- the relay routes and stores only sealed blobs and workspace
*metadata*, never channel content.

---

## 1. Theory of operation

The load-bearing insight: **a channel is a group.** Enclave already has, per
`ConvKind::Group`, everything a text channel needs -- an MLS group with
cryptographic membership, server fan-out of sealed ciphertext, and the full
message feature set (history, reactions, pins, polls, files, edits). A **voice
channel** is a group running a persistent call: the existing `start_call` +
sealed `Media` fan-out + MLS-derived media-key schedule (`media_root_secret`),
including screenshare and video. So a workspace is mostly an **organizational and
key-coordination layer** over channel-groups, not a new cryptosystem.

```
Workspace  (server metadata: name, category/channel tree, roster, signed roles, invites)
 ├─ Category "Text"
 │   ├─ #general   public   -> keyed off the Workspace group
 │   └─ #dev       public   -> keyed off the Workspace group
 ├─ Category "Staff"
 │   └─ #admins    private  -> its own MLS group (subset)
 └─ Category "Voice"
     ├─ Lounge     public   voice
     └─ Standup    private  voice (subset)
```

---

## 2. Keying architecture

Two membership realities drive it: **public channels all have the same member set
(the whole workspace)**, while **private channels each have a distinct subset.**
So:

- **Workspace group (WG)** -- one MLS group over all workspace members. Public
  channels do **not** each run their own MLS group; each derives a content key
  from the WG epoch secret, domain-separated per channel:
  `K_chan = HKDF(WG_exporter_secret, "enclave-ws-chan-v1" || channel_id)`.
  One membership change = **one** WG commit, and every public channel rekeys with
  it. This is what makes medium scale viable (section 10).
- **Private channel = its own MLS group**, exactly like a normal group today, over
  its subset. Adding someone to a private channel is one commit to that group,
  independent of the WG.
- **Voice** channels derive a media root the same way (public: from WG; private:
  from the private channel's MLS group), feeding the existing media-key schedule.

Consequence to accept: public-channel messages are forward-secret at
**WG-epoch** granularity (they rekey when membership changes), not per-message.
That is fine here because scrollback (section 3) already makes old messages
readable to future members -- per-message ratchet FS on the live path buys little
once history is intentionally replayable. Private channels that need stronger FS
can run as full per-message MLS groups (they already are).

Alternative considered and rejected for the common case: **one MLS group per
channel** (max isolation, per-message FS) -- costs `O(channels)` commits per
membership change, a rekey storm at medium scale, for FS that scrollback negates.

---

## 3. History & scrollback

Requirement (user's choice): a new channel member can **read messages from before
they joined**, like Discord -- which pure MLS forbids (forward secrecy). The
mechanism, reusing the off-ratchet content-key pattern (`crypto::seal_chunk` /
`seal_ballot`):

- Each channel has a **history key**, versioned into **epochs**: `HK[0], HK[1], ...`.
- When a message is posted it is sealed **twice**: once through the live path
  (MLS / derived key) for online members, and once under the current `HK[e]` and
  uploaded to a **server-side sealed history store** for that channel, tagged with
  its epoch `e`. The server holds ciphertext + epoch id, never a key.
- Members hold the set of `HK` epoch keys they are entitled to. A **new member is
  bootstrapped with every current epoch key**, sealed to them over MLS on join ->
  full scrollback to channel creation.
- On a **member removal**, the channel starts a **new epoch** `HK[e+1]`; future
  messages seal under it. The removed member keeps only the older epoch keys they
  already held (history they could already read), never the new one.

Security note (documented tradeoff, goes in THREAT_MODEL): backfilled history is
protected by a **symmetric epoch key shared among current members**, not the MLS
per-message ratchet. Whoever is trusted as a member can read (and could leak) all
history for the epochs they hold; a new member is deliberately trusted with the
whole past. The server alone still never holds a key. This is the inherent cost
of "new members can scroll up," chosen deliberately.

---

## 4. Roles & permissions (RBAC -- see M8)

The original Owner/Admin/Member tiers became a permission-based system (M8): a
fixed set of `Permission`s, custom named roles that bundle them, and per-member
role assignment. **Owner** (one, created the workspace) holds every permission via
a protected built-in role; everyone else's power is exactly the union of the roles
assigned to them (deny by default). The hard part is enforcing this under an
**untrusted relay**.

Design principle: **authorization is cryptographic, not server-asserted.**

- Every management action -- create/delete channel, add/remove member, create/
  edit/delete/assign a role, move a channel or member -- is a **signed, timestamped
  operation** in an append-only **workspace op-log**, signed by the actor's
  identity key, and checked against the actor's replayed permissions.
- Authority **traces to genesis**: the genesis op fixes the owner and their
  protected Owner role; every later op is valid iff its signer holds the required
  permission at that point in the replayed log, and no one may grant a permission
  they lack. Clients verify by replay; **the server cannot forge a role or a
  permission** because it holds no signing key (fail closed: no assignment means no
  permission).
- Membership that governs **content access** is the **MLS group roster** (who was
  actually added via a signed commit / holds the keys), not the server's metadata
  roster. Clients treat MLS membership as authoritative and reconcile the
  server's convenience roster against it.

Honest limit (for THREAT_MODEL): a malicious relay cannot forge authorization or
read content, but it **can still censor** -- refuse to relay an op, or
selectively deliver -- which is a liveness/availability attack, not a
confidentiality or integrity one. On a self-hosted server (yours) this is the
accepted posture; it is called out explicitly rather than hidden.

---

## 4b. Channel attachments (files & voice messages)

A channel post is not text-only: it carries an optional embedded **file or voice
clip**, so a text channel behaves like a group chat minus calls. The plaintext is
`ChannelWire { id, sender, text, ts, sig, attach: Option<ChannelAttach> }`
(`client::lib`); `ChannelAttach { name, bytes, voice_ms, waveform }` holds the media
inline (channels have no separate transfer path). Rules:

- **Bounded.** An attachment is capped at `CHANNEL_ATTACH_MAX` (8 MB); the sender
  refuses a larger file up front and a receiver drops an over-cap one (defense in
  depth against a hostile peer).
- **Authenticated end to end.** The signed body binds `channel_attach_hash(attach)`
  -- a SHA-256 over *every* attachment field (name, `voice_ms`, waveform, bytes),
  length-prefixed. Because the history key is symmetric (any co-member could
  re-seal a post), binding only the bytes would let a member swap the displayed
  filename or voice duration under the original signature; hashing the whole
  attachment closes that. A mismatch fails `verify_op` and the post is dropped.
- **Backward compatible.** Posts sealed before attachments existed decode via
  `ChannelWireV1` (the old 5-field wire) and verify against the pre-attachment body
  (`channel_msg_body_v1`); new posts always use `ChannelWire`. bincode's missing
  trailing `Option` byte is what distinguishes the two on the wire.
- **Same store paths as DMs.** A received file lands in the download cache
  (`store_channel_file_at`, path-sanitized); a voice clip lands in the voice cache
  (`store_voice_at`). The UI renders both with the shared message renderer, so file
  rows and the voice player look identical to a conversation.

Still DM-only (not yet on the channel path): polls, reactions, replies, pins. These
need the full group-message-path unification; the composer hides the poll option in
a channel rather than offer a control that does nothing.

Tests: `a_file_round_trips_through_a_workspace_channel` (end-to-end through the
relay, plus the over-cap refusal), `channel_wire_tests` (format discrimination and
the every-field hash binding).

---

## 5. Voice channels

A voice channel is a channel-group with an **always-joinable persistent call**:

- Join = connect to the SFU for that channel's group and derive media keys from
  its MLS/derived secret (reuses `start_call`, the media-key schedule, sealed
  `Media` fan-out, screenshare, video).
- **Voice presence** (who is connected) is metadata the SFU already sees; shown
  live in the channel, and each occupant is clickable (opens their profile).
- **Mute/deafen state** is announced by each client with `ClientMsg::VoiceState`
  (a boolean pair) and folded by the relay into the roster it broadcasts, so every
  occupant is badged muted/deafened. The relay attributes state to the
  authenticated sender only, and only while that sender is present in the channel.
  Audio itself still stops locally; this is purely the visible indicator.
- **Active speaker** ("who is talking") is detected **locally**, receiver-side: the
  call's decode thread measures per-sender RMS on the already-per-sender-decoded
  PCM (`call.rs`, `frame_is_loud` + a short hold), and the mic thread measures our
  own; transitions ride a `SpeakingUpdate` channel out of `Call` (mirroring
  `screen_rx`) to `Event::Speaking` -> `UiEvent::Speaking`. The UI rings the
  talker's avatar/tile green. Because it is computed only from audio we receive,
  the ring appears **only when we are in the call** -- no wire traffic, no server
  involvement, and it needs no extra trust (a peer cannot spoof someone else's
  ring, since it is our own measurement of their audio).
- No new crypto -- it is the existing call, scoped to a channel and left open.

---

## 6. Server data model & protocol

New server state (metadata tier -- the relay already holds the friend graph and
group rosters under the accepted model):

- `Workspace { id, name, owner, categories[], channels[], roster[], invites[] }`
- `Channel { id, workspace, name, kind: Text|Voice, private: bool, category }`
- The **op-log** (signed admin operations) -- append-only, per workspace.
- The **sealed history store** (section 3) -- per channel, quota-bounded, evictable.

New protocol messages (sketch): `WorkspaceCreate`, `ChannelCreate/Delete`,
`WorkspaceInvite/Join/Leave`, `RoleGrant/Revoke` (all carrying signed ops),
`ChannelHistoryFetch { channel, from_epoch }` -> sealed page, and reuse of
existing `Mls` / `Text` / `Media` fan-out for live channel traffic keyed per
channel. Live channel messages reuse the current group-send path with the
per-channel key.

---

## 7. Client & UI

- **Workspace rail**: a left strip of workspace icons (like Discord), above/left
  of the existing conversation sidebar. Selecting a workspace swaps the sidebar to
  its **category -> channel tree**; DMs/home stay reachable.
- **Channel view** reuses the current chat surface (composer, message renderer,
  files and voice messages; polls are still DM-only, see section 4b). A voice
  channel shows a connected-members panel + join button.
- **Management** (create channel, roles, invites, private-channel membership)
  behind an admin panel gated by the client-verified role.
- Reuses: the whole message renderer, the call UI, the profile card, search
  (scoped per channel and per workspace).

---

## 8. STRIDE threat model (design-time pass)

Trust boundary: **client <-> untrusted relay**. Content is E2E; workspace
*structure and rosters* are server-visible metadata (consistent with the existing
model and section 2 of THREAT_MODEL). Threats at the boundary and their controls:

| STRIDE | Threat | Decision / mitigation |
|---|---|---|
| **S** Spoofing | Relay injects a ghost into a channel to read it | **Mitigate.** Content access is the MLS roster; a ghost with no signed Welcome holds no key. Server's metadata roster is convenience only, reconciled against MLS. |
| **S** Spoofing | Posting as another member | **Mitigate.** Messages are MLS-authenticated to the sender, as today. |
| **T** Tampering | Relay forges roles / membership metadata | **Mitigate.** Roles are Owner-chained signed ops; clients verify the chain. Server cannot mint a valid grant. |
| **T** Tampering | Relay reorders/drops op-log entries | **Mitigate.** Op-log is append-only and signed; clients detect gaps/forks by sequence + hash-chain. Withholding is a liveness issue (D), not integrity. |
| **R** Repudiation | "Who kicked / promoted whom?" | **Mitigate.** Every admin op is signed + timestamped in the op-log -- accountability without trusting the server. |
| **I** Info disclosure | Relay reads channel content | **Mitigate.** E2E; server sees only sealed blobs + `HK`-sealed history it cannot open. |
| **I** Info disclosure | Backfill history key exposure | **Accept (documented).** Scrollback = symmetric epoch key shared with members; not per-message FS. Section 3. Server never holds it. |
| **I** Info disclosure | Non-members learn a private channel's name/members | **Mitigate (from peers).** Private-channel metadata sealed to its members; the client shows only channels it holds keys for. The **relay** still sees the channel exists to route it -- accepted metadata tier. |
| **I** Info disclosure | Workspace membership / channel tree / voice presence | **Accept.** Metadata inherent to a self-hosted relay (THREAT_MODEL). |
| **D** DoS | Message / channel-creation spam; add bursts; unbounded history | **Mitigate.** Per-workspace history bounded on disk (capped, oldest-evicted, `MAX_HISTORY_PER_CHANNEL`); a burst of member adds queues and drains one per freed op-log slot instead of dropping redeemers (M6). Every refusal returns a clear error. |
| **D** DoS | Relay censors (drops ops/messages) | **Accept (self-hosted).** Cannot be prevented against a server you rely on; noted as liveness, not confidentiality/integrity. |
| **S/E** Spoofing / Elevation | Invite code abused to self-join or elevate | **Mitigate.** An invite is a bearer code an **admin** mints (relay checks the role) and can only *request* admission; the actual add is a signed AddMember op by an online admin, so redemption never bypasses role authority or the op-log record. |
| **E** Elevation | Member performs admin action without the role | **Mitigate.** Authorization is the signed Owner-chained grant; clients reject ops whose signer lacks the role. Server cannot elevate. |
| **E** Elevation | Removed member keeps reading | **Mitigate.** Removal triggers a WG commit (public) / group commit (private) **and** a history-epoch rotation; they hold no post-removal key. |

Resolved during implementation: op-log fork-detection is **both** a per-signer
sequence number and a SHA-256 `prev_hash` chain (`crypto::workspace`), not one or
the other, so a gap and a reorder are each caught. The server's convenience roster
was kept (it is what lets the relay fan channel traffic out), but it is never the
authority: content access is the MLS roster, and the metadata roster is reconciled
from the same signed op-log the clients replay.

---

## 9. Performance & scale (medium-community)

Target: up to a few hundred members, tens of channels. Costs:

- **Public channels: O(1) membership ops** -- one WG commit covers all of them
  (section 2). This is the whole reason for the WG-derived-key design.
- **Private channels: O(granted-channels)** per member change -- unavoidable, but
  only touches the private channels a member is actually in.
- **Rekey storms** (many joins/leaves at once): batch membership deltas into a
  single WG commit per tick rather than one commit per person; process the join
  queue on a short timer. Same pattern as the ballot sweeper.
- **History store**: append-only, quota-bounded per channel with oldest-epoch
  eviction; fetched in pages (`from_epoch`), not all at once.
- MLS at a few hundred members is well within openmls's comfort zone; the design
  avoids the one thing that would break it (per-channel groups).

---

## 10. Phased roadmap

- **M0 [DONE] -- data model & op-log.** Workspace/channel/role types
  (`enclave-protocol`); signed append-only op-log + role-chain verification
  (`crypto::sign`, `crypto::workspace`); server storage + protocol
  (`transport::workspaces`). Tests: `genesis_establishes_owner_and_roles`,
  `only_the_owner_grants_admin_and_only_higher_roles_remove`,
  `a_forged_or_reordered_entry_is_rejected`, `a_tampered_op_body_breaks_the_signature`.
- **M1 [DONE] -- public text channels.** Workspace MLS group + per-channel derived
  keys; create workspace, add members, `#public` text channels reusing the chat
  surface. Tests: `a_workspace_is_created_and_a_member_is_added_end_to_end`,
  `members_exchange_messages_in_a_workspace_channel`,
  `a_non_member_never_sees_a_workspaces_channel_traffic`.
- **M2 [DONE] -- scrollback history.** History-key epochs; server sealed history
  store + oldest-first eviction cap; new-member bootstrap; removal rotation. Test:
  `a_late_joiner_reads_channel_history_from_before_they_joined`. Removal rotates
  every channel's history epoch (`client::workspace_remove_member`).
- **M3 [DONE] -- private channels & roles UI.** Per-private-channel MLS groups;
  role/permission management behind the verified-role admin panel; categories.
  Test: `a_private_channel_is_readable_only_by_its_members`.
- **M4 [DONE] -- voice channels.** Persistent call per channel; join/leave;
  voice-presence panel; reuse media/screenshare/video. Test:
  `voice_channel_presence_tracks_who_is_connected`.
- **M5 [DONE] -- UI & op serialization.** The workspace UI (rail, channel tree,
  channel view, voice stage) built by reusing the direct-message message renderer
  (`appendInto`) and the app's modal system, not a parallel one; back-to-back
  structural ops serialized through a per-workspace op-submission queue that
  re-signs on a sequence conflict.
- **M6 [DONE] -- scale & robustness.** The items once listed here as future:
  - **Durable, paginated history.** Channel scrollback persists to disk (an
    append-only framed log per channel with a stable per-channel seq and
    slack-window compaction), so a relay restart keeps the backlog. Fetches are
    paged by seq (newest page, then older on scroll-up) instead of dumping the
    whole backlog, and the client catches up on channel open (channel posts are
    fan-out, not the reliable queue). Tests:
    `history_pages_newest_first_and_walks_older_by_cursor`,
    `history_survives_a_restart`.
  - **Invite codes.** An admin mints a bearer code (relay-enforced role,
    persisted, with expiry/use limits); redeeming routes a join request to one
    online admin whose client admits the redeemer through the normal signed
    AddMember op. Tests: `invites_validate_expiry_and_use_limits`,
    `an_invite_code_admits_a_redeemer`.
  - **Concurrent-add robustness.** A burst of adds (several redemptions of one
    invite link at once) queues per workspace and drains one per freed op-log
    slot rather than failing on a busy log, so no redeemer is dropped. Test:
    `a_burst_of_invite_redemptions_all_get_admitted`. (Collapsing a burst into a
    single multi-member MLS commit would trim commits under churn; at
    medium-community scale the serial queue is correct and sufficient, so that
    micro-optimization is intentionally not built.)
- **M7 [DONE] -- sidebar hierarchy & voice moves.**
  - **Nested, draggable tree.** Categories collapse/expand (one chevron per
    header; a single header `+` chooses channel-or-category), and channels and
    categories reparent by drag: `SetChannelCategory` moves a channel, and
    `SetCategoryParent` nests a category under another. The op-log refuses a move
    that would form a cycle or exceed `MAX_CATEGORY_DEPTH`. Tests:
    `channels_and_categories_can_be_reparented`, `a_channel_can_be_created_inside_a_category`,
    `a_category_move_is_rejected_when_it_would_cycle_or_target_is_missing`,
    `category_nesting_is_depth_bounded`.
  - **Admin voice moves.** Someone with the move-voice permission drags a member
    from one voice channel onto another; the relay (checking the permission and
    that the target is a voice channel the member may enter) directs the member's
    client to switch, so presence flows through the member's own join/leave and is
    never double counted. Test: `an_admin_moves_a_member_between_voice_channels`.
- **M8 [DONE] -- role-based access control.** The fixed Owner/Admin/Member tiers
  became a modular permission system: a fixed set of `Permission`s
  (`manage_channels`, `manage_members`, `manage_channel_members`, `manage_roles`,
  `move_voice_members`), custom named roles that bundle them, and per-member role
  assignment. Every op now checks the specific permission it needs against the
  author's effective permissions (the union of their roles). Key properties, all
  enforced in the op-log and mirrored in the UI:
  - **Deny by default, fail closed.** A member with no role has no permissions.
    The owner's all-permissions come from a protected built-in Owner role assigned
    at genesis (`OWNER_ROLE_ID`), *not* a special case -- so a bypassed check
    grants nothing, not everything.
  - **No privilege escalation.** A non-owner may only create or assign a role
    whose every permission they already hold; the Owner role is immutable and
    unassignable, and the owner is never a role target.
  - **UI.** A role editor (name + permission checkboxes, disabled for permissions
    you lack) and per-member role chips in the manage dialog; every management
    affordance in the sidebar and dialog is gated on the specific permission.
  Tests: `genesis_establishes_owner_and_roles`,
  `role_ops_prevent_privilege_escalation_and_protect_the_owner_role`,
  `a_bare_member_cannot_touch_roles_and_the_owner_is_unremovable`.

Each milestone landed with its tests and a THREAT_MODEL update.

---

## 11. Honest limitations (state these up front)

- **Scrollback weakens forward secrecy** for backfilled history (section 3) --
  the deliberate cost of Discord-style history.
- **No metadata privacy for workspace structure** -- membership, channel tree,
  and voice presence are visible to the relay you host (THREAT_MODEL: forced by
  self-hosted async delivery, not a gap).
- **The relay can censor** (drop ops/messages) though it cannot forge or read --
  a liveness limit inherent to depending on a server.
- **Invite codes are bearer secrets** -- anyone who obtains a code can request to
  join until it expires or is used up; admission still requires an online admin
  and is recorded (signed) in the op-log.
- **Scale ceiling ~ a few hundred**; this is not a 50k-member public-server design.
- **Big build**: M0-M5 is the largest feature since calls. It is additive -- DMs,
  groups, and the home screen are untouched.
