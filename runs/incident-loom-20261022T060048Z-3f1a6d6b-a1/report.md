# Incident Loom run report

> Synthetic data: every event, entity and label was generated for a fictional organisation. Detector metrics measure agreement with synthetic labels and do not estimate real-world performance.

6 batch(es) 2026-10-13 to 2026-10-18, clock-skew correction off: 1502 normalized events from 1534 records (19 duplicates merged, 13 quarantined). 10 incident(s): 2 critical, 5 high, 3 medium. Evidence gaps: host_auth declared 2026-10-14T13:45Z to 2026-10-14T16:15Z; resource_access silent 2026-10-16T09:40Z to 2026-10-16T14:31Z. Synthetic data: every event, entity and label was generated for a fictional organisation. Detector metrics measure agreement with synthetic labels and do not estimate real-world performance.

## Ingestion

| batch | source | received | accepted | exact dup | redelivered | out of order | quarantined | skew applied (s) |
|---|---|---|---|---|---|---|---|---|
| 2026-10-13 | idp_signin | 80 | 78 | 0 | 0 | 0 | 2 | 0 |
| 2026-10-13 | cloud_audit | 40 | 40 | 0 | 0 | 0 | 0 | 0 |
| 2026-10-13 | host_auth | 72 | 70 | 0 | 0 | 0 | 2 | 0 |
| 2026-10-13 | resource_access | 96 | 96 | 0 | 0 | 0 | 0 | 0 |
| 2026-10-14 | idp_signin | 70 | 66 | 4 | 0 | 0 | 0 | 0 |
| 2026-10-14 | cloud_audit | 43 | 41 | 0 | 0 | 0 | 2 | 0 |
| 2026-10-14 | host_auth | 99 | 99 | 0 | 0 | 0 | 0 | 0 |
| 2026-10-14 | resource_access | 46 | 44 | 0 | 2 | 0 | 0 | 0 |
| 2026-10-15 | idp_signin | 71 | 70 | 0 | 0 | 0 | 1 | 0 |
| 2026-10-15 | cloud_audit | 32 | 32 | 0 | 0 | 0 | 0 | 0 |
| 2026-10-15 | host_auth | 56 | 54 | 2 | 0 | 0 | 0 | 0 |
| 2026-10-15 | resource_access | 104 | 101 | 0 | 0 | 0 | 3 | 0 |
| 2026-10-16 | idp_signin | 70 | 64 | 0 | 5 | 0 | 1 | 0 |
| 2026-10-16 | cloud_audit | 38 | 38 | 0 | 0 | 4 | 0 | 0 |
| 2026-10-16 | host_auth | 64 | 64 | 0 | 0 | 0 | 0 | 0 |
| 2026-10-16 | resource_access | 37 | 37 | 0 | 0 | 0 | 0 | 0 |
| 2026-10-17 | idp_signin | 56 | 56 | 0 | 0 | 2 | 0 | 0 |
| 2026-10-17 | cloud_audit | 40 | 36 | 0 | 3 | 0 | 1 | 0 |
| 2026-10-17 | host_auth | 72 | 72 | 0 | 0 | 0 | 0 | 0 |
| 2026-10-17 | resource_access | 123 | 120 | 3 | 0 | 0 | 0 | 0 |
| 2026-10-18 | idp_signin | 70 | 70 | 0 | 0 | 0 | 0 | 0 |
| 2026-10-18 | cloud_audit | 38 | 38 | 0 | 0 | 0 | 0 | 0 |
| 2026-10-18 | host_auth | 73 | 73 | 0 | 0 | 0 | 0 | 0 |
| 2026-10-18 | resource_access | 44 | 43 | 0 | 0 | 3 | 1 | 0 |

Quarantined by reason: parse_error 3, wrong_field_count 2, missing_required_field 3, invalid_timestamp 5, invalid_field 0, outside_batch_window 0, conflicting_redelivery 0

## Evidence gaps

- `gap-4086f6501e` declared gap in host_auth, 2026-10-14T13:45:00.000Z to 2026-10-14T16:15:00.000Z (150 min). Declared in the batch manifest: "endpoint log forwarder restarted; records in this window were not retained". Incidents: inc-c04a95bc97.
- `gap-b1963b8509` silent gap in resource_access, 2026-10-16T09:40:08.538Z to 2026-10-16T14:31:37.903Z (291 min). No resource_access records for 291 minutes inside the declared coverage (threshold 120 minutes). Incidents: inc-50a71c858a.

## Incidents

Links marked causal rest on an explicit identifier in the records; links marked temporal only state order. In correlations.json, attribution edges only state that a record names an entity.

### inc-c4d8644219 (high): user:tobin.harrowgate: repeated failed sign-ins then a success

Window 2026-10-13T10:02:00.000Z to 2026-10-13T10:16:30.000Z; 13 events; gaps: none.

Timeline:

- t01 2026-10-13T10:02:00.000Z: 9 failed sign-in(s) for user:tobin.harrowgate from ip:203.0.113.77 (JP) to mail at 10:02:00-10:09:20 UTC [ev-9c9fe994f445f4c5, ev-676667f783a1a414, ev-7e2dbc312978b5f8, +6 more]
- t02 2026-10-13T10:11:05.000Z: 1 successful sign-in(s) for user:tobin.harrowgate from ip:203.0.113.77 (JP) to mail at 10:11:05 UTC [ev-72dca107fcbd45b7]
- t03 2026-10-13T10:14:00.000Z: 3 read(s) of resource:share/fh-sales-reports by user:tobin.harrowgate from ip:203.0.113.77 (JP) (1 MB) at 10:14:00-10:16:30 UTC [ev-9fe09f52d3b6632c, ev-5f926e181d87cee1, ev-8de93fc91f700dc8]

Links: t01->t02 temporal; t02->t03 causal (same_session)

Hypotheses:

- h1 [medium; before gaps medium] Someone other than the owner of user:tobin.harrowgate may have used the account's credentials (repeated failed sign-ins then a success). Basis: 1 supporting detection(s) across 1 source(s); no explicit identifier joins the supporting events; the successful sign-in came from ip:203.0.113.77, an address this account had not signed in from successfully before (it appears earlier only in 9 other event(s) such as the failed attempts).
  - alternative (benign): The owner of user:tobin.harrowgate mistyped or used a stale saved password several times and then signed in. Distinguish by: A password-change or lockout ticket and a success from an address already used by user:tobin.harrowgate favour this reading; the success came from ip:203.0.113.77, which this account had not signed in from successfully earlier in the ingested batches.

### inc-eb3e4da2bb (medium): ip:198.51.100.200: password spray

Window 2026-10-13T14:20:00.000Z to 2026-10-13T14:39:50.000Z; 8 events; gaps: none.

Timeline:

- t01 2026-10-13T14:20:00.000Z: 1 failed sign-in(s) for user:mira.quellon from ip:198.51.100.200 (IN) to mail at 14:20:00 UTC [ev-12420e9463cf7692]
- t02 2026-10-13T14:22:50.000Z: 1 failed sign-in(s) for user:sela.vantriss from ip:198.51.100.200 (IN) to mail at 14:22:50 UTC [ev-e59dffd4172db20f]
- t03 2026-10-13T14:25:40.000Z: 1 failed sign-in(s) for user:oren.blackfen from ip:198.51.100.200 (IN) to mail at 14:25:40 UTC [ev-32359108a6aa8d5f]
- t04 2026-10-13T14:28:30.000Z: 1 failed sign-in(s) for user:bram.oduya from ip:198.51.100.200 (IN) to mail at 14:28:30 UTC [ev-82e4407197762cf0]
- t05 2026-10-13T14:31:20.000Z: 1 failed sign-in(s) for user:rhea.solvane from ip:198.51.100.200 (IN) to mail at 14:31:20 UTC [ev-7b7167aa0477f787]
- t06 2026-10-13T14:34:10.000Z: 1 failed sign-in(s) for user:kai.thornwick from ip:198.51.100.200 (IN) to mail at 14:34:10 UTC [ev-7499b7e5092e9501]
- t07 2026-10-13T14:37:00.000Z: 1 failed sign-in(s) for user:jun.okarra from ip:198.51.100.200 (IN) to mail at 14:37:00 UTC [ev-0be4b201bf8f27d0]
- t08 2026-10-13T14:39:50.000Z: 1 failed sign-in(s) for user:wren.halloway from ip:198.51.100.200 (IN) to mail at 14:39:50 UTC [ev-a793271e486adb5e]

Links: t01->t02 temporal; t02->t03 temporal; t03->t04 temporal; t04->t05 temporal; t05->t06 temporal; t06->t07 temporal; t07->t08 temporal

Hypotheses:

- h1 [low; before gaps low] ip:198.51.100.200 attempted password spraying against 8 accounts; no successful sign-in from that address appears in the ingested batches. Basis: 1 supporting detection(s) across 1 source(s); no explicit identifier joins the supporting events.
  - alternative (benign): A misconfigured client or a shared egress address retrying stale credentials for several users. Distinguish by: User agents and applications of the attempts; a shared address of legitimate users would also show successful sign-ins.

### inc-036c93a13d (critical): user:nico.ashgrove: repeated failed sign-ins then a success, privilege change after an anomalous sign-in, public exposure, mass download, audit logging stopped

Window 2026-10-13T15:40:00.000Z to 2026-10-13T16:40:20.000Z; 64 events; gaps: none.

Timeline:

- t01 2026-10-13T15:40:00.000Z: 8 failed sign-in(s) for user:nico.ashgrove from ip:203.0.113.100 (JP) to console at 15:40:00-15:47:35 UTC [ev-fd9c29e336ccc258, ev-71bc0704de969e8e, ev-58d2574a279f1681, +5 more]
- t02 2026-10-13T15:49:10.000Z: 1 successful sign-in(s) for user:nico.ashgrove from ip:203.0.113.100 (JP) to console at 15:49:10 UTC [ev-20dd95cd0b1a0b18]
- t03 2026-10-13T16:02:30.000Z: 1 x iam.role.grant by user:nico.ashgrove on user:nico.ashgrove from ip:203.0.113.100 (JP) (role=iam-admin, credential=console) at 16:02:30 UTC [ev-23d950618cc9dbff]
- t04 2026-10-13T16:10:45.000Z: 1 x storage.bucket.set_acl by user:nico.ashgrove on resource:bucket/fh-backups from ip:203.0.113.100 (JP) (acl=public-read, credential=console) at 16:10:45 UTC [ev-6ea2c13682203e1d]
- t05 2026-10-13T16:14:00.000Z: 52 read(s) of resource:bucket/fh-backups by user:anonymous from ip:198.51.100.150 (NL) (530 MB) at 16:14:00-16:32:42 UTC [ev-cc9c4add8d18e83f, ev-691c8846f7e19340, ev-3076b43931034e37, +49 more]
- t06 2026-10-13T16:40:20.000Z: 1 x logging.trail.delete by user:nico.ashgrove on resource:trail/fh-storage-trail from ip:203.0.113.100 (JP) (credential=console) at 16:40:20 UTC [ev-7d7269c10cacafea]

Links: t01->t02 temporal; t02->t03 causal (same_session); t03->t04 causal (same_session); t02->t04 causal (same_session); t04->t05 temporal; t05->t06 temporal; t04->t06 causal (same_session)

Hypotheses:

- h1 [high; before gaps high] Someone other than the owner of user:nico.ashgrove may have used the account's credentials (repeated failed sign-ins then a success). Basis: 4 supporting detection(s) across 2 source(s); an explicit session, request, process or parent id joins supporting events; the successful sign-in came from ip:203.0.113.100, an address this account had not signed in from successfully before (it appears earlier only in 8 other event(s) such as the failed attempts).
  - alternative (benign): The owner of user:nico.ashgrove mistyped or used a stale saved password several times and then signed in. Distinguish by: A password-change or lockout ticket and a success from an address already used by user:nico.ashgrove favour this reading; the success came from ip:203.0.113.100, which this account had not signed in from successfully earlier in the ingested batches.
- h2 [high; before gaps high] Privileges for user:nico.ashgrove were expanded during or shortly after the anomalous access (iam.role.grant). Basis: 3 supporting detection(s) across 2 source(s); an explicit session, request, process or parent id joins supporting events.
  - alternative (benign): An authorised administrative change made by the account owner. Distinguish by: A change ticket in the audit record parameters (none recorded) and approval by a second administrator.
- h3 [high; before gaps high] Data in resource:bucket/fh-backups may have been exposed to, or copied by, parties outside the organisation. Basis: 3 supporting detection(s) across 2 source(s); an explicit session, request, process or parent id joins supporting events.
  - alternative (benign): The resource was published on purpose for public content. Distinguish by: Whether the resource holds public material such as website assets and whether a ticket covers the change; reads after the change show who fetched what.
  - alternative (malicious): An insider staged the data for collection rather than an outside party. Distinguish by: Whether the reads come from the account owner's usual addresses or from unrelated ones.
- h4 [high; before gaps high] Audit logging on resource:trail/fh-storage-trail was turned off, which may hide later control-plane activity. It ran in a session already recorded in 3 earlier event(s) of this incident. Basis: 5 supporting detection(s) across 2 source(s); an explicit session, request, process or parent id joins supporting events.
  - alternative (benign): Planned logging maintenance or a cost change. Distinguish by: A maintenance ticket and the trail being restarted shortly afterwards.

### inc-c04a95bc97 (high): user:oren.blackfen: repeated failed sign-ins then a success

Window 2026-10-14T13:27:00.000Z to 2026-10-14T13:50:50.000Z; 17 events; gaps: gap-4086f6501e.

Timeline:

- t01 2026-10-14T13:27:00.000Z: 12 failed SSH login(s) for user:oren.blackfen on host:fh-bastion-01 from ip:203.0.113.140 (DE) at 13:27:00-13:37:05 UTC [ev-fa423149d48a0b71, ev-93126dd2c04c890e, ev-a5e816ee7dc5036a, +9 more]
- t02 2026-10-14T13:40:10.000Z: 1 accepted SSH login(s) for user:oren.blackfen on host:fh-bastion-01 from ip:203.0.113.140 (DE) at 13:40:10 UTC [ev-38b71b9687ad235a]
- t03 2026-10-14T13:41:02.000Z: 1 sudo command(s) by user:oren.blackfen on host:fh-bastion-01: /usr/bin/id at 13:41:02 UTC [ev-44ca0bebbc3ab9f1]
- t04 2026-10-14T13:42:40.000Z: 3 process execution(s) by user:oren.blackfen on host:fh-bastion-01: /usr/bin/scp, /usr/bin/tar, /usr/local/bin/cloudctl at 13:42:40-13:50:50 UTC [ev-060dbb0ca92ebaf9, ev-e20372a58b8be852, ev-948f0e807a3f1658]

Links: t01->t02 temporal; t02->t03 causal (parent_id); t03->t04 temporal; t02->t04 causal (parent_id)

Hypotheses:

- h1 [low; before gaps medium] Someone other than the owner of user:oren.blackfen may have used the account's credentials (repeated failed sign-ins then a success). This reading depends on missing evidence: host_auth is silent 13:45-16:15 UTC (gap-4086f6501e). Basis: 1 supporting detection(s) across 1 source(s); no explicit identifier joins the supporting events; the successful sign-in came from ip:203.0.113.140, an address this account had not signed in from successfully before (it appears earlier only in 12 other event(s) such as the failed attempts); lowered one level: depends on evidence gap(s) gap-4086f6501e.
  - alternative (benign): The owner of user:oren.blackfen mistyped or used a stale saved password several times and then signed in. Distinguish by: A password-change or lockout ticket and a success from an address already used by user:oren.blackfen favour this reading; the success came from ip:203.0.113.140, which this account had not signed in from successfully earlier in the ingested batches.
- h2 [low; before gaps medium] The SSH session obtained on host:fh-bastion-01 was used to run commands (4 command or process events record its process fh-bastion-01:7120 as their parent). This reading depends on missing evidence: host_auth is silent 13:45-16:15 UTC (gap-4086f6501e). Basis: 1 supporting detection(s) across 1 source(s); an explicit session, request, process or parent id joins supporting events; lowered one level: depends on evidence gap(s) gap-4086f6501e.
  - alternative (benign): The owner logged in to host:fh-bastion-01 after mistyping and ran routine administration. Distinguish by: Whether the commands match the owner's usual work (archiving configuration and copying it to an outside address is unusual) and what the session did after its last recorded line.

### inc-f3f95c466f (medium): user:sela.vantriss: impossible travel

Window 2026-10-14T17:10:00.000Z to 2026-10-14T17:45:30.000Z; 3 events; gaps: none.

Timeline:

- t01 2026-10-14T17:10:00.000Z: 1 successful sign-in(s) for user:sela.vantriss from ip:198.51.100.70 (DE) to mail at 17:10:00 UTC [ev-8ac7bd344c25c60f]
- t02 2026-10-14T17:45:21.000Z: 1 MFA push(es) for user:sela.vantriss (approved) for a sign-in from ip:203.0.113.80 (JP) at 17:45:21 UTC [ev-33cb87894a365b06]
- t03 2026-10-14T17:45:30.000Z: 1 successful sign-in(s) for user:sela.vantriss from ip:203.0.113.80 (JP) to console at 17:45:30 UTC [ev-7a6b14945d6e1342]

Links: t01->t02 temporal; t02->t03 causal (same_session)

Hypotheses:

- h1 [low; before gaps low] Someone other than the owner of user:sela.vantriss may have used the account's credentials (impossible travel). Basis: 1 supporting detection(s) across 1 source(s); no explicit identifier joins the supporting events; the successful sign-in came from ip:203.0.113.80, an address this account had not signed in from successfully before (it appears earlier only in 1 other event(s) such as the failed attempts); lowered one level for 1 contradicting event(s).
  - alternative (benign): A VPN exit node, proxy or mobile carrier changed the apparent country without the owner travelling. Distinguish by: Device identifiers or VPN assignment records for both sign-ins (not present in these sources) would show whether one device made both.

### inc-14f58ed1e7 (critical): user:mira.quellon: MFA push fatigue, privilege change after an anomalous sign-in, public exposure, mass download, audit logging stopped

Window 2026-10-15T19:02:10.000Z to 2026-10-15T23:40:30.000Z; 60 events; gaps: none.

Timeline:

- t01 2026-10-15T19:02:10.000Z: 6 MFA push(es) for user:mira.quellon (denied, timeout) for a sign-in from ip:198.51.100.140 (NL) at 19:02:10-19:10:15 UTC [ev-57c17199555bc0b9, ev-e01f5e98f0958ff9, ev-5493ca99dde67b95, +3 more]
- t02 2026-10-15T19:13:20.000Z: 1 MFA push(es) for user:mira.quellon (approved) for a sign-in from ip:198.51.100.140 (NL) at 19:13:20 UTC [ev-51b91c1887c6db5c]
- t03 2026-10-15T19:13:29.000Z: 1 successful sign-in(s) for user:mira.quellon from ip:198.51.100.140 (NL) to console at 19:13:29 UTC [ev-88743863c072764c]
- t04 2026-10-15T19:20:05.000Z: 1 x iam.accesskey.create by user:mira.quellon on user:mira.quellon from ip:198.51.100.140 (NL) (key_id=fhk-7c21d9e0, credential=console) at 19:20:05 UTC [ev-8184868a6c18d2b9]
- t05 2026-10-15T19:23:40.000Z: 1 x iam.role.grant by user:mira.quellon on user:mira.quellon from ip:198.51.100.140 (NL) (role=storage-admin, credential=console) at 19:23:40 UTC [ev-fafe74ee25d0680c]
- t06 2026-10-15T19:31:15.000Z: 1 x storage.bucket.set_acl by user:mira.quellon on resource:bucket/fh-finance-exports from ip:198.51.100.140 (NL) (acl=public-read, credential=console) at 19:31:15 UTC [ev-10d3e717b91c1db6]
- t07 2026-10-15T19:35:00.000Z: 48 read(s) of resource:bucket/fh-finance-exports by user:anonymous from ip:203.0.113.200 (US) (982 MB) at 19:35:00-19:51:27 UTC [ev-b3175b7f789ae9e1, ev-ae9762a2cbfcadfb, ev-e954fea69e74c5ed, +45 more]
- t08 2026-10-15T23:40:30.000Z: 1 x logging.trail.stop by user:mira.quellon on resource:trail/fh-org-trail from ip:198.51.100.140 (NL) (credential=access_key:fhk-7c21d9e0) at 23:40:30 UTC [ev-823be70d659fdd58]

Links: t01->t02 temporal; t02->t03 causal (same_session); t03->t04 causal (same_session); t02->t04 causal (same_session); t04->t05 causal (same_session); t03->t05 causal (same_session); t05->t06 causal (same_session); t04->t06 causal (same_session); t06->t07 temporal; t07->t08 temporal

Hypotheses:

- h1 [high; before gaps high] Someone other than the owner of user:mira.quellon may have used the account's credentials (MFA push fatigue). Basis: 4 supporting detection(s) across 2 source(s); an explicit session, request, process or parent id joins supporting events; the successful sign-in came from ip:198.51.100.140, an address this account had not signed in from successfully before (it appears earlier only in 7 other event(s) such as the failed attempts).
  - alternative (benign): The owner dismissed prompts from a stale session on their own device and later approved a genuine sign-in. Distinguish by: The approving device and the sign-in address: an approval for a sign-in from an address never used by the owner favours the malicious reading.
- h2 [high; before gaps high] Privileges for user:mira.quellon were expanded during or shortly after the anomalous access (iam.accesskey.create, iam.role.grant). Basis: 3 supporting detection(s) across 2 source(s); an explicit session, request, process or parent id joins supporting events.
  - alternative (benign): An authorised administrative change made by the account owner. Distinguish by: A change ticket in the audit record parameters (none recorded) and approval by a second administrator.
  - alternative (malicious): The new access key is persistence for later access rather than for immediate escalation. Distinguish by: Later activity that authenticates with the new key id.
- h3 [high; before gaps high] Data in resource:bucket/fh-finance-exports may have been exposed to, or copied by, parties outside the organisation. Basis: 3 supporting detection(s) across 2 source(s); an explicit session, request, process or parent id joins supporting events.
  - alternative (benign): The resource was published on purpose for public content. Distinguish by: Whether the resource holds public material such as website assets and whether a ticket covers the change; reads after the change show who fetched what.
  - alternative (malicious): An insider staged the data for collection rather than an outside party. Distinguish by: Whether the reads come from the account owner's usual addresses or from unrelated ones.
- h4 [medium; before gaps medium] Audit logging on resource:trail/fh-org-trail was turned off, which may hide later control-plane activity; the request used access key fhk-7c21d9e0, created earlier in this incident. Basis: 2 supporting detection(s) across 1 source(s); no explicit identifier joins the supporting events.
  - alternative (benign): Planned logging maintenance or a cost change. Distinguish by: A maintenance ticket and the trail being restarted shortly afterwards.

### inc-9212a1e53e (high): user:rhea.solvane: MFA push fatigue

Window 2026-10-15T21:05:00.000Z to 2026-10-15T21:26:40.000Z; 9 events; gaps: none.

Timeline:

- t01 2026-10-15T21:05:00.000Z: 5 MFA push(es) for user:rhea.solvane (denied, timeout) for a sign-in from ip:203.0.113.90 (JP) at 21:05:00-21:14:00 UTC [ev-8c4df29a114ea0e2, ev-e4d873102f55f9a8, ev-eef0b12db4ebdd08, +2 more]
- t02 2026-10-15T21:17:22.000Z: 1 MFA push(es) for user:rhea.solvane (approved) for a sign-in from ip:203.0.113.90 (JP) at 21:17:22 UTC [ev-f65d18669335d8ff]
- t03 2026-10-15T21:17:31.000Z: 1 successful sign-in(s) for user:rhea.solvane from ip:203.0.113.90 (JP) to mail at 21:17:31 UTC [ev-7266bf9e4310baeb]
- t04 2026-10-15T21:25:00.000Z: 2 read(s) of resource:share/fh-eng-docs by user:rhea.solvane from ip:203.0.113.90 (JP) (4 MB) at 21:25:00-21:26:40 UTC [ev-0e9492a4321b0948, ev-5ab02f495ccad62e]

Links: t01->t02 temporal; t02->t03 causal (same_session); t03->t04 causal (same_session); t02->t04 causal (same_session)

Hypotheses:

- h1 [high; before gaps high] Someone other than the owner of user:rhea.solvane may have used the account's credentials (MFA push fatigue). Basis: 1 supporting detection(s) across 1 source(s); an explicit session, request, process or parent id joins supporting events; the successful sign-in came from ip:203.0.113.90, an address this account had not signed in from successfully before (it appears earlier only in 6 other event(s) such as the failed attempts).
  - alternative (benign): The owner dismissed prompts from a stale session on their own device and later approved a genuine sign-in. Distinguish by: The approving device and the sign-in address: an approval for a sign-in from an address never used by the owner favours the malicious reading.

### inc-50a71c858a (high): user:bram.oduya: impossible travel, public exposure

Window 2026-10-16T09:00:00.000Z to 2026-10-16T10:05:40.000Z; 4 events; gaps: gap-b1963b8509.

Timeline:

- t01 2026-10-16T09:00:00.000Z: 1 successful sign-in(s) for user:bram.oduya from ip:192.0.2.25 (CA) to wiki at 09:00:00 UTC [ev-aa4acf378b831c2b]
- t02 2026-10-16T09:50:11.000Z: 1 MFA push(es) for user:bram.oduya (approved) for a sign-in from ip:203.0.113.75 (JP) at 09:50:11 UTC [ev-a27dafc797b91e36]
- t03 2026-10-16T09:50:20.000Z: 1 successful sign-in(s) for user:bram.oduya from ip:203.0.113.75 (JP) to console at 09:50:20 UTC [ev-8e34a134582a916f]
- t04 2026-10-16T10:05:40.000Z: 1 x storage.share.set_permission by user:bram.oduya on resource:share/fh-hr-share from ip:203.0.113.75 (JP) (principal=everyone, permission=read, credential=console) at 10:05:40 UTC [ev-ba60966260368be5]

Links: t01->t02 temporal; t02->t03 causal (same_session); t03->t04 causal (same_session); t02->t04 causal (same_session)

Hypotheses:

- h1 [low; before gaps medium] Someone other than the owner of user:bram.oduya may have used the account's credentials (impossible travel). This reading depends on missing evidence: resource_access is silent 09:40-14:31 UTC (gap-b1963b8509). Basis: 2 supporting detection(s) across 2 source(s); an explicit session, request, process or parent id joins supporting events; the successful sign-in came from ip:203.0.113.75, an address this account had not signed in from successfully before (it appears earlier only in 1 other event(s) such as the failed attempts); lowered one level for 1 contradicting event(s); lowered one level: depends on evidence gap(s) gap-b1963b8509.
  - alternative (benign): A VPN exit node, proxy or mobile carrier changed the apparent country without the owner travelling. Distinguish by: Device identifiers or VPN assignment records for both sign-ins (not present in these sources) would show whether one device made both.
- h2 [medium; before gaps high] Data in resource:share/fh-hr-share may have been exposed to, or copied by, parties outside the organisation. This reading depends on missing evidence: resource_access is silent 09:40-14:31 UTC (gap-b1963b8509). Basis: 2 supporting detection(s) across 2 source(s); an explicit session, request, process or parent id joins supporting events; lowered one level: depends on evidence gap(s) gap-b1963b8509.
  - alternative (benign): The resource was published on purpose for public content. Distinguish by: Whether the resource holds public material such as website assets and whether a ticket covers the change; reads after the change show who fetched what.
  - alternative (malicious): An insider staged the data for collection rather than an outside party. Distinguish by: Whether the reads come from the account owner's usual addresses or from unrelated ones.

### inc-19a50c65a0 (medium): user:ada.vexley: privilege change after an anomalous sign-in

Window 2026-10-18T02:09:51.000Z to 2026-10-18T02:40:00.000Z; 4 events; gaps: none.

Timeline:

- t01 2026-10-18T02:09:51.000Z: 1 MFA push(es) for user:ada.vexley (approved) for a sign-in from ip:198.51.100.80 (DE) at 02:09:51 UTC [ev-e068e822d4ce0e32]
- t02 2026-10-18T02:10:00.000Z: 1 successful sign-in(s) for user:ada.vexley from ip:198.51.100.80 (DE) to console at 02:10:00 UTC [ev-e27d5436f4ae94bc]
- t03 2026-10-18T02:25:30.000Z: 1 x iam.group.add_member by user:ada.vexley on user:ada.vexley from ip:198.51.100.80 (DE) (group=billing-admins, credential=console) at 02:25:30 UTC [ev-13aef2b5eb9b3e8d]
- t04 2026-10-18T02:40:00.000Z: 1 x billing.export.run by user:ada.vexley on resource:report/invoices-2026-10 from ip:198.51.100.80 (DE) (credential=console) at 02:40:00 UTC [ev-b95bd002b85f0aba]

Links: t01->t02 causal (same_session); t02->t03 causal (same_session); t01->t03 causal (same_session); t03->t04 causal (same_session); t02->t04 causal (same_session)

Hypotheses:

- h1 [medium; before gaps medium] Someone other than the owner of user:ada.vexley may have used the account's credentials (a first sign-in from a new country). Basis: 1 supporting detection(s) across 2 source(s); an explicit session, request, process or parent id joins supporting events; the successful sign-in came from ip:198.51.100.80, an address this account had not signed in from successfully before (it appears earlier only in 1 other event(s) such as the failed attempts); lowered one level for 1 contradicting event(s).
  - alternative (benign): The owner of user:ada.vexley is travelling and signed in from a new country. Distinguish by: A travel record, the same device identifier as earlier sign-ins, or a change ticket for the follow-on activity would support this reading.
- h2 [high; before gaps high] Privileges for user:ada.vexley were expanded during or shortly after the anomalous access (iam.group.add_member). Basis: 1 supporting detection(s) across 2 source(s); an explicit session, request, process or parent id joins supporting events.
  - alternative (benign): An authorised administrative change made by the account owner. Distinguish by: A change ticket in the audit record parameters (none recorded) and approval by a second administrator.

### inc-21b12a9bc0 (high): user:wren.halloway: repeated failed sign-ins then a success

Window 2026-10-18T11:00:00.000Z to 2026-10-18T11:23:10.000Z; 11 events; gaps: none.

Timeline:

- t01 2026-10-18T11:00:00.000Z: 7 failed sign-in(s) for user:wren.halloway from ip:2001:db8:8000::2a (JP) to vpn at 11:00:00-11:05:00 UTC [ev-118888832481d508, ev-39f97f18df59a50c, ev-a1b9165f78e4ea12, +4 more]
- t02 2026-10-18T11:08:00.000Z: 1 successful sign-in(s) for user:wren.halloway from ip:2001:db8:8000::2a (JP) to vpn at 11:08:00 UTC [ev-c901d7b25b3edb1a]
- t03 2026-10-18T11:20:00.000Z: 3 read(s) of resource:share/fh-eng-docs by user:wren.halloway from ip:2001:db8:8000::2a (JP) (16 MB) at 11:20:00-11:23:10 UTC [ev-bc273d1b9d2ac62a, ev-105b0f6930e9ec8b, ev-aff2c73e6b4f98cb]

Links: t01->t02 temporal; t02->t03 causal (same_session)

Hypotheses:

- h1 [medium; before gaps medium] Someone other than the owner of user:wren.halloway may have used the account's credentials (repeated failed sign-ins then a success). Basis: 1 supporting detection(s) across 1 source(s); no explicit identifier joins the supporting events; the successful sign-in came from ip:2001:db8:8000::2a, an address this account had not signed in from successfully before (it appears earlier only in 7 other event(s) such as the failed attempts).
  - alternative (benign): The owner of user:wren.halloway mistyped or used a stale saved password several times and then signed in. Distinguish by: A password-change or lockout ticket and a success from an address already used by user:wren.halloway favour this reading; the success came from ip:2001:db8:8000::2a, which this account had not signed in from successfully earlier in the ingested batches.

## Detector metrics (synthetic)

Synthetic data: every event, entity and label was generated for a fictional organisation. Detector metrics measure agreement with synthetic labels and do not estimate real-world performance.

A scenario counts as detected when any detection shares at least one event id with it. Overall: tp = incident scenarios detected, fp = benign scenarios detected, fn = incident scenarios not detected, tn = benign scenarios not detected. Per detector: tp/fp count scenarios that detector touched; recall uses only incident scenarios whose labelled techniques the detector targets. Scenarios whose events are not all present in the ingested batches are excluded and listed. Precision or recall is null when its denominator is zero.

### held-out (evaluation: these labels were never used to choose thresholds)

Overall on 8 scenarios: tp 4, fp 1, fn 1, tn 2, precision 0.8, recall 0.8.

| detector | tp | fp | fn | tn | precision | recall |
|---|---|---|---|---|---|---|
| password_spray | 0 | 0 | 1 | 3 | None | 0.0 |
| brute_force_success | 2 | 0 | 0 | 3 | 1.0 | 1.0 |
| impossible_travel | 1 | 0 | 0 | 3 | 1.0 | 1.0 |
| mfa_fatigue | 1 | 0 | 0 | 3 | 1.0 | 1.0 |
| privilege_after_anomalous_signin | 1 | 1 | 1 | 2 | 0.5 | 0.5 |
| public_exposure_after_anomaly | 2 | 0 | 0 | 3 | 1.0 | 1.0 |
| mass_download_after_exposure | 1 | 0 | 0 | 3 | 1.0 | 1.0 |
| logging_disabled | 1 | 0 | 0 | 3 | 1.0 | 1.0 |

- ho-01 host_brute_force_persistence expected incident: tp (detected by brute_force_success)
- ho-02 account_takeover_chain expected incident: tp (detected by logging_disabled, mass_download_after_exposure, mfa_fatigue, privilege_after_anomalous_signin, public_exposure_after_anomaly)
- ho-03 password_spray expected incident: fn
- ho-04 impossible_travel_exposure expected incident: tp (detected by impossible_travel, public_exposure_after_anomaly)
- ho-05 ticketed_change expected benign: tn
- ho-06 admin_unusual expected benign: fp (detected by privilege_after_anomalous_signin)
- ho-07 bulk_export_audit expected benign: tn
- ho-08 brute_force_success expected incident: tp (detected by brute_force_success)

### development (tuning data: thresholds were chosen on these scenarios, so these numbers are not an estimate of anything)

Overall on 7 scenarios: tp 5, fp 0, fn 0, tn 2, precision 1.0, recall 1.0.

| detector | tp | fp | fn | tn | precision | recall |
|---|---|---|---|---|---|---|
| password_spray | 1 | 0 | 0 | 2 | 1.0 | 1.0 |
| brute_force_success | 2 | 0 | 0 | 2 | 1.0 | 1.0 |
| impossible_travel | 1 | 0 | 0 | 2 | 1.0 | 1.0 |
| mfa_fatigue | 1 | 0 | 0 | 2 | 1.0 | 1.0 |
| privilege_after_anomalous_signin | 1 | 0 | 0 | 2 | 1.0 | 1.0 |
| public_exposure_after_anomaly | 1 | 0 | 0 | 2 | 1.0 | 1.0 |
| mass_download_after_exposure | 1 | 0 | 0 | 2 | 1.0 | 1.0 |
| logging_disabled | 1 | 0 | 0 | 2 | 1.0 | 1.0 |

- dev-01 brute_force_success expected incident: tp (detected by brute_force_success)
- dev-02 password_spray expected incident: tp (detected by password_spray)
- dev-03 scheduled_maintenance expected benign: tn
- dev-04 impossible_travel expected incident: tp (detected by impossible_travel)
- dev-05 plausible_travel expected benign: tn
- dev-06 mfa_fatigue expected incident: tp (detected by mfa_fatigue)
- dev-07 account_takeover_chain expected incident: tp (detected by brute_force_success, logging_disabled, mass_download_after_exposure, privilege_after_anomalous_signin, public_exposure_after_anomaly)

## Limitations

- All data, entities and labels are synthetic and describe a fictional organisation.
- The same author wrote the fixtures and the detectors, so held-out numbers are optimistic.
- Confidence levels come from a documented point rule, not a calibrated model.
- Temporal links state order only; absence of an explicit identifier is not proof of independence.
