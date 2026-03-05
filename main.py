#!/usr/bin/env python3
"""
OCI IAM User Policy Auditor
Maps 'manage' verb and API-action policies to individual users across all identity domains.

Handles:
  - Multiple identity domains (oci.identity_domains)
  - Group references by name, domain-qualified name, or OCID
  - any-user / any-group → possible_permissions for every user
  - Tag-based conditions → possible_permissions with a note
  - dynamic-group / service → unresolved_statements section

Auth modes:
  -dt   Delegation Token  (auto-detected in Cloud Shell)
  -ip   Instance Principals
  -st   Security Token
  (none) ~/.oci/config (default profile)
  -c + -t  custom config file + named profile

Output: <prefix>.json  and  <prefix>.csv
"""

import oci
import json
import re
import os
import csv
import argparse
from datetime import datetime
from collections import defaultdict


# ─── Detection patterns ───────────────────────────────────────────────────────

MANAGE_RE     = re.compile(r'\bmanage\b', re.IGNORECASE)
API_ACTION_RE = re.compile(r'\{[^}]+\}')
OCID_RE       = re.compile(r'^ocid1\.\w+\.[a-z0-9-]*\.\.[a-zA-Z0-9_-]+$')


# ─── Cloud Shell detection ────────────────────────────────────────────────────

def is_cloud_shell() -> bool:
    return (
        os.environ.get('OCI_CS_USER_CERT_HOST')     is not None or
        os.environ.get('OCI_DELEGATION_TOKEN_FILE') is not None
    )


# ─── Auth (same structure as original) ────────────────────────────────────────

def create_signer(file_location, config_profile, is_instance_principals,
                  is_delegation_token, is_security_token):

    if is_instance_principals:
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        return {'region': signer.region, 'tenancy': signer.tenancy_id}, signer

    if is_delegation_token:
        env_file    = os.environ.get('OCI_CONFIG_FILE')
        env_profile = os.environ.get('OCI_CONFIG_PROFILE')
        config      = oci.config.from_file(env_file, env_profile)
        with open(config['delegation_token_file']) as f:
            token = f.read().strip()
        signer = oci.auth.signers.InstancePrincipalsDelegationTokenSigner(
            delegation_token=token)
        return config, signer

    if is_security_token:
        config = oci.config.from_file(
            oci.config.DEFAULT_LOCATION,
            config_profile or oci.config.DEFAULT_PROFILE
        )
        with open(config['security_token_file']) as f:
            token = f.read()
        private_key = oci.signer.load_private_key_from_file(config['key_file'])
        signer      = oci.auth.signers.SecurityTokenSigner(token, private_key)
        return config, signer

    config = oci.config.from_file(
        file_location or oci.config.DEFAULT_LOCATION,
        config_profile or oci.config.DEFAULT_PROFILE
    )
    signer = oci.signer.Signer(
        tenancy=config['tenancy'],
        user=config['user'],
        fingerprint=config['fingerprint'],
        private_key_file_location=config.get('key_file'),
        pass_phrase=oci.config.get_config_value_or_default(config, 'pass_phrase'),
        private_key_content=config.get('key_content')
    )
    return config, signer


# ─── Compartment helpers ──────────────────────────────────────────────────────

class _Compartment:
    def __init__(self, ocid, name):
        self.id   = ocid
        self.name = name


def get_all_compartments(identity_client, tenancy_id):
    root = _Compartment(tenancy_id, 'root (tenancy)')
    children = oci.pagination.list_call_get_all_results(
        identity_client.list_compartments,
        tenancy_id,
        compartment_id_in_subtree=True,
        lifecycle_state='ACTIVE',
        access_level='ANY'
    ).data
    return [root] + list(children)


# ─── Identity Domain helpers ──────────────────────────────────────────────────

def get_all_identity_domains(identity_client, compartments: list):
    """
    Return all active identity domains across every compartment in the tenancy.

    We iterate over the already-fetched compartment list and call list_domains
    per compartment.  This is more robust than relying solely on
    compartment_id_in_subtree=True because:
      • Handles per-compartment permission errors individually (one failure
        does not abort the entire scan).
      • Works regardless of whether the caller's IAM policy grants subtree
        list access on the root compartment.
      • Deduplicates by domain OCID so domains are never counted twice.

    OCI IAM is a home-region global service — no multi-region iteration needed.
    """
    seen_ids   = set()
    all_domains = []

    for comp in compartments:
        try:
            batch = oci.pagination.list_call_get_all_results(
                identity_client.list_domains,
                compartment_id=comp.id,
                lifecycle_state='ACTIVE'
            ).data
        except oci.exceptions.ServiceError as e:
            print(f'  [!] list_domains failed in "{comp.name}": {e.message}')
            continue

        for domain in batch:
            did = getattr(domain, 'id', None)
            if did and did not in seen_ids:
                seen_ids.add(did)
                all_domains.append(domain)

    return all_domains


def _scim_paginate(fn, **kwargs):
    """
    Identity Domains uses SCIM-style pagination (start_index + count).
    Wraps any list_* call on an IdentityDomainsClient.
    """
    items      = []
    start      = 1
    page_size  = 100
    while True:
        resp  = fn(count=page_size, start_index=start, **kwargs)
        batch = getattr(resp.data, 'resources', None) or []
        items.extend(batch)
        total = getattr(resp.data, 'total_results', 0) or 0
        if len(items) >= total or not batch:
            break
        start += len(batch)
    return items


def fetch_domain_users_and_groups(config, signer, domain, domain_name):
    """
    Fetch all users and groups from one identity domain.

    NOTE: We request users and groups with explicit attribute lists rather than
    attribute_sets=['all'], because OCI Identity Domains does NOT reliably return
    the 'groups' attribute on User objects via the bulk list API.  Instead we fetch
    groups with their 'members' list, which IS reliably populated, and build the
    user↔group mapping from that direction.

    Returns (users: list, groups: list).
    """
    endpoint = domain.url
    try:
        client = oci.identity_domains.IdentityDomainsClient(
            config, signer=signer, service_endpoint=endpoint
        )
    except Exception as e:
        print(f'  [!] Cannot connect to domain "{domain_name}": {e}')
        return [], []

    # Fetch users — we only need identity fields here; memberships come from groups below
    try:
        users = _scim_paginate(
            client.list_users,
            attributes='id,userName,displayName,name,emails,active,groups'
        )
    except oci.exceptions.ServiceError as e:
        print(f'  [!] list_users failed in "{domain_name}": {e.message}')
        users = []

    # Fetch groups WITH their members — this is the authoritative source for membership
    try:
        groups = _scim_paginate(
            client.list_groups,
            attributes='id,displayName,members,externalId'
        )
    except oci.exceptions.ServiceError as e:
        print(f'  [!] list_groups failed in "{domain_name}": {e.message}')
        groups = []

    return users, groups


# ─── Policy statement parsing ─────────────────────────────────────────────────

def _parse_group_ref(raw_name: str):
    """
    Parse a group reference token from an IAM policy statement into
    (domain_or_None, group_name).

    Quoting rules (per OCI policy syntax):
      'domain/group'           → group name only  (slash is inside the single pair of quotes)
      "domain/group"           → group name only  (same, double-quoted)
      'domain'/'group'         → domain + group   (each part separately quoted)
      'domain'/"group"         → domain + group
      domain/'group'           → domain + group
      domain/group             → domain + group   (no quotes at all)
      groupname                → group name only  (no slash)
    """
    if '/' not in raw_name:
        return None, raw_name.strip("'\"")

    # If the ENTIRE string is wrapped in exactly ONE pair of matching quotes
    # the slash is part of the group name — do NOT split on it.
    for q in ("'", '"'):
        if (raw_name.startswith(q) and raw_name.endswith(q)
                and raw_name.count(q) == 2):
            return None, raw_name[1:-1]   # strip the outer quotes; keep the slash

    # Otherwise the slash separates domain from group name.
    # Split on the first slash only.
    slash_idx   = raw_name.index('/')
    domain_raw  = raw_name[:slash_idx].strip().strip("'\"")
    group_raw   = raw_name[slash_idx + 1:].strip().strip("'\"")
    return (domain_raw or None), group_raw


def statement_qualifies(stmt: str):
    """Return (bool, reasons) — True if the statement has manage verb or API actions."""
    reasons = []
    if MANAGE_RE.search(stmt):
        reasons.append('manage verb')
    hits = API_ACTION_RE.findall(stmt)
    if hits:
        reasons.append(f"api-actions: {', '.join(hits)}")
    return bool(reasons), reasons


def parse_statement(stmt: str) -> dict | None:
    """
    Parse an OCI IAM policy statement into its components.

    Handles all subject types:
      group <name>              — by plain name
      group 'domain'/<name>     — domain-qualified
      group ocid1.group.oc1..x  — by OCID
      any-user
      any-group
      dynamic-group <name>
      service <name>

    Returns a dict with keys:
      raw, subject_type, group_name, group_domain, group_is_ocid,
      verb, api_actions, resource, scope, condition, has_tag_condition
    Or None if the statement cannot be parsed.
    """
    original = stmt.strip()
    lower    = original.lower()

    if not lower.startswith('allow '):
        return None

    rest = original[6:].strip()   # everything after 'Allow '

    subject_type   = None
    subject_name   = None
    subject_domain = None
    subject_is_ocid = False

    # ── Identify subject type and extract name ────────────────────────────────
    rl = rest.lower()

    if rl.startswith('any-user'):
        subject_type = 'any-user'
        rest = rest[8:].strip()

    elif rl.startswith('any-group'):
        subject_type = 'any-group'
        rest = rest[9:].strip()

    elif rl.startswith('dynamic-group '):
        subject_type = 'dynamic-group'
        rest = rest[14:].strip()
        m = re.match(r'(.+?)\s+to\s+', rest, re.IGNORECASE)
        if not m:
            return None
        subject_name = m.group(1).strip().strip("'\"")
        rest = rest[m.end() - len('to '):]

    elif rl.startswith('service '):
        subject_type = 'service'
        rest = rest[8:].strip()
        m = re.match(r'(.+?)\s+to\s+', rest, re.IGNORECASE)
        if not m:
            return None
        subject_name = m.group(1).strip().strip("'\"")
        rest = rest[m.end() - len('to '):]

    elif rl.startswith('group '):
        subject_type = 'group'
        rest = rest[6:].strip()
        # Group name: everything up to ' to ' (non-greedy)
        m = re.match(r'(.+?)\s+to\s+', rest, re.IGNORECASE)
        if not m:
            return None
        raw_name = m.group(1).strip()

        # Detect domain-qualified name using quoting-aware helper.
        # 'domain'/'group' or domain/group  → (domain, group)
        # 'domain/group'                    → (None, 'domain/group')  ← whole thing is the group name
        subject_domain, subject_name = _parse_group_ref(raw_name)

        if subject_name and OCID_RE.match(subject_name):
            subject_is_ocid = True

        rest = rest[m.end() - len('to '):]

    else:
        return None   # Unknown subject type

    # ── Expect 'to ' next ─────────────────────────────────────────────────────
    if not rest.lower().startswith('to '):
        return None
    rest = rest[3:].strip()

    # ── Extract verb / API actions ────────────────────────────────────────────
    api_actions = API_ACTION_RE.findall(rest)
    if api_actions:
        verb = 'api-action'
        # Advance past the full API action block
        m = re.match(r'(\{[^}]+\}(?:\s*,\s*\{[^}]+\})*)\s*', rest)
        rest = rest[m.end():].strip() if m else rest
    else:
        m = re.match(r'(manage|use|read|inspect)\s+', rest, re.IGNORECASE)
        if not m:
            return None
        verb = m.group(1).lower()
        rest = rest[m.end():].strip()

    # ── Extract resource type ─────────────────────────────────────────────────
    m = re.match(r'(\S+)', rest)
    if not m:
        return None
    resource = m.group(1)
    rest = rest[m.end():].strip()

    # ── Extract scope and optional where-condition ────────────────────────────
    scope     = 'tenancy'
    condition = ''

    if rest.lower().startswith('in '):
        rest = rest[3:].strip()
        where_m = re.search(r'\bwhere\b', rest, re.IGNORECASE)
        if where_m:
            scope     = rest[:where_m.start()].strip()
            condition = rest[where_m.end():].strip()
        else:
            scope = rest.strip()
    elif rest.lower().startswith('where '):
        condition = rest[6:].strip()

    has_tag = bool(re.search(r'\btag\b', condition, re.IGNORECASE)) if condition else False

    return {
        'raw'              : original,
        'subject_type'     : subject_type,
        'group_name'       : subject_name,
        'group_domain'     : subject_domain,
        'group_is_ocid'    : subject_is_ocid,
        'verb'             : verb,
        'api_actions'      : api_actions,
        'resource'         : resource,
        'scope'            : scope,
        'condition'        : condition,
        'has_tag_condition': has_tag,
    }


def make_summary(p: dict) -> str:
    if p['verb'] == 'api-action':
        actions = ', '.join(p['api_actions'])
        return f"Grants API actions [{actions}] on '{p['resource']}' in {p['scope']}."
    return f"Grants '{p['verb']}' on '{p['resource']}' in {p['scope']}."


# ─── Build user / group lookup maps ──────────────────────────────────────────

def build_lookup_maps(all_domain_data: list):
    """
    Build lookup maps for matching policy group references → users.

    Strategy (two-pass per domain):
      PASS 1 — users: build user_records keyed by user-id, tagged with their
                      home domain.  A user's home domain is authoritative —
                      cross-domain group membership is NOT allowed.
      PASS 2 — groups: iterate group.members (always populated) as the
                       PRIMARY source for membership.  Only update a user record
                       if the member's UID belongs to THIS domain (prevents the
                       bug where e.g. Loblaw-test/administrators members bleed
                       into Default-domain user records because the OCID matched).
      PASS 2b — supplement with user.groups if the API happened to return it,
                again restricted to same-domain users.

    Resulting maps:
      user_records        : {user_id -> user_info_dict}
                            user_info includes identity_domain_ocid and
                            identity_domain_compartment for full traceability
      group_name_to_uids  : {(domain_lower, group_name_lower) -> {user_id}}
                            also keyed as {(None, group_name_lower)} for
                            domain-agnostic lookups (policy has no domain prefix)
      group_id_to_uids    : {group_id -> {user_id}}  (OCID-based policy refs)

    all_domain_data : list of
        (domain_name, domain_id, domain_ocid, domain_compartment, users, groups)
    """
    user_records       = {}
    group_name_to_uids = defaultdict(set)
    group_id_to_uids   = defaultdict(set)

    for domain_name, _domain_id, domain_ocid, domain_compartment, users, groups in all_domain_data:

        dl = domain_name.lower()

        # ── PASS 1: build basic user records, keyed by UID, tagged to this domain
        domain_uids = set()   # UIDs that truly belong to this domain
        for user in users:
            uid   = user.id
            uname = getattr(user, 'user_name', None) or uid
            email = ''
            for e in (getattr(user, 'emails', None) or []):
                if getattr(e, 'primary', False):
                    email = getattr(e, 'value', '')
                    break
            if not email:
                first = next(iter(getattr(user, 'emails', None) or []), None)
                email = getattr(first, 'value', '') if first else ''

            domain_uids.add(uid)
            user_records[uid] = {
                'user_name'                  : uname,
                'user_id'                    : uid,
                'identity_domain'            : domain_name,
                'identity_domain_ocid'       : domain_ocid,
                'identity_domain_compartment': domain_compartment,
                'email'                      : email,
                'groups'                     : [],   # populated in pass 2
            }

        # ── PASS 2: authoritative membership from group.members ───────────────
        # OCI Identity Domains reliably populates group.members; user.groups is
        # often absent from the list_users bulk response.
        #
        # CRITICAL: only associate a member with a group if that member's UID
        # is in domain_uids (i.e. belongs to THIS domain).  Without this guard,
        # a cross-domain UID collision causes users from domain A to pick up
        # groups from domain B.
        for grp in groups:
            gid   = grp.id
            gname = getattr(grp, 'display_name', None) or gid

            for member in (getattr(grp, 'members', None) or []):
                # Skip nested-group entries (type='Group')
                mtype = getattr(member, 'type', 'User')
                if isinstance(mtype, str) and mtype.lower() == 'group':
                    continue

                uid = getattr(member, 'value', '')
                if not uid:
                    continue

                if uid in domain_uids:
                    # ── Member belongs to this domain: safe to link ───────────
                    already = [g['group_id'] for g in user_records[uid]['groups']]
                    if gid not in already:
                        user_records[uid]['groups'].append({
                            'group_name': gname,
                            'group_id'  : gid,
                            'domain'    : domain_name,
                        })
                elif uid not in user_records:
                    # ── UID not seen at all yet (rare: service account not in
                    #    list_users). Create a minimal record for this domain. ──
                    display = getattr(member, 'display', uid)
                    domain_uids.add(uid)
                    user_records[uid] = {
                        'user_name'                  : display,
                        'user_id'                    : uid,
                        'identity_domain'            : domain_name,
                        'identity_domain_ocid'       : domain_ocid,
                        'identity_domain_compartment': domain_compartment,
                        'email'                      : '',
                        'groups'                     : [{
                            'group_name': gname,
                            'group_id'  : gid,
                            'domain'    : domain_name,
                        }],
                    }
                else:
                    # ── UID belongs to a DIFFERENT domain already — skip.
                    #    This is the guard that prevents cross-domain bleed. ───
                    continue

                # Build lookup indexes only for same-domain confirmed members
                group_name_to_uids[(dl, gname.lower())].add(uid)
                group_name_to_uids[(None, gname.lower())].add(uid)
                group_id_to_uids[gid].add(uid)

        # ── PASS 2b: supplement with user.groups if the API returned it ───────
        # Restricted to same-domain users only (domain_uids guard).
        for user in users:
            uid = user.id
            if uid not in domain_uids:
                continue
            existing_gids = {g['group_id'] for g in user_records[uid]['groups']}
            for grp_ref in (getattr(user, 'groups', None) or []):
                gid   = getattr(grp_ref, 'value', '')
                gname = getattr(grp_ref, 'display', gid) or gid
                if not gid or gid in existing_gids:
                    continue
                user_records[uid]['groups'].append({
                    'group_name': gname,
                    'group_id'  : gid,
                    'domain'    : domain_name,
                })
                group_name_to_uids[(dl, gname.lower())].add(uid)
                group_name_to_uids[(None, gname.lower())].add(uid)
                group_id_to_uids[gid].add(uid)

    return user_records, group_name_to_uids, group_id_to_uids


# ─── Policy scanning ──────────────────────────────────────────────────────────

def scan_policies(identity_client, compartments: list) -> tuple[list, int]:
    """
    Scan every compartment for qualifying policy statements (manage verb / API actions).
    Returns (list of enriched parsed-statement dicts, total_policies_scanned).
    """
    qualifying = []
    total      = 0

    for comp in compartments:
        print(f'    Scanning: {comp.name:<60}', end='\r')
        try:
            policies = oci.pagination.list_call_get_all_results(
                identity_client.list_policies,
                comp.id
            ).data
        except oci.exceptions.ServiceError as e:
            print(f'\n  [!] Skip "{comp.name}": {e.message}')
            continue

        for pol in policies:
            total += 1
            for stmt in pol.statements:
                qualifies, reasons = statement_qualifies(stmt)
                if not qualifies:
                    continue
                parsed = parse_statement(stmt)
                meta = {
                    'policy_name'    : pol.name,
                    'policy_id'      : pol.id,
                    'compartment'    : comp.name,
                    'compartment_id' : comp.id,
                    'reasons'        : reasons,
                }
                if parsed:
                    parsed.update(meta)
                    parsed['summary'] = make_summary(parsed)
                else:
                    # Couldn't parse — store raw for unresolved section
                    parsed = {
                        'raw'          : stmt,
                        'subject_type' : 'unknown',
                        'parse_error'  : True,
                        **meta
                    }
                qualifying.append(parsed)

    return qualifying, total


# ─── Map statements → users ───────────────────────────────────────────────────

def _perm_record(p: dict, extra: dict | None = None) -> dict:
    """Build a clean permission record from a parsed statement."""
    rec = {
        'policy_name' : p.get('policy_name', ''),
        'policy_id'   : p.get('policy_id', ''),
        'compartment' : p.get('compartment', ''),
        'statement'   : p.get('raw', ''),
        'verb'        : p.get('verb', ''),
        'api_actions' : p.get('api_actions', []),
        'resource'    : p.get('resource', ''),
        'scope'       : p.get('scope', ''),
        'condition'   : p.get('condition', ''),
        'reasons'     : p.get('reasons', []),
        'summary'     : p.get('summary', ''),
    }
    if extra:
        rec.update(extra)
    return rec


def map_statements_to_users(
    parsed_stmts  : list,
    user_records  : dict,
    group_name_to_uids : dict,
    group_id_to_uids   : dict,
) -> tuple[dict, dict]:
    """
    Returns:
      per_user   : {user_id -> {'direct': [...], 'possible': [...]}}
      unresolved : dict of lists (any_user, any_group, tag_based, dynamic_groups,
                                  services, unknown_group_ocids, unparseable)
    """
    per_user   = defaultdict(lambda: {'direct': [], 'possible': []})
    unresolved = {
        'any_user'           : [],
        'any_group'          : [],
        'tag_based'          : [],
        'dynamic_groups'     : [],
        'services'           : [],
        'unknown_group_ocids': [],
        'unparseable'        : [],
    }

    for p in parsed_stmts:

        sub = p.get('subject_type', 'unknown')

        # ── Unparseable ───────────────────────────────────────────────────────
        if p.get('parse_error'):
            unresolved['unparseable'].append(_perm_record(p))
            continue

        # ── any-user ─────────────────────────────────────────────────────────
        if sub == 'any-user':
            rec = _perm_record(p)
            unresolved['any_user'].append(rec)
            for uid in user_records:
                per_user[uid]['possible'].append({
                    **_perm_record(p),
                    'reason': 'any-user — this statement applies to every user in the tenancy',
                })

        # ── any-group ─────────────────────────────────────────────────────────
        elif sub == 'any-group':
            rec = _perm_record(p)
            unresolved['any_group'].append(rec)
            for uid in user_records:
                per_user[uid]['possible'].append({
                    **_perm_record(p),
                    'reason': 'any-group — this statement applies to all groups and their members',
                })

        # ── dynamic-group ─────────────────────────────────────────────────────
        elif sub == 'dynamic-group':
            unresolved['dynamic_groups'].append(
                _perm_record(p, {'dynamic_group': p.get('group_name', '')})
            )

        # ── service ───────────────────────────────────────────────────────────
        elif sub == 'service':
            unresolved['services'].append(
                _perm_record(p, {'service_name': p.get('group_name', '')})
            )

        # ── group ─────────────────────────────────────────────────────────────
        elif sub == 'group':
            gname    = p.get('group_name', '')
            gdomain  = p.get('group_domain')
            is_ocid  = p.get('group_is_ocid', False)
            has_tag  = p.get('has_tag_condition', False)

            matched_uids: set = set()

            if is_ocid:
                matched_uids = group_id_to_uids.get(gname, set())
                if not matched_uids:
                    unresolved['unknown_group_ocids'].append(
                        _perm_record(p, {
                            'group_ocid': gname,
                            'note'      : f'Group OCID {gname!r} not resolved to any user in identity domains',
                        })
                    )
            else:
                name_l = gname.lower()
                if gdomain:
                    # Policy explicitly names a domain → exact domain match ONLY.
                    # Do NOT fall back to the domain-agnostic (None) key: that
                    # would incorrectly include users from other domains (e.g.
                    # a Default-domain user in an 'administrators' group would
                    # wrongly match a policy for 'Loblaw-test'/'administrators').
                    matched_uids = group_name_to_uids.get((gdomain.lower(), name_l), set())
                else:
                    matched_uids = group_name_to_uids.get((None, name_l), set())

            if not matched_uids and not is_ocid:
                # Group name referenced in policy but no users found — still record as unresolved
                unresolved['unknown_group_ocids'].append(
                    _perm_record(p, {
                        'group_name': gname,
                        'group_domain': gdomain or '',
                        'note': f'Group {gname!r} not found in any identity domain (may be empty or deleted)',
                    })
                )

            via = f"{gdomain}/{gname}" if gdomain else gname
            note = 'Group matched by OCID in policy' if is_ocid else ''

            if has_tag:
                # Tag condition: even for resolved groups, membership ≠ permission
                unresolved['tag_based'].append(
                    _perm_record(p, {
                        'via_group' : via,
                        'note'      : 'Tag condition present — not all group members may qualify',
                    })
                )
                for uid in matched_uids:
                    per_user[uid]['possible'].append({
                        **_perm_record(p),
                        'via_group' : via,
                        'reason'    : f'Tag-based condition via group {via!r} — effective access depends on resource/user tags',
                        'note'      : note,
                    })
            else:
                for uid in matched_uids:
                    per_user[uid]['direct'].append({
                        **_perm_record(p),
                        'via_group' : via,
                        'note'      : note,
                    })

    return per_user, unresolved


# ─── Report assembly ──────────────────────────────────────────────────────────

def build_report(user_records, per_user, unresolved, meta) -> dict:
    users_out = []
    for uid, info in sorted(user_records.items(), key=lambda x: x[1]['user_name'].lower()):
        users_out.append({
            'user_name'                  : info['user_name'],
            'user_id'                    : uid,
            'identity_domain'            : info['identity_domain'],
            'identity_domain_ocid'       : info.get('identity_domain_ocid', ''),
            'identity_domain_compartment': info.get('identity_domain_compartment', ''),
            'email'                      : info['email'],
            'groups'                     : [g['group_name'] for g in info['groups']],
            'direct_permissions'         : per_user[uid]['direct'],
            'possible_permissions'       : per_user[uid]['possible'],
        })
    return {
        **meta,
        'users'                : users_out,
        'unresolved_statements': unresolved,
    }


# ─── Output writers ───────────────────────────────────────────────────────────

def write_json(report: dict, path: str) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, default=str)


_CSV_FIELDS = [
    # ── User identity ──────────────────────────────────────────────────────────
    'user_name', 'user_id', 'email',
    'identity_domain', 'identity_domain_ocid', 'identity_domain_compartment',
    # ── Group & policy ─────────────────────────────────────────────────────────
    'via_group', 'policy_name', 'policy_id', 'compartment',
    # ── What the policy grants ─────────────────────────────────────────────────
    'verb', 'api_actions', 'resource', 'scope', 'condition',
    # ── Classification ─────────────────────────────────────────────────────────
    'permission_type', 'reason_or_note', 'statement',
]


def _perm_to_row(user: dict, perm: dict, ptype: str) -> dict:
    api_str = ', '.join(perm.get('api_actions', []))
    return {
        'user_name'                  : user['user_name'],
        'user_id'                    : user['user_id'],
        'email'                      : user['email'],
        'identity_domain'            : user['identity_domain'],
        'identity_domain_ocid'       : user.get('identity_domain_ocid', ''),
        'identity_domain_compartment': user.get('identity_domain_compartment', ''),
        'via_group'                  : perm.get('via_group', ''),
        'policy_name'                : perm.get('policy_name', ''),
        'policy_id'                  : perm.get('policy_id', ''),
        'compartment'                : perm.get('compartment', ''),
        'verb'                       : perm.get('verb', ''),
        'api_actions'                : api_str,
        'resource'                   : perm.get('resource', ''),
        'scope'                      : perm.get('scope', ''),
        'condition'                  : perm.get('condition', ''),
        'permission_type'            : ptype,
        'reason_or_note'             : perm.get('reason', perm.get('note', '')),
        'statement'                  : perm.get('statement', ''),
    }


def write_csv(report: dict, path: str) -> None:
    rows = []

    # Per-user rows
    for user in report['users']:
        for p in user['direct_permissions']:
            rows.append(_perm_to_row(user, p, 'direct'))
        for p in user['possible_permissions']:
            rows.append(_perm_to_row(user, p, 'possible'))

    # Unresolved section (labelled rows — no user_name)
    unresolved = report.get('unresolved_statements', {})
    category_label = {
        'any_user'           : 'UNRESOLVED — any-user',
        'any_group'          : 'UNRESOLVED — any-group',
        'tag_based'          : 'UNRESOLVED — tag-based condition',
        'dynamic_groups'     : 'UNRESOLVED — dynamic-group',
        'services'           : 'UNRESOLVED — service principal',
        'unknown_group_ocids': 'UNRESOLVED — group not found',
        'unparseable'        : 'UNRESOLVED — parse error',
    }
    for key, label in category_label.items():
        for p in unresolved.get(key, []):
            api_str = ', '.join(p.get('api_actions', []))
            rows.append({
                'user_name'                  : label,
                'user_id'                    : '',
                'email'                      : '',
                'identity_domain'            : '',
                'identity_domain_ocid'       : '',
                'identity_domain_compartment': '',
                'via_group'                  : p.get('via_group', p.get('group_name', p.get('dynamic_group', p.get('service_name', '')))),
                'policy_name'                : p.get('policy_name', ''),
                'policy_id'                  : p.get('policy_id', ''),
                'compartment'                : p.get('compartment', ''),
                'verb'                       : p.get('verb', ''),
                'api_actions'                : api_str,
                'resource'                   : p.get('resource', ''),
                'scope'                      : p.get('scope', ''),
                'condition'                  : p.get('condition', ''),
                'permission_type'            : 'unresolved',
                'reason_or_note'             : p.get('note', ''),
                'statement'                  : p.get('statement', p.get('raw', '')),
            })

    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=_CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Audit OCI 'manage'/API-action policies mapped to individual users"
    )
    parser.add_argument('-c', default='', dest='file_location',
                        help='OCI config file path')
    parser.add_argument('-t', default='', dest='config_profile',
                        help='OCI config profile name')
    parser.add_argument('-ip', action='store_true', dest='is_instance_principals',
                        help='Use Instance Principals auth')
    parser.add_argument('-dt', action='store_true', dest='is_delegation_token',
                        help='Use Delegation Token auth (Cloud Shell)')
    parser.add_argument('-st', action='store_true', dest='is_security_token',
                        help='Use Security Token auth')
    parser.add_argument('-o', default='', dest='output_prefix',
                        help='Output file prefix (default: oci_user_policies_<timestamp>)')
    cmd = parser.parse_args()

    # Auto-detect Cloud Shell
    if not any([cmd.is_instance_principals, cmd.is_delegation_token, cmd.is_security_token]):
        if is_cloud_shell():
            print('[*] Cloud Shell detected — switching to delegation token auth automatically')
            cmd.is_delegation_token = True

    config, signer = create_signer(
        cmd.file_location, cmd.config_profile,
        cmd.is_instance_principals, cmd.is_delegation_token, cmd.is_security_token
    )
    tenancy_id      = config['tenancy']
    identity_client = oci.identity.IdentityClient(config, signer=signer)

    print(f'[*] Tenancy : {tenancy_id}')

    # ── 1. Compartments ───────────────────────────────────────────────────────
    print('[*] Fetching compartments ...')
    compartments = get_all_compartments(identity_client, tenancy_id)
    print(f'[*] Found {len(compartments)} compartment(s) (including root)')

    # Build compartment_id → name map (used to resolve domain compartment names)
    comp_map = {c.id: c.name for c in compartments}

    # ── 2. Identity Domains ───────────────────────────────────────────────────
    print('[*] Fetching identity domains across all compartments ...')
    domains = get_all_identity_domains(identity_client, compartments)
    print(f'[*] Found {len(domains)} identity domain(s)')

    all_domain_data = []
    total_users = 0
    for domain in domains:
        dname      = getattr(domain, 'display_name', None) or getattr(domain, 'name', str(domain.id))
        docid      = getattr(domain, 'id', '')
        dcomp_id   = getattr(domain, 'compartment_id', '')
        dcomp_name = comp_map.get(dcomp_id, dcomp_id)   # resolve name; fall back to OCID

        print(f'    Domain: {dname}  (ocid: {docid}  compartment: {dcomp_name})')
        users, groups = fetch_domain_users_and_groups(config, signer, domain, dname)
        print(f'           {len(users)} users, {len(groups)} groups')
        # Tuple: (domain_name, domain_id, domain_ocid, domain_compartment, users, groups)
        all_domain_data.append((dname, domain.id, docid, dcomp_name, users, groups))
        total_users += len(users)

    print(f'[*] Total users across all domains: {total_users}')

    # ── 3. Build lookup maps ──────────────────────────────────────────────────
    print('[*] Building group → user lookup maps ...')
    user_records, group_name_to_uids, group_id_to_uids = build_lookup_maps(all_domain_data)

    # ── 4. Scan policies ──────────────────────────────────────────────────────
    print('[*] Scanning policies across all compartments ...')
    parsed_stmts, total_policies = scan_policies(identity_client, compartments)
    print(f'\n[*] Scanned {total_policies} policies — {len(parsed_stmts)} qualifying statements found')

    # ── 5. Map statements → users ─────────────────────────────────────────────
    print('[*] Mapping policy statements to users ...')
    per_user, unresolved = map_statements_to_users(
        parsed_stmts, user_records, group_name_to_uids, group_id_to_uids
    )

    # ── 6. Assemble & write output ────────────────────────────────────────────
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    prefix    = cmd.output_prefix.rstrip('_') if cmd.output_prefix else f'oci_user_policies_{timestamp}'

    total_unresolved = sum(len(v) for v in unresolved.values())
    meta = {
        'generated_at'             : timestamp,
        'tenancy_id'               : tenancy_id,
        'identity_domains_scanned' : len(domains),
        'compartments_scanned'     : len(compartments),
        'total_users'              : total_users,
        'total_policies_scanned'   : total_policies,
        'qualifying_statements'    : len(parsed_stmts),
        'unresolved_statements'    : total_unresolved,
    }

    report   = build_report(user_records, per_user, unresolved, meta)
    json_out = f'{prefix}.json'
    csv_out  = f'{prefix}.csv'

    write_json(report, json_out)
    write_csv(report, csv_out)

    users_with_direct   = sum(1 for u in report['users'] if u['direct_permissions'])
    users_with_possible = sum(1 for u in report['users'] if u['possible_permissions'])

    print(f'')
    print(f'[OK] Users with DIRECT manage access   : {users_with_direct}')
    print(f'[OK] Users with POSSIBLE manage access  : {users_with_possible}')
    print(f'[OK] Unresolved statements              : {total_unresolved}')
    print(f'[OK] JSON report : {json_out}')
    print(f'[OK] CSV  report : {csv_out}')


if __name__ == '__main__':
    main()
