#!/usr/bin/env python3
"""
OCI Policy Auditor - Finds all policies with 'manage' verb or API-level actions
Outputs a JSON file with policy details and summaries

Auth modes (same as cis_reports.py):
  -dt   Delegation Token  → Cloud Shell  (AUTO-DETECTED — no flag needed in Cloud Shell)
  -ip   Instance Principals → Compute VM
  -st   Security Token    → oci session authenticate
  (none) ~/.oci/config    → local workstation

Usage:
  Cloud Shell (auto):     python3 oci_policy_audit.py          <- detects Cloud Shell automatically
  Cloud Shell (explicit): python3 oci_policy_audit.py -dt
  Local workstation:      python3 oci_policy_audit.py
  Specific profile:       python3 oci_policy_audit.py -t MYPROFILE
  Compute instance:       python3 oci_policy_audit.py -ip
"""

import oci
import json
import re
import os
import sys
import argparse
from datetime import datetime


# -- Cloud Shell auto-detection -----------------------------------------------

def is_cloud_shell() -> bool:
    """
    OCI Cloud Shell sets OCI_CS_USER_CERT_HOST in the environment.
    OCI_DELEGATION_TOKEN_FILE is also present as a fallback check.
    """
    return (
        os.environ.get('OCI_CS_USER_CERT_HOST')     is not None or
        os.environ.get('OCI_DELEGATION_TOKEN_FILE') is not None
    )


# -- detection patterns --------------------------------------------------------

MANAGE_PATTERN     = re.compile(r'\bmanage\b', re.IGNORECASE)
API_ACTION_PATTERN = re.compile(r'\{[^}]+\}')   # matches {LaunchInstance} style


# -- auth (lifted from cis_reports.py) ----------------------------------------

def create_signer(file_location, config_profile, is_instance_principals,
                  is_delegation_token, is_security_token):

    # Instance Principals (Compute VM)
    if is_instance_principals:
        try:
            signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
            config = {'region': signer.region, 'tenancy': signer.tenancy_id}
            return config, signer
        except Exception:
            print("Error obtaining instance principals certificate, aborting")
            raise SystemExit

    # Delegation Token (Cloud Shell)
    elif is_delegation_token:
        try:
            env_config_file    = os.environ.get('OCI_CONFIG_FILE')
            env_config_section = os.environ.get('OCI_CONFIG_PROFILE')

            if env_config_file is None or env_config_section is None:
                print("*** OCI_CONFIG_FILE and OCI_CONFIG_PROFILE env variables not found.")
                print("    Are you running this in OCI Cloud Shell? ***")
                raise SystemExit

            config = oci.config.from_file(env_config_file, env_config_section)
            delegation_token_location = config["delegation_token_file"]

            with open(delegation_token_location, 'r') as f:
                delegation_token = f.read().strip()

            signer = oci.auth.signers.InstancePrincipalsDelegationTokenSigner(
                delegation_token=delegation_token)
            return config, signer

        except KeyError:
            print("* Key Error: delegation_token_file not found in config")
            raise SystemExit
        except Exception:
            raise

    # Security Token (oci session authenticate)
    elif is_security_token:
        try:
            config = oci.config.from_file(
                oci.config.DEFAULT_LOCATION,
                (config_profile if config_profile else oci.config.DEFAULT_PROFILE)
            )
            token_file = config['security_token_file']
            with open(token_file, 'r') as f:
                token = f.read()

            private_key = oci.signer.load_private_key_from_file(config['key_file'])
            signer      = oci.auth.signers.SecurityTokenSigner(token, private_key)
            return config, signer

        except KeyError:
            print("* Key Error: security_token_file not found in config")
            raise SystemExit
        except Exception:
            raise

    # Config file (local ~/.oci/config)
    else:
        try:
            config = oci.config.from_file(
                file_location if file_location else oci.config.DEFAULT_LOCATION,
                (config_profile if config_profile else oci.config.DEFAULT_PROFILE)
            )
            signer = oci.signer.Signer(
                tenancy=config["tenancy"],
                user=config["user"],
                fingerprint=config["fingerprint"],
                private_key_file_location=config.get("key_file"),
                pass_phrase=oci.config.get_config_value_or_default(config, "pass_phrase"),
                private_key_content=config.get("key_content")
            )
            return config, signer

        except Exception:
            print(f"** OCI Config not found at {oci.config.DEFAULT_LOCATION} -- aborting **")
            raise SystemExit


# -- policy helpers ------------------------------------------------------------

def statement_has_manage_or_api(statement: str) -> tuple[bool, list[str]]:
    """Return (matched, reasons) for a single policy statement."""
    reasons = []
    if MANAGE_PATTERN.search(statement):
        reasons.append("manage verb")
    api_hits = API_ACTION_PATTERN.findall(statement)
    if api_hits:
        reasons.append(f"api-actions: {', '.join(api_hits)}")
    return bool(reasons), reasons


def summarize_statement(stmt: str) -> str:
    """
    Build a 1-2 line human summary from an OCI policy statement.
    Parses:  Allow <subject> to <verb> <resource> in <location> [where ...]
    """
    m = re.match(
        r'(?i)allow\s+(?P<subject>.+?)\s+to\s+(?P<verb>\S+)\s+(?P<resource>\S+)'
        r'(?:\s+in\s+(?P<location>[^wW][^\s]*(?:\s+\S+)*))?',
        stmt.strip()
    )
    if m:
        subject  = m.group("subject")
        verb     = m.group("verb")
        resource = m.group("resource")
        location = m.group("location") or "any location"
        return f"Grants '{verb}' on '{resource}' to {subject} in {location}."
    return stmt[:200] + ("..." if len(stmt) > 200 else "")


class _SimpleCompartment:
    """
    Minimal stand-in for root tenancy compartment.
    We avoid calling get_compartment(tenancy_id) because delegation-token
    sessions in Cloud Shell may not have 'inspect tenancy' permission,
    which causes the 401 NotAuthenticated error.
    """
    def __init__(self, ocid, name):
        self.id   = ocid
        self.name = name


def get_all_compartments(identity_client, tenancy_id: str) -> list:
    """
    Return root + all active descendant compartments.
    Root is constructed locally -- no API call -- to avoid 401 in Cloud Shell.
    """
    root = _SimpleCompartment(tenancy_id, "root (tenancy)")
    children = oci.pagination.list_call_get_all_results(
        identity_client.list_compartments,
        tenancy_id,
        compartment_id_in_subtree=True,
        lifecycle_state="ACTIVE",
        access_level="ANY"
    ).data
    return [root] + list(children)


# -- main ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Audit OCI policies for 'manage' verb or API-action grants",
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=60, width=140)
    )
    parser.add_argument('-c', default="", dest='file_location',
                        help='OCI config file location (default: ~/.oci/config)')
    parser.add_argument('-t', default="", dest='config_profile',
                        help='Config profile/section to use')
    parser.add_argument('-ip', action='store_true', default=False,
                        dest='is_instance_principals',
                        help='Use Instance Principals (Compute VM)')
    parser.add_argument('-dt', action='store_true', default=False,
                        dest='is_delegation_token',
                        help='Use Delegation Token -- for OCI Cloud Shell')
    parser.add_argument('-st', action='store_true', default=False,
                        dest='is_security_token',
                        help='Use Security Token (oci session authenticate)')
    parser.add_argument('-o', default="", dest='output_file',
                        help='Output JSON filename (default: auto-generated with timestamp)')
    cmd = parser.parse_args()

    # Auto-detect Cloud Shell if no auth flag was given
    if not any([cmd.is_instance_principals, cmd.is_delegation_token, cmd.is_security_token]):
        if is_cloud_shell():
            print("[*] Cloud Shell detected -- switching to delegation token auth automatically")
            cmd.is_delegation_token = True

    # Auth
    config, signer = create_signer(
        cmd.file_location, cmd.config_profile,
        cmd.is_instance_principals, cmd.is_delegation_token, cmd.is_security_token
    )
    tenancy_id = config["tenancy"]

    identity_client = oci.identity.IdentityClient(config, signer=signer)

    print(f"[*] Tenancy  : {tenancy_id}")
    print(f"[*] Fetching all compartments ...")

    compartments   = get_all_compartments(identity_client, tenancy_id)
    print(f"[*] Found {len(compartments)} compartment(s) (including root)")

    results        = []
    total_policies = 0
    total_matched  = 0

    for comp in compartments:
        comp_id   = comp.id
        comp_name = comp.name
        print(f"    Scanning: {comp_name:<60}", end="\r")

        try:
            policies = oci.pagination.list_call_get_all_results(
                identity_client.list_policies,
                comp_id
            ).data
        except oci.exceptions.ServiceError as e:
            print(f"\n  [!] Skip '{comp_name}': {e.message}")
            continue

        for policy in policies:
            total_policies += 1
            matched_statements = []

            for stmt in policy.statements:
                hit, reasons = statement_has_manage_or_api(stmt)
                if hit:
                    matched_statements.append({
                        "statement" : stmt,
                        "reasons"   : reasons,
                        "summary"   : summarize_statement(stmt)
                    })

            if matched_statements:
                total_matched += 1
                results.append({
                    "policy_id"                 : policy.id,
                    "policy_name"               : policy.name,
                    "policy_description"        : policy.description or "",
                    "compartment_id"            : comp_id,
                    "compartment_name"          : comp_name,
                    "time_created"              : str(policy.time_created),
                    "total_statements_in_policy": len(policy.statements),
                    "matched_count"             : len(matched_statements),
                    "matched_statements"        : matched_statements
                })

    # Write JSON
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file  = cmd.output_file if cmd.output_file else f"oci_manage_policies_{timestamp}.json"

    report = {
        "generated_at"               : timestamp,
        "tenancy_id"                 : tenancy_id,
        "compartments_scanned"       : len(compartments),
        "total_policies_scanned"     : total_policies,
        "policies_with_manage_or_api": total_matched,
        "policies"                   : results
    }

    with open(out_file, "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\n[OK] Scanned  : {total_policies} policies across {len(compartments)} compartments")
    print(f"[OK] Matched  : {total_matched} policies with 'manage' verb or API actions")
    print(f"[OK] Report   : {out_file}")


if __name__ == "__main__":
    main()
