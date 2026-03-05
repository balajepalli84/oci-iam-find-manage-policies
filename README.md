# OCI IAM Find & Manage Policies — User Policy Auditor

A Python script that audits all IAM policies across every compartment in an OCI tenancy,
identifies any statement that grants `manage` level access or uses API-action style grants,
and maps those permissions down to **individual users** through their identity domain group memberships.

Results are written to a timestamped **JSON** and **CSV** file.

---

## Why This Matters

In OCI IAM, `manage` is the highest permission verb — it allows full CRUD including deletion
and configuration changes on a resource. Policies grant access to **groups**, but security teams
need to know which **users** actually have that access. This script does the full resolution:

```
Policy statement → Group → Identity Domain → Users
```

It also flags situations where direct resolution is not possible (any-user, tag conditions)

---

## What It Detects & Resolves

| Pattern | Example | Resolution |
|---|---|---|
| `manage` verb | `Allow group Admins to manage all-resources in tenancy` | Resolved to users via group membership |
| API-action block | `Allow group X to {TerminateInstance} in tenancy` | Resolved to users via group membership |
| `any-user` | `Allow any-user to manage objects in compartment X` | Listed as `possible_permissions` for every user |
| `any-group` | `Allow any-group to manage buckets in tenancy` | Listed as `possible_permissions` for every user |


The `manage` check uses a word-boundary regex — no false positives on words like `management`.

---

## Requirements

- Python 3.9+
- `oci` Python SDK

```bash
pip install oci
```

---

## Authentication Modes

The script supports all standard OCI auth methods and **auto-detects OCI Cloud Shell** —
no flags needed when running there.

| Flag | Method | When to use |
|---|---|---|
| *(none)* | Auto-detect | Cloud Shell auto-switches; local uses `~/.oci/config` |
| `-dt` | Delegation Token | OCI Cloud Shell (explicit) |
| `-ip` | Instance Principals | Running on an OCI Compute instance |
| `-st` | Security Token | After `oci session authenticate` |
| `-c` + `-t` | Config file + profile | Local workstation with a named profile |

---

## Usage

### OCI Cloud Shell (recommended)

```bash
# Download
wget -q https://raw.githubusercontent.com/balajepalli84/oci-iam-find-manage-policies/main/main.py

# Run (Cloud Shell auto-detected)
python3 main.py

# Or explicitly
python3 main.py -dt
```

### Local Workstation

```bash
# Default profile in ~/.oci/config
python3 main.py

# Named profile
python3 main.py -t PROD

# Custom config file location
python3 main.py -c /path/to/config -t MYPROFILE
```

### Compute Instance (Instance Principals)

```bash
python3 main.py -ip
```

### Custom Output Prefix

```bash
python3 main.py -o my_audit
# Produces: my_audit.json  and  my_audit.csv
```

---

## Output

The script prints a 6-step progress log and writes both a JSON and CSV report:

```
[*] Tenancy : ocid1.tenancy.oc1..xxxxx
[*] Fetching compartments ...
[*] Found 42 compartment(s) (including root)
[*] Fetching identity domains across all compartments ...
[*] Found 3 identity domain(s)
    Domain: Default  (ocid: ocid1.domain.oc1..xxxxx  compartment: root (tenancy))
           124 users, 18 groups
    Domain: CorpDirectory  (ocid: ocid1.domain.oc1..yyyyy  compartment: shared-services)
           310 users, 42 groups
[*] Total users across all domains: 434
[*] Building group → user lookup maps ...
[*] Scanning policies across all compartments ...
[*] Scanned 87 policies — 134 qualifying statements found
[*] Mapping policy statements to users ...

[OK] Users with DIRECT manage access   : 38
[OK] Users with POSSIBLE manage access : 434
[OK] Unresolved statements             : 12
[OK] JSON report : oci_user_policies_20260305_103715.json
[OK] CSV  report : oci_user_policies_20260305_103715.csv
```

---

## JSON Structure

```json
{
  "generated_at": "20260305_103715",
  "tenancy_id": "ocid1.tenancy.oc1..xxxxx",
  "identity_domains_scanned": 3,
  "compartments_scanned": 42,
  "total_users": 434,
  "total_policies_scanned": 87,
  "qualifying_statements": 134,
  "unresolved_statements": 12,
  "users": [
    {
      "user_name": "john.smith@example.com",
      "user_id": "ocid1.user.oc1..xxxxx",
      "identity_domain": "Default",
      "identity_domain_ocid": "ocid1.domain.oc1..xxxxx",
      "identity_domain_compartment": "root (tenancy)",
      "email": "john.smith@example.com",
      "groups": ["NetworkAdmins", "DevOps"],
      "direct_permissions": [
        {
          "policy_name": "NetworkAdminPolicy",
          "policy_id": "ocid1.policy.oc1..xxxxx",
          "compartment": "prod-network",
          "statement": "Allow group NetworkAdmins to manage virtual-network-family in tenancy",
          "verb": "manage",
          "resource": "virtual-network-family",
          "scope": "tenancy",
          "condition": "",
          "via_group": "NetworkAdmins",
          "summary": "Grants 'manage' on 'virtual-network-family' in tenancy."
        }
      ],
      "possible_permissions": []
    }
  ],
  "unresolved_statements": {
    "any_user": [],
    "any_group": [],
    "tag_based": [],
    "dynamic_groups": [],
    "services": [],
    "unknown_group_ocids": [],
    "unparseable": []
  }
}
```

---

## CSV Structure

The CSV contains one row per permission per user, making it easy to filter in Excel or import into SIEM tools.

| Column | Description |
|---|---|
| `user_name` | User login name |
| `user_id` | User OCID |
| `email` | User email address |
| `identity_domain` | Identity domain display name |
| `identity_domain_ocid` | Identity domain OCID |
| `identity_domain_compartment` | Compartment the domain lives in |
| `via_group` | Group through which the permission is granted |
| `policy_name` | Name of the IAM policy |
| `policy_id` | OCID of the IAM policy |
| `compartment` | Compartment where the policy is defined |
| `verb` | Permission verb (`manage`, `api-action`) |
| `api_actions` | API action names if applicable |
| `resource` | Resource type (e.g. `all-resources`, `virtual-network-family`) |
| `scope` | Scope of the policy (`tenancy` or compartment name) |
| `condition` | Where-condition if present |
| `permission_type` | `direct`, `possible`, or `unresolved` |
| `reason_or_note` | Explanation for possible/unresolved entries |
| `statement` | Full raw policy statement |

---

## Permissions Required

The identity running this script needs at minimum:

```
Allow group <your-group> to read policies in tenancy
Allow group <your-group> to read compartments in tenancy
Allow group <your-group> to read domains in tenancy
Allow group <your-group> to read domain-memberships in tenancy
```

In Cloud Shell, your user session's existing permissions are used via the delegation token —
no additional setup required as long as your user can read IAM policies and identity domains.

---

## Notes

- **Cross-domain safety**: Group membership is strictly scoped per identity domain — users from
  Domain A will never incorrectly inherit groups from Domain B.
- **`direct_permissions`**: The user is a confirmed member of the group referenced in the policy.
- **`possible_permissions`**: Access may apply (any-user, any-group, or tag-based conditions)
  but cannot be confirmed without runtime context.
- **`unresolved_statements`**: Dynamic groups, service principals, unknown group OCIDs, and
  unparseable statements are collected here for manual review.
- Deleted and inactive compartments are skipped automatically.
- If a compartment or domain returns a permission error it is skipped with a warning and the
  scan continues.
- The root tenancy compartment is always included.
- Generated `.json` and `.csv` output files are excluded from version control via `.gitignore`.

---
