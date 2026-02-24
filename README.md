# OCI IAM Find Manage Policies

A Python script that audits **all IAM policies** across every compartment in an OCI tenancy and identifies any statement that grants `manage` level access or uses API-action style grants like `{LaunchInstance}`.

Results are written to a timestamped JSON file with a plain-English summary of what each matched statement does.

---

## Why This Matters

In OCI IAM, `manage` is the highest permission verb — it allows full CRUD including deletion and configuration changes on a resource. Policies are scattered across compartments and it is easy to lose track of who has `manage` access to what. This script gives you a full picture in one run.

---

## What It Detects

| Pattern | Example |
|---|---|
| `manage` verb | `Allow group Admins to manage all-resources in tenancy` |
| API-action block | `Allow group X {TerminateInstance} in tenancy` |

The `manage` check uses a word-boundary regex so it will not false-positive on words like `management` or `unmanaged`.

---

## Requirements

- Python 3.9+
- `oci` Python SDK

```bash
pip install oci
```

---

## Authentication Modes

The script supports all standard OCI auth methods and **auto-detects OCI Cloud Shell** — no flags needed when running there.

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

# Or explicitly
python main.py -dt
```

### Local Workstation

```bash
# Default profile in ~/.oci/config
python main.py

# Named profile
python main.py -t PROD

# Custom config file location
python main.py -c /path/to/config -t MYPROFILE
```

### Compute Instance (Instance Principals)

```bash
python main.py -ip
```

### Custom Output File

```bash
python main.py -o my_audit_results.json
```

---

## Output

The script prints progress to the terminal and writes a JSON report:

```
[*] Cloud Shell detected -- switching to delegation token auth automatically
[*] Tenancy  : ocid1.tenancy.oc1..xxxxx
[*] Fetching all compartments ...
[*] Found 42 compartment(s) (including root)
    Scanning: prod-workloads
[OK] Scanned  : 87 policies across 42 compartments
[OK] Matched  : 23 policies with 'manage' verb or API actions
[OK] Report   : oci_manage_policies_20260224_163045.json
```

### JSON Structure

```json
{
  "generated_at": "20260224_163045",
  "tenancy_id": "ocid1.tenancy.oc1..xxxxx",
  "compartments_scanned": 42,
  "total_policies_scanned": 87,
  "policies_with_manage_or_api": 23,
  "policies": [
    {
      "policy_id": "ocid1.policy.oc1..xxxxx",
      "policy_name": "NetworkAdmins",
      "policy_description": "Network team access",
      "compartment_name": "prod-network",
      "time_created": "2024-03-15 10:22:00+00:00",
      "total_statements_in_policy": 4,
      "matched_count": 2,
      "matched_statements": [
        {
          "statement": "Allow group NetworkAdmins to manage virtual-network-family in tenancy",
          "reasons": ["manage verb"],
          "summary": "Grants 'manage' on 'virtual-network-family' to group NetworkAdmins in tenancy."
        }
      ]
    }
  ]
}
```

---

## Permissions Required

The identity running this script needs at minimum:

```
Allow group <your-group> to read policies in tenancy
Allow group <your-group> to read compartments in tenancy
```

In Cloud Shell, your user session's existing permissions are used via the delegation token — no additional setup required as long as your user can read IAM policies.

---

## Notes

- Deleted and inactive compartments are skipped automatically
- If a compartment returns a permission error it is skipped with a warning and the scan continues
- The root tenancy compartment is always included
- Only statements containing `manage` or `{...}` API actions are written to the output — clean `read`/`use`/`inspect` statements are not included

---
