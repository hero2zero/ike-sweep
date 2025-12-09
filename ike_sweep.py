#!/usr/bin/env python3
import subprocess
import argparse
import re
import csv
from typing import List, Tuple, Dict, Optional

# Type alias for readability
Transform = Tuple[int, int, int, int]  # (Enc, Hash, Auth, Group)


def get_vendor_profile(profile: str) -> List[Transform]:
    """
    Return a list of transforms for a given vendor profile.

    Enc, Hash, Auth, Group
    Enc:  1=DES, 3=3DES, 5=AES-128, 7=AES-256
    Hash: 1=MD5, 2=SHA1, 4=SHA2-256
    Auth: 1=PSK, 3=RSA-SIG
    Group: 1,2,5,14 = common MODP groups
    """

    profiles: Dict[str, List[Transform]] = {}

    # Generic bounded sweep will be handled separately
    profiles["cisco"] = [
        # Classic and common Cisco ASA / IOS transform sets
        (3, 2, 1, 2),   # 3DES-SHA1-PSK-DH2
        (5, 2, 1, 2),   # AES128-SHA1-PSK-DH2
        (7, 2, 1, 2),   # AES256-SHA1-PSK-DH2
        (5, 2, 3, 2),   # AES128-SHA1-RSA-DH2
        (7, 2, 3, 2),   # AES256-SHA1-RSA-DH2
        (5, 4, 1, 14),  # AES128-SHA256-PSK-DH14
        (7, 4, 1, 14),  # AES256-SHA256-PSK-DH14
    ]

    profiles["fortinet"] = [
        # Common FortiGate style configs
        (5, 2, 1, 5),   # AES128-SHA1-PSK-DH5
        (7, 2, 1, 5),   # AES256-SHA1-PSK-DH5
        (5, 4, 1, 14),  # AES128-SHA256-PSK-DH14
        (7, 4, 1, 14),  # AES256-SHA256-PSK-DH14
        (5, 2, 3, 5),   # AES128-SHA1-RSA-DH5
        (7, 2, 3, 5),   # AES256-SHA1-RSA-DH5
    ]

    profiles["checkpoint"] = [
        # Common Check Point IKEv1 defaults
        (3, 2, 1, 2),   # 3DES-SHA1-PSK-DH2
        (5, 2, 1, 2),   # AES128-SHA1-PSK-DH2
        (7, 2, 1, 2),   # AES256-SHA1-PSK-DH2
        (5, 2, 3, 2),   # AES128-SHA1-RSA-DH2
        (7, 2, 3, 2),   # AES256-SHA1-RSA-DH2
        (5, 4, 1, 14),  # AES128-SHA256-PSK-DH14
    ]

    profiles["juniper"] = [
        # Common Juniper / SRX style configs
        (5, 2, 1, 2),   # AES128-SHA1-PSK-DH2
        (7, 2, 1, 2),   # AES256-SHA1-PSK-DH2
        (5, 2, 1, 5),   # AES128-SHA1-PSK-DH5
        (7, 2, 1, 5),   # AES256-SHA1-PSK-DH5
        (5, 4, 1, 14),  # AES128-SHA256-PSK-DH14
        (7, 4, 1, 14),  # AES256-SHA256-PSK-DH14
        (5, 2, 3, 2),   # AES128-SHA1-RSA-DH2
    ]

    return profiles.get(profile.lower(), [])


def parse_sa_from_output(output: str) -> List[str]:
    """
    Parse SA lines from ike-scan output, return list of SA strings (contents inside SA=(...)).
    """
    sas = []
    for line in output.splitlines():
        match = re.search(r"SA=\(([^)]*)\)", line)
        if match:
            sas.append(match.group(1))
    return sas


def write_results_to_file(
    output_path: str,
    output_format: str,
    target: str,
    profile: str,
    results: List[Dict[str, str]],
) -> None:
    """
    Write successful SA results to a file in CSV or text format.
    """
    if output_format == "csv":
        fieldnames = [
            "target",
            "profile",
            "transform",
            "enc",
            "hash",
            "auth",
            "group",
            "auth_method",
            "sa",
        ]
        with open(output_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                row = {
                    "target": target,
                    "profile": profile,
                    "transform": r["transform"],
                    "enc": r["enc"],
                    "hash": r["hash"],
                    "auth": r["auth"],
                    "group": r["group"],
                    "auth_method": r["auth_method"],
                    "sa": r["sa"],
                }
                writer.writerow(row)
    else:  # text
        with open(output_path, "w") as f:
            f.write(f"IKE sweep results for target {target}, profile {profile}\n")
            f.write("=" * 80 + "\n\n")
            if not results:
                f.write("No SA responses found (no Auth=... observed).\n")
                return
            for r in results:
                f.write(f"Transform: {r['transform']} (Enc={r['enc']}, Hash={r['hash']}, "
                        f"Auth={r['auth']}, Group={r['group']})\n")
                f.write(f"  Auth method: {r['auth_method']}\n")
                f.write(f"  SA: {r['sa']}\n")
                f.write("-" * 80 + "\n")


def run_ike_scan(
    target: str,
    transforms: List[Transform],
    extra_args: List[str],
    profile: str,
    use_matrix: bool = False,
    output_path: Optional[str] = None,
    output_format: str = "csv",
) -> None:
    """
    Run ike-scan against target with either:
      - a list of explicit transforms (vendor profile), OR
      - a bounded matrix sweep (if use_matrix=True).

    Optionally record successful SA results and write them to CSV/text.
    """
    successful_sas: List[Tuple[str, str, Transform]] = []  # (transform_str, sa_string, transform tuple)

    if use_matrix:
        enc_list = [1, 3, 5, 7]      # DES, 3DES, AES-128, AES-256
        hash_list = [1, 2, 4]        # MD5, SHA1, SHA2-256
        auth_list = [1, 3]           # PSK, RSA-SIG
        group_list = [2, 5, 14]      # MODP 1024, 1536, 2048

        matrix_transforms: List[Transform] = []
        for enc in enc_list:
            for hsh in hash_list:
                for auth in auth_list:
                    for group in group_list:
                        matrix_transforms.append((enc, hsh, auth, group))

        transforms = matrix_transforms

    for enc, hsh, auth, group in transforms:
        trans_str = f"{enc},{hsh},{auth},{group}"
        print("=" * 80)
        print(f"[+] Testing transform: Enc={enc}, Hash={hsh}, Auth={auth}, Group={group}")
        print(f"[+] Command: ike-scan -A --trans={trans_str} {target} {' '.join(extra_args)}")
        print("-" * 80)

        cmd = ["ike-scan", "-A", f"--trans={trans_str}"] + extra_args + [target]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
        except FileNotFoundError:
            print("[!] ike-scan not found. Make sure it is installed and in your PATH.")
            return
        except subprocess.TimeoutExpired:
            print(f"[!] Command timed out for transform {trans_str}")
            print()
            continue

        if result.stdout:
            print(result.stdout.strip())
            sas = parse_sa_from_output(result.stdout)
            for sa in sas:
                # Highlight any SA with Auth= field
                auth_match = re.search(r"Auth=([A-Za-z0-9_]+)", sa)
                auth_value = auth_match.group(1) if auth_match else "UNKNOWN"
                print()
                print("!!! -------------------------------------------------------------")
                print(f"!!! SA FOUND for transform {trans_str}")
                print(f"!!! SA: {sa}")
                print(f"!!! Auth method reported: {auth_value}")
                print("!!! -------------------------------------------------------------")
                print()
                successful_sas.append((trans_str, sa, (enc, hsh, auth, group)))

        if result.stderr:
            print("[stderr]")
            print(result.stderr.strip())

        print()

    # Summary of successful SAs
    print("=" * 80)
    print("[*] Sweep complete.")
    if successful_sas:
        print("[*] Successful SA responses detected:")
        for trans_str, sa, (enc, hsh, auth, group) in successful_sas:
            auth_match = re.search(r"Auth=([A-Za-z0-9_]+)", sa)
            auth_value = auth_match.group(1) if auth_match else "UNKNOWN"
            print(f"  - Transform {trans_str}: Enc={enc}, Hash={hsh}, Auth={auth}, "
                  f"Group={group} | Auth={auth_value}, SA=({sa})")
    else:
        print("[*] No SA responses found (no Auth=... observed).")
        print("    All transforms likely returned notify (e.g. NO-PROPOSAL-CHOSEN) or no response.")
    print("=" * 80)

    # Optional file output
    if output_path:
        file_results: List[Dict[str, str]] = []
        for trans_str, sa, (enc, hsh, auth, group) in successful_sas:
            auth_match = re.search(r"Auth=([A-Za-z0-9_]+)", sa)
            auth_value = auth_match.group(1) if auth_match else "UNKNOWN"
            file_results.append(
                {
                    "transform": trans_str,
                    "enc": str(enc),
                    "hash": str(hsh),
                    "auth": str(auth),
                    "group": str(group),
                    "auth_method": auth_value,
                    "sa": sa,
                }
            )
        write_results_to_file(output_path, output_format, target, profile, file_results)
        print(f"[*] Results written to {output_path} ({output_format}).")


def main():
    parser = argparse.ArgumentParser(
        description="IKEv1 transform sweep using ike-scan (authorized testing only)."
    )
    parser.add_argument("target", help="Target IP or hostname (authorized system only)")
    parser.add_argument(
        "--profile",
        choices=["generic", "cisco", "fortinet", "checkpoint", "juniper"],
        default="generic",
        help="Vendor/profile for transform selection. 'generic' uses a bounded matrix sweep."
    )
    parser.add_argument(
        "--extra",
        nargs=argparse.REMAINDER,
        default=[],
        help="Extra arguments to pass to ike-scan (e.g. --id=myvpn.example.com)"
    )
    parser.add_argument(
        "--output",
        help="Optional output file path to store successful SA results (CSV or text).",
        default=None,
    )
    parser.add_argument(
        "--output-format",
        choices=["csv", "text"],
        default="csv",
        help="Output format when --output is provided (default: csv).",
    )

    args = parser.parse_args()

    if args.profile == "generic":
        print("[*] Using generic bounded matrix sweep (common transforms).")
        run_ike_scan(
            target=args.target,
            transforms=[],
            extra_args=args.extra,
            profile=args.profile,
            use_matrix=True,
            output_path=args.output,
            output_format=args.output_format,
        )
    else:
        print(f"[*] Using vendor profile: {args.profile}")
        transforms = get_vendor_profile(args.profile)
        if not transforms:
            print("[!] No transforms defined for this profile. Exiting.")
            return
        run_ike_scan(
            target=args.target,
            transforms=transforms,
            extra_args=args.extra,
            profile=args.profile,
            use_matrix=False,
            output_path=args.output,
            output_format=args.output_format,
        )


if __name__ == "__main__":
    main()