# ike_sweep.py

## Background
IPsec VPN gateways use the Internet Key Exchange (IKE) protocol
(typically on UDP port 500) to negotiate security associations (SAs).\
Each IKEv1 proposal defines a combination of:

-   Encryption algorithm (Enc)
-   Hash / integrity algorithm (Hash)
-   Authentication method (Auth)
-   Diffie--Hellman group (Group)

If the client and gateway agree on a proposal, the gateway responds with
an SA payload that includes details like `Enc=...`, `Hash=...`,
`Auth=...`, and `Group=...`.

Tools like `ike-scan` can send crafted IKEv1 proposals and observe how a
gateway responds. This is useful for:

-   Verifying VPN configuration\
-   Detecting weak or legacy cryptographic settings\
-   Confirming whether pre-shared keys (PSK) or certificate-based
    authentication (e.g. RSA signatures) are in use

> **Important:** This script is intended **only** for use against
> systems you are explicitly authorized to test (your own lab, corporate
> infrastructure with permission, etc.).\
> Unauthorized scanning of third‑party systems may be illegal.

------------------------------------------------------------------------

## Purpose
`ike_sweep.py` automates a bounded IKEv1 transform sweep using
`ike-scan`. It helps you:

1.  Systematically test common IKEv1 transform combinations\
2.  Use vendor-oriented transform profiles (Cisco, Fortinet, Check
    Point, Juniper)\
3.  Detect when a gateway returns an SA payload and extract
    authentication details\
4.  Export results to CSV or text

This is intended for **defensive security assessments** such as:

-   Internal VPN audits\
-   Validating production configs\
-   Identifying outdated transforms

------------------------------------------------------------------------

## Requirements

-   Python 3.6+\
-   `ike-scan` installed and available in PATH

### Installing ike-scan (Debian/Ubuntu)

``` bash
sudo apt-get update
sudo apt-get install ike-scan
```

Make the script executable:

``` bash
chmod +x ike_sweep.py
```

------------------------------------------------------------------------

## Usage

### Basic Syntax

``` bash
./ike_sweep.py <target> [options]
```

### Profiles

  Profile        Purpose
  -------------- --------------------------------
  `generic`      Bounded matrix sweep (default)
  `cisco`        Cisco ASA/IOS transform sets
  `fortinet`     FortiGate transforms
  `checkpoint`   Check Point transforms
  `juniper`      Juniper/SRX transforms

Example:

``` bash
./ike_sweep.py 192.0.2.10 --profile cisco
```

------------------------------------------------------------------------

## Passing Extra ike-scan Options

``` bash
./ike_sweep.py 192.0.2.10 --extra --id=myvpn.example.com
```

------------------------------------------------------------------------

## Output Options

### CSV Output

``` bash
./ike_sweep.py 192.0.2.10 \
  --profile cisco \
  --output results.csv \
  --output-format csv
```

### Text Output

``` bash
./ike_sweep.py 192.0.2.10 \
  --output results.txt \
  --output-format text
```

Only successful SA responses are written.

------------------------------------------------------------------------

## Interpreting Results

When a transform matches, you'll see:

    SA FOUND for transform 5,2,1,14
    SA: Enc=AES Hash=SHA1 Auth=PSK Group=14 ...
    Auth method reported: PSK

If *no* transform matches:

    No SA responses found (NO-PROPOSAL-CHOSEN for all transforms)

------------------------------------------------------------------------

## Legal & Ethical Use

This tool is strictly for **authorized security assessments**:

✔ Internal systems\
✔ Lab environments\
✔ Systems where written authorization exists

❌ Must not be used on third‑party systems without explicit permission
