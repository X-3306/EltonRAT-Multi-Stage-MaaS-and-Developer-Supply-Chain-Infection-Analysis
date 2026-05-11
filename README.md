# EltonRAT-Multi-Stage-MaaS-and-Developer-Supply-Chain-Infection-Analysis
The analyzed materials describe a coordinated MaaS operation with an entire campaign infrastructure consisting of a silently propagating the malicious delivery chain through infected build environments, an obfuscated stager, and a feature-rich final payload operated through shared infrastructure.


# X3306 Elton MaaS Chain Detection Pack

This repository contains defensive detection material for the multi-stage chain described in `X-3306.MaaS.pdf`:

`void.exe -> BK470009.exe -> Elton`

The indicators in `iocs/` are intentionally **not defanged** so they can be loaded directly into SIEMs, EDRs, DNS filters, blocklists, or enrichment pipelines. The public report keeps indicators defanged for safe reading.

## Contents

- `X-3306.MaaS.pdf` - final public report.
- `yara/X3306_Elton_Chain.yar` - YARA rules for loader, stager, payload, panel artifacts, C2 intake, source-code infection, and logo provenance.
- `iocs/domains.txt` - one domain per line.
- `iocs/urls.txt` - one URL per line for high/medium-high confidence network indicators.
- `iocs/urls_low_confidence.txt` - pivots and external references that should not be blocklisted blindly.
- `iocs/hashes.*.txt` - hash lists split by algorithm.
- `iocs/all_iocs.csv` - typed IOC table with confidence and description.
- `script/xor_decode.py` - script that I used to extract githubusercontant link from the file
- `sigma/` - Windows process creation rules for PowerShell loader and ms-settings UAC bypass behavior.
- `flossINFO` - the most important information extracted from floss
- `mitre_attack` - MITRE ATT&CK
- `suricata/` - network rules for DNS, URI, and user-agent detection.

## Suggested Use

Run YARA if `yara-python` is installed:

```powershell
python -m pip install yara-python
python .\tools\validate_package.py
```

Scan a sample directory:

```powershell
yara64.exe -r .\yara\X3306_Elton_Chain.yar C:\path\to\samples
```

## Detection Notes

- `X3306_Elton_Chain_Known_Hashes` is exact-match and high confidence.
- `X3306_Elton_Loader_PowerShell_Cradle` and `X3306_Elton_Source_Code_Infection` are high-confidence when the campaign ID or observed output filenames are present.
- `X3306_Elton_Final_Payload_Behavioral` is broader and should be triaged with surrounding telemetry.
- `X3306_Elton_C2PA_Logo_Metadata` detects the campaign branding artifact, not executable malware.

## Confidence Model

- `high`: direct payload, loader, C2, or strongly unique chain indicator.
- `medium-high`: related infrastructure or behavior with strong correlation.
- `medium`: useful pivot or behavioral signal that may need surrounding context.
- `low`: weak clue, test/debug string, or external pivot.

## License / Sharing

Use for defensive research and threat hunting. If you republish, keep attribution to `github.com/X-3306` and preserve the confidence labels.
