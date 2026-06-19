# INTEL-001 — Intelligence Requirements

## Purpose

Defines all intelligence products, entities, and classifications supported by DWITP.

---

# Intelligence Categories

## Ransomware

Indicators:

- Victim disclosures
- Negotiation references
- Leak announcements

---

## Credential Leaks

Indicators:

- Email addresses
- Password dumps
- Authentication databases

---

## Initial Access Brokers

Indicators:

- VPN access sales
- RDP access sales
- Domain access advertisements

---

## Malware Sales

Indicators:

- Stealers
- RATs
- Crypters
- Loaders

---

# Entity Extraction Requirements

## CVEs

Format:

CVE-YYYY-NNNNN

---

## Email Addresses

Extract:

- Full address
- Domain

---

## Domains

Extract:

- Domain
- TLD

---

## Cryptocurrency

Supported:

- BTC
- XMR
- ETH

---

## PGP Fingerprints

Store:

- Fingerprint
- Associated Alias

---

# MITRE ATT&CK Mapping

Supported:

- T1003
- T1059
- T1486
- T1566
- T1078

Additional mappings may be added.

---

# Threat Actor Profiles

Every actor profile should support:

- Aliases
- PGP Keys
- Wallets
- Telegram Handles
- Jabber IDs
- Mention History

---

# Confidence Model

Levels:

- UNCONFIRMED
- LOW
- MEDIUM
- HIGH
- VERIFIED

Single-source intelligence must remain UNCONFIRMED.

---

# End of Document