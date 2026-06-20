"""DWITP classification engine — offline, deterministic, explainable.

Rule-based: weighted phrase lexicons + IOC signals, confidence via an exponential
mapping, conservative on terrorism_extremism / human_trafficking. No model, no
network. This is the single seam the pipeline classifies through: the worker in
main.py calls classify(content, entities) and wraps the result.

Engine logic designed by DeepSeek; integrated with three changes for the DWITP
contract: (1) content is truncated to CLASSIFY_MAX_CHARS to bound latency on huge
pages, (2) evidence_quote is "" when the final category is "unknown", (3) the dead
flat_key line in entity flattening was removed. Python 3.12, stdlib only.
"""
from __future__ import annotations

import math
import os
import re
from typing import Dict, List, Tuple

# Bound the scan on pathologically large pages (matching is linear in text length).
CLASSIFY_MAX_CHARS = int(os.environ.get("CLASSIFY_MAX_CHARS", "50000"))

# ----------------------------------------------------------------------
# 1. LEXICON DEFINITIONS
# Each category has a list of (phrase, weight). Phrases are matched with
# word-boundary-aware regexes (case-insensitive). Weights reflect signal
# strength: 0.5 = weak, 1.0 = moderate, 1.5+ = strong. Only unique phrases
# count once per document.
# ----------------------------------------------------------------------
CATEGORY_PHRASES: Dict[str, List[Tuple[str, float]]] = {
    "ransomware": [
        ("LockBit", 1.5), ("Conti", 1.5), ("ALPHV", 1.5), ("BlackCat", 1.5),
        ("Hive", 1.5), ("RansomEXX", 1.5), ("REvil", 1.5), ("BlackMatter", 1.5),
        ("DarkSide", 1.5), ("Avaddon", 1.5), ("NetWalker", 1.5), ("Maze", 1.4),
        ("Egregor", 1.5), ("Ryuk", 1.5), ("Sodinokibi", 1.5), ("GandCrab", 1.5),
        ("Phobos", 1.4), ("Dharma", 1.4), ("Makop", 1.5), ("MedusaLocker", 1.5),
        ("Nefilim", 1.5), ("Ragnar Locker", 1.5), ("Clop", 1.5), ("DoppelPaymer", 1.5),
        ("Cuba ransomware", 1.5), ("Karakurt", 1.5), ("Black Basta", 1.5), ("Royal ransomware", 1.5),
        ("Trigona", 1.5), ("NoEscape", 1.5), ("Snatch", 1.4), ("Babuk", 1.5),
        ("Vice Society", 1.5), ("BianLian", 1.5), ("Akira ransomware", 1.5), ("Play ransomware", 1.5),
        ("ransomware attack", 1.5), ("ransomware group", 1.5),
        ("data encrypted", 1.0), ("files encrypted", 1.0),
        ("decrypt your files", 1.0), ("decryption key", 1.0), ("decryptor", 1.0),
        ("victim portal", 1.0), ("leak site", 1.0), ("shame site", 1.2),
        ("we have your data", 1.5), ("we stole your data", 1.5), ("publish your data", 1.2),
        ("double extortion", 1.0), ("if you don't pay", 1.0),
        ("ransom note", 0.8), ("ransom amount", 1.0), ("ransom deadline", 1.0),
        ("countdown timer", 0.8), ("affiliate program", 0.8), ("negotiation chat", 1.0),
        ("recovery key", 0.9), ("master key", 0.7), ("RaaS", 1.0),
        ("ransomware as a service", 1.0),
        ("ransom", 0.5), ("encrypted", 0.4), ("decrypt", 0.4),
        ("pay bitcoin", 0.6), ("payment in bitcoin", 0.8), ("payment in monero", 0.8),
    ],
    "malware_sale": [
        ("stealer", 0.8), ("credential stealer", 1.0), ("RedLine", 1.5), ("Vidar", 1.5),
        ("Raccoon stealer", 1.5), ("Mars stealer", 1.5), ("Azorult", 1.5), ("Formbook", 1.5),
        ("LokiBot", 1.5), ("Agent Tesla", 1.5), ("AsyncRAT", 1.5), ("Quasar RAT", 1.5),
        ("Remcos", 1.5), ("NanoCore", 1.5), ("Warzone RAT", 1.5), ("Orcus", 1.4),
        ("VenomRAT", 1.5), ("njRAT", 1.5), ("DarkComet", 1.5),
        ("RAT", 0.8), ("remote access trojan", 1.2),
        ("crypter", 0.8), ("FUD crypter", 1.3), ("cryptor", 0.9), ("loader", 0.8),
        ("runPE", 1.0), ("packer", 0.7), ("stub", 0.6),
        ("botnet", 1.0), ("keylogger", 0.8), ("spyware", 0.8), ("trojan", 0.8),
        ("infostealer", 1.0), ("info-stealer", 1.0),
        ("exploit kit", 1.0), ("obfuscator", 0.8), ("builder", 0.7),
        ("web inject", 1.0), ("form grabber", 1.0), ("C2 panel", 1.0),
        ("malware for sale", 1.5), ("buy RAT", 1.5), ("RAT price", 1.2),
        ("crypter for sale", 1.5), ("buy malware", 1.5), ("malware panel", 1.0),
        ("malware source", 1.2), ("botnet source", 1.2),
        ("bypass Windows Defender", 1.2), ("bypass AV", 1.2),
        ("loader service", 1.1), ("crypting service", 1.2), ("installs", 0.5),
        ("lifetime license", 0.6), ("private build", 0.7), ("custom build", 0.6),
        ("silent miner", 1.2), ("hidden miner", 1.2), ("clipper", 1.0),
        ("clipboard hijacker", 1.3), ("undetectable", 0.5), ("fud", 0.5),
    ],
    "credential_leak": [
        ("combolist", 1.5), ("combo list", 1.4), ("email:pass", 1.5), ("email:password", 1.5),
        ("log:pass", 1.5), ("leaked accounts", 1.5), ("account dump", 1.5),
        ("credential dump", 1.5), ("login:password", 1.5), ("database leak", 1.2),
        ("db leak", 1.2), ("SQL dump", 1.2), ("emails and passwords", 1.2),
        ("credential stuffing", 1.2), ("leaked database", 1.0), ("data breach email", 1.0),
        ("password list", 0.8), ("fresh combo", 1.2), ("private combo", 1.2),
        ("verified combo", 1.2), ("valid accounts", 1.0), ("checker", 0.7), ("checker logs", 1.2),
        ("redline logs", 1.3), ("stealer logs", 1.3), ("rdp logs", 1.2), ("vpn logs", 1.2),
        ("ftp logs", 1.1), ("urllogpass", 1.4), ("cracked accounts", 1.2), ("cracking", 0.7),
        ("hashes", 0.6), ("NTLM hash", 1.0), ("MD5 hash", 0.8), ("cPanel access", 1.1),
        ("SMTP combo", 1.2), ("bank logs", 1.3), ("track2", 1.2), ("fullz dump", 1.3),
        ("username list", 0.8), ("credentials for sale", 1.4), ("buy combo", 1.3),
        ("share combo", 1.1), ("pastebin dump", 1.0), ("mail access", 0.9), ("email access", 0.9),
        ("netflix accounts", 0.9), ("spotify accounts", 0.9), ("paypal accounts", 1.0),
    ],
    "access_broker": [
        ("initial access", 1.2), ("access broker", 1.5), ("IAB", 1.2),
        ("RDP access", 1.5), ("SSH access", 1.5), ("VPN access", 1.5), ("Citrix access", 1.5),
        ("Pulse Secure", 1.3), ("Fortinet VPN", 1.3), ("SonicWall", 1.2), ("web shell", 1.2),
        ("admin panel access", 1.5), ("remote desktop access", 1.5),
        ("compromised network", 1.2), ("network access for sale", 1.5), ("network access", 1.1),
        ("sell access", 1.5), ("buy access", 1.5), ("RDP shop", 1.4),
        ("dedicated access", 1.2), ("backdoor access", 1.2), ("persistent access", 1.1),
        ("reverse shell", 1.1), ("beacon", 0.7), ("Cobalt Strike", 1.2), ("Metasploit session", 1.2),
        ("initial foothold", 1.3), ("foothold for sale", 1.5), ("lateral movement", 0.8),
        ("domain admin", 1.2), ("domain admin access", 1.5), ("DA access", 1.3), ("EA access", 1.2),
        ("domain controller", 0.8), ("Active Directory access", 1.2), ("SMB access", 1.0),
        ("WinRM", 0.8), ("PsExec", 0.8), ("shell access", 1.0), ("root access", 1.0),
        ("local admin", 0.9), ("enterprise admin", 1.1), ("privilege escalation", 0.6),
        ("corporate access", 1.2), ("access to company", 1.3), ("company revenue", 0.5),
        ("target organization", 0.8),
        ("RDP", 0.5), ("SSH", 0.5), ("VPN", 0.5), ("shell", 0.3),
    ],
    "data_leak": [
        ("data breach", 1.2), ("leaked database", 1.5), ("sensitive documents", 1.5),
        ("internal files", 1.5), ("confidential data", 1.5), ("source code leak", 1.5),
        ("customer data leaked", 1.5), ("stolen data", 1.2), ("data dump", 1.2),
        ("private key leaked", 1.5), ("database downloaded", 1.5), ("db leaked", 1.2),
        ("exposed credentials", 1.2), ("document leak", 1.0), ("PII leak", 1.3),
        ("SSN leak", 1.3), ("credit card leak", 1.3), ("passport scan", 1.1), ("ID scan", 0.9),
        ("bank statement leak", 1.2), ("medical records leak", 1.4), ("intellectual property", 0.8),
        ("trade secrets", 1.0), ("code repository leak", 1.3), ("GitLab leak", 1.3),
        ("internal docs", 1.1), ("classified document", 1.0), ("company secrets", 1.2),
        ("breach disclosure", 1.1), ("hacked data", 1.2), ("stolen data for sale", 1.4),
        ("full database for sale", 1.4), ("mega.nz leak", 1.1), ("customer list", 0.8),
        ("employee list", 0.8), ("financial report leak", 1.2), ("internal memo", 0.9),
        ("strategy document", 0.8), ("leaked source", 1.2), ("leaked archive", 1.0),
        ("dump for sale", 1.2), ("breached", 0.7), ("exfiltrated data", 1.2),
        ("exposed bucket", 1.2), ("open S3 bucket", 1.3),
    ],
    "drug_trafficking": [
        ("cocaine", 1.0), ("crack cocaine", 1.2), ("heroin", 1.0), ("black tar heroin", 1.3),
        ("methamphetamine", 1.0), ("meth", 1.0), ("crystal meth", 1.2), ("MDMA", 1.0),
        ("ecstasy", 1.0), ("molly", 0.9), ("LSD", 1.0), ("acid tabs", 1.0), ("blotter", 0.8),
        ("microdot", 0.9), ("cannabis", 0.8), ("weed", 0.8), ("marijuana", 0.8), ("hashish", 0.8),
        ("opium", 1.0), ("fentanyl", 1.0), ("carfentanil", 1.2), ("prescription", 0.5),
        ("oxycodone", 1.0), ("oxycontin", 1.0), ("percocet", 1.0), ("xanax", 0.8),
        ("alprazolam", 1.0), ("adderall", 0.8), ("valium", 0.9), ("ketamine", 1.0),
        ("special k", 0.7), ("shrooms", 0.8), ("psilocybin", 1.0), ("magic mushrooms", 1.0),
        ("mescaline", 1.0), ("psychedelic", 0.7), ("2C-B", 1.0), ("DMT", 1.0), ("GHB", 1.0),
        ("rohypnol", 1.1), ("steroids", 0.7), ("anabolic steroids", 1.0), ("HGH", 0.7),
        ("tramadol", 0.9), ("codeine", 0.8), ("lean", 0.4), ("purple drank", 1.0),
        ("research chemical", 0.9), ("designer drug", 1.0), ("synthetic cannabinoid", 1.1),
        ("spice", 0.4), ("K2", 0.5), ("bath salts", 1.0), ("legal high", 0.8),
        ("narcotics", 1.0), ("controlled substance", 1.0), ("illegal drugs", 1.2),
        ("buy drugs online", 1.5), ("drug marketplace", 1.5), ("drug vendor", 1.3),
        ("vendor", 0.5), ("escrow", 0.6), ("shipment", 0.5), ("vacuum sealed", 1.0),
        ("stealth shipping", 1.5), ("discreet shipping", 1.5), ("worldwide shipping", 0.8),
        ("finalize early", 1.2), ("grams", 0.5), ("ounces", 0.5), ("quarter ounce", 0.9),
        ("half ounce", 0.9), ("eighth", 0.5), ("gram price", 0.8), ("kilo", 0.5),
        ("pill press", 1.2), ("reagent test", 0.9), ("vape cart", 0.8), ("wax", 0.4),
        ("shatter", 0.7), ("dabs", 0.7), ("THC", 0.7), ("edibles", 0.6), ("pre-rolls", 0.8),
        ("cartel", 0.9), ("Sinaloa", 1.1), ("plug", 0.3), ("re-up", 0.6), ("key of coke", 1.2),
        ("order", 0.3), ("price", 0.2),
        ("buy cocaine", 1.5), ("weed for sale", 1.5), ("drugs for sale", 1.5),
    ],
    "weapons_trafficking": [
        ("firearm", 1.0), ("gun", 0.7), ("rifle", 1.0), ("pistol", 1.0), ("shotgun", 1.0),
        ("handgun", 1.0), ("submachine gun", 1.3), ("machine gun", 1.2), ("assault rifle", 1.3),
        ("AK-47", 1.5), ("AKM", 1.4), ("AK-74", 1.4), ("AR-15", 1.5), ("M16", 1.3), ("M4 carbine", 1.3),
        ("Glock", 1.4), ("Glock 17", 1.5), ("Glock 19", 1.5), ("Beretta", 1.3), ("Beretta 92", 1.4),
        ("Sig Sauer", 1.4), ("Sig P320", 1.4), ("Smith & Wesson", 1.3), ("Ruger", 1.2),
        ("Remington 870", 1.4), ("Mossberg 500", 1.4), ("CZ 75", 1.4), ("HK USP", 1.4),
        ("FN Five-seveN", 1.5), ("Desert Eagle", 1.4),
        ("ammunition", 1.2), ("ammo", 1.0), ("cartridge", 0.7), ("bullet", 0.7),
        ("hollow point", 1.1), ("full metal jacket", 1.0), ("tracer round", 1.1),
        ("armor-piercing", 1.5), ("9mm", 0.8), (".223", 0.9), ("5.56", 0.8), (".308", 0.8),
        ("7.62x39", 1.0), (".45 ACP", 0.9), (".50 BMG", 1.2),
        ("explosive", 1.5), ("C4", 1.5), ("grenade", 1.5), ("detonator", 1.4), ("blasting cap", 1.4),
        ("suppressor", 1.0), ("silencer", 1.0), ("bump stock", 1.3), ("binary trigger", 1.3),
        ("full auto", 1.2), ("auto sear", 1.4), ("select fire", 1.3), ("conversion kit", 1.1),
        ("drop-in auto sear", 1.5), ("ghost gun", 1.4), ("80% lower", 1.4), ("3D printed gun", 1.4),
        ("FGC-9", 1.5), ("Liberator pistol", 1.4), ("untraceable firearm", 1.5), ("high capacity magazine", 1.1),
        ("no background check", 1.2), ("no paper trail", 1.0), ("straw purchase", 1.3),
        ("buy guns", 1.5), ("buy guns online", 1.5), ("firearms for sale", 1.5), ("gun for sale", 1.4),
        ("ammo in stock", 1.5), ("order pistol", 1.5), ("gun dealer", 1.2), ("arms dealer", 1.4),
        ("weapon for sale", 1.5), ("illegal firearm", 1.4), ("weapon shipment", 1.2),
    ],
    "terrorism_extremism": [
        ("ISIS", 1.5), ("ISIL", 1.5), ("Daesh", 1.5), ("Al-Qaeda", 1.5), ("AQAP", 1.5),
        ("AQIM", 1.5), ("Al-Shabaab", 1.5), ("Boko Haram", 1.5), ("Taliban", 1.3),
        ("Hezbollah", 1.4), ("Hamas", 1.3), ("PKK", 1.3), ("Atomwaffen", 1.6), ("The Base", 1.2),
        ("Feuerkrieg", 1.6), ("accelerationism", 1.3), ("neo-nazi", 1.5), ("white supremacy", 1.2),
        ("white power", 1.2), ("14 words", 1.3), ("Siege culture", 1.4),
        ("jihad", 1.0), ("jihadi", 1.2), ("mujahideen", 1.5), ("martyrdom", 1.2), ("martyr", 0.9),
        ("istishhad", 1.4), ("infidel", 1.0), ("kuffar", 1.2), ("apostate", 0.9), ("takfir", 1.2),
        ("caliphate", 1.5), ("khilafah", 1.5), ("pledge allegiance", 1.2), ("bay'ah", 1.3),
        ("attack planning", 2.0), ("attack plan", 1.6), ("attack timeline", 1.5), ("lone wolf", 1.5),
        ("bomb-making instructions", 2.0), ("bomb making", 1.8), ("pipe bomb", 1.6),
        ("pressure cooker bomb", 1.8), ("IED", 1.3), ("TATP", 1.6), ("ANFO", 1.5),
        ("fertilizer bomb", 1.6), ("vehicle ramming", 1.5), ("knife attack", 1.2),
        ("mass casualty", 1.5), ("suicide vest", 1.7), ("suicide bombing", 1.7),
        ("kill kuffar", 2.0), ("kill in the name of", 2.0), ("incite violence", 1.2),
        ("holy war", 1.0), ("beheading", 1.5), ("beheading video", 1.6), ("execution video", 1.5),
        ("propaganda", 0.9), ("propaganda video", 1.3), ("nasheed", 1.2), ("manifesto", 1.2),
        ("Inspire magazine", 1.6), ("Dabiq", 1.5), ("Rumiyah", 1.5), ("training camp", 1.2),
        ("material support", 1.2), ("foreign fighters", 1.3), ("terror financing", 1.4),
        ("recruitment for jihad", 1.5), ("recruit for jihad", 1.5), ("radicalization", 1.1),
        ("terrorist", 1.0), ("extremist", 0.8), ("terrorism", 1.0), ("bioterrorism", 1.5),
        ("prepare for attack", 2.0), ("target list", 1.4), ("hit list", 1.3),
    ],
    "human_trafficking": [
        ("human trafficking", 2.0), ("sex trafficking", 2.0), ("trafficking in persons", 2.0),
        ("child trafficking", 2.0), ("forced labour", 1.5), ("forced labor", 1.5),
        ("sexual exploitation", 1.5), ("trafficking victims", 1.5), ("trafficking victim", 1.5),
        ("modern slavery", 1.5), ("sold into slavery", 1.6), ("prostitution ring", 1.0),
        ("escort service", 0.7), ("sex slave", 2.0), ("forced prostitution", 2.0),
        ("trafficker", 1.2), ("pimp", 0.9), ("brothel", 0.9), ("sexual servitude", 1.6),
        ("domestic servitude", 1.5), ("debt bondage", 1.5), ("bride trafficking", 1.7),
        ("organ trafficking", 1.7), ("illegal adoption", 1.3), ("migrant smuggling", 1.4),
        ("coyote smuggler", 1.3), ("snakehead", 1.2), ("passport confiscation", 1.3),
        ("victim recruitment", 1.2), ("harboring", 0.7), ("safe house", 0.7), ("stash house", 0.9),
        ("forced marriage", 1.4), ("mail-order bride", 1.2), ("human cargo", 1.4),
        ("labor exploitation", 1.2), ("exploitation ring", 1.3), ("trafficking network", 1.5),
        ("trafficking syndicate", 1.5), ("online enticement", 1.0), ("sextortion", 0.9),
        ("webcam exploitation", 1.3), ("cybersex trafficking", 1.6), ("live-streamed abuse", 1.4),
    ],
    "scam": [
        ("phishing", 1.0), ("scam", 0.8), ("fraud", 0.8), ("con artist", 1.0),
        ("vishing", 1.2), ("smishing", 1.2), ("advance fee fraud", 1.4), ("419 scam", 1.4),
        ("lottery scam", 1.4), ("inheritance scam", 1.4), ("romance scam", 1.4), ("catfish", 0.8),
        ("dating scam", 1.2), ("crypto scam", 1.2), ("giveaway scam", 1.3), ("fake giveaway", 1.3),
        ("airdrop scam", 1.3), ("fake exchange", 1.3), ("wallet drainer", 1.4),
        ("seed phrase phishing", 1.5), ("tech support scam", 1.4), ("IRS scam", 1.3),
        ("refund scam", 1.2), ("refund method", 1.2), ("carding", 1.5), ("CVV", 1.2),
        ("dumps", 1.0), ("fullz", 1.3), ("bank login", 1.2), ("PayPal log", 1.2),
        ("PayPal scam", 1.2), ("Zelle scam", 1.2), ("cash app flip", 1.3), ("cashout", 0.9),
        ("money transfer", 0.7), ("Western Union", 0.9), ("fake ID", 1.2), ("counterfeit", 1.0),
        ("stolen credit card", 1.5), ("credit card fraud", 1.4), ("account takeover", 1.0),
        ("check fraud", 1.2), ("fake check", 1.2), ("overpayment scam", 1.3), ("BEC", 1.2),
        ("business email compromise", 1.4), ("CEO fraud", 1.3), ("invoice fraud", 1.2),
        ("gift card scam", 1.3), ("apple gift card", 1.0), ("google play card", 1.0),
        ("steam card", 0.9), ("mystery shopper scam", 1.3), ("work from home scam", 1.2),
        ("chargeback fraud", 1.2), ("triangulation fraud", 1.3), ("drop shipping scam", 1.2),
        ("return fraud", 1.2), ("reshipper", 1.1), ("social engineering", 0.8),
        ("spoofed email", 1.0), ("impersonation scam", 1.2), ("social security number", 1.0),
        ("SSN", 0.9), ("spam", 0.4), ("Nigerian prince", 1.5),
    ],
    # ── New categories (THREAT_LEXICON.md) ──
    "counterfeit_documents": [
        ("fake passport", 1.5), ("fake driver license", 1.5), ("fake ID card", 1.5),
        ("fake national ID", 1.5), ("fake SSN card", 1.5), ("fake green card", 1.5),
        ("counterfeit document", 1.5), ("counterfeit currency", 1.5), ("counterfeit money", 1.5),
        ("blank passport", 1.5), ("blank ID", 1.3), ("buy fake documents", 1.5),
        ("superdollar", 1.5), ("fake birth certificate", 1.5), ("fake diploma", 1.3),
        ("fake degree", 1.3), ("fake ID", 1.0), ("fake visa", 1.2), ("fake certificate", 1.0),
        ("fake utility bill", 1.2), ("fake bank statement", 1.2), ("fake pay stub", 1.2),
        ("fake tax return", 1.2), ("fake insurance card", 1.0), ("fake vehicle title", 1.2),
        ("novelty document", 1.0), ("replica document", 1.0), ("scannable ID", 1.2),
        ("document forger", 1.3), ("fake euros", 1.2), ("fake dollars", 1.2),
        ("fake banknotes", 1.3), ("full document set", 1.0),
        ("hologram", 0.4), ("MRZ", 0.5), ("biometric passport", 0.6), ("1:1 replica", 0.5),
    ],
    "financial_fraud": [
        ("investment fraud", 1.5), ("securities fraud", 1.5), ("insider trading", 1.5),
        ("market manipulation", 1.5), ("pump and dump", 1.3), ("prime bank fraud", 1.5),
        ("wire fraud", 1.3), ("mortgage fraud", 1.5), ("PPP fraud", 1.5), ("tax evasion", 1.3),
        ("boiler room", 1.5), ("high-yield investment program", 1.5),
        ("ponzi", 1.2), ("crypto ponzi", 1.4), ("pyramid scheme", 1.2), ("HYIP", 1.3),
        ("binary options", 1.0), ("forex scam", 1.2), ("investment scam", 1.2),
        ("spoofing", 0.9), ("embezzlement", 1.2), ("accounting fraud", 1.2),
        ("cooking the books", 1.2), ("ACH fraud", 1.2), ("wire transfer fraud", 1.2),
        ("check kiting", 1.2), ("loan fraud", 1.2), ("COVID relief fraud", 1.3),
        ("tax fraud", 1.2), ("offshore account", 1.0), ("shell company", 1.0),
        ("false invoicing", 1.2), ("front running", 1.2), ("sanctions evasion", 1.2),
        ("OFAC evasion", 1.3), ("asset misappropriation", 1.2), ("falsified statements", 1.0),
        ("investment scheme", 1.0), ("stock manipulation", 1.2), ("payment diversion", 1.0),
        ("insider tip", 0.8),
        ("guaranteed returns", 0.5), ("risk-free profit", 0.6), ("double your money", 0.5),
    ],
    "identity_theft": [
        ("fullz", 1.5), ("SSN DOB", 1.5), ("synthetic identity", 1.5), ("CPN", 1.3),
        ("credit privacy number", 1.5), ("identity package", 1.5), ("identity profile", 1.3),
        ("new identity", 1.2), ("second identity", 1.3), ("identity theft", 1.5),
        ("stolen identity", 1.5), ("fullz shop", 1.6),
        ("full info", 0.9), ("credit report", 1.0), ("credit profile", 1.0),
        ("EIN for sale", 1.3), ("fake identity", 1.2), ("leaked SSN", 1.2), ("leaked DOB", 1.2),
        ("mother maiden name", 1.0), ("driver license number", 1.0), ("passport number", 1.0),
        ("background check data", 1.0), ("KYC bypass", 1.3), ("eKYC bypass", 1.3),
        ("verification bypass", 1.0), ("selfie with ID", 1.2), ("identity fraud", 1.3),
        ("account takeover", 1.0), ("PII package", 1.3), ("personal data for sale", 1.2),
        ("full identity", 1.2), ("SSN lookup", 1.0), ("credit sweep", 1.0),
        ("Equifax", 0.5), ("Experian", 0.5), ("TransUnion", 0.5), ("dox", 0.6), ("doxx", 0.6),
    ],
    "exploit_trading": [
        ("zero-day", 1.7), ("0day", 1.7), ("remote code execution", 1.4),
        ("weaponized exploit", 1.7), ("exploit kit", 1.4), ("exploit for sale", 1.7),
        ("buy exploit", 1.6), ("sell exploit", 1.6), ("vulnerability broker", 1.7),
        ("zero-day broker", 1.7), ("pre-auth RCE", 1.7), ("unauthenticated RCE", 1.6),
        ("full chain", 1.4), ("sandbox escape", 1.5), ("private exploit", 1.5),
        ("exploit", 0.9), ("RCE", 1.0), ("LPE", 1.0), ("local privilege escalation", 1.0),
        ("elevation of privilege", 1.0), ("exploit code", 1.2), ("proof of concept", 0.9),
        ("exploit pack", 1.2), ("vulnerability market", 1.3), ("browser exploit", 1.2),
        ("kernel exploit", 1.2), ("SQLi exploit", 1.0), ("auth bypass exploit", 1.0),
        ("buffer overflow", 0.9), ("heap spray", 1.0), ("ROP chain", 1.0), ("ASLR bypass", 1.0),
        ("DEP bypass", 1.0), ("shellcode", 0.8), ("post-exploitation", 0.9), ("1day", 1.0),
        ("n-day", 1.0), ("CVE for sale", 1.5), ("fresh exploit", 1.3),
        ("undisclosed vulnerability", 1.3), ("wormable", 1.2), ("jailbreak exploit", 1.2),
        ("root exploit", 1.2), ("payload", 0.4),
    ],
    "phishing_kits": [
        ("phishing kit", 1.5), ("phishkit", 1.6), ("scam page", 1.5), ("fake login page", 1.5),
        ("phishing template", 1.5), ("phishing panel", 1.5), ("phishing as a service", 1.6),
        ("PhaaS", 1.6), ("buy phishing kit", 1.6), ("sell phishing kit", 1.6),
        ("2FA bypass kit", 1.5), ("OTP bot", 1.5), ("OTP grabber", 1.5),
        ("scam page builder", 1.5), ("web inject kit", 1.4),
        ("fake bank login", 1.2), ("office 365 phishing", 1.2), ("microsoft phishing", 1.2),
        ("google phishing", 1.2), ("paypal phishing", 1.2), ("apple phishing", 1.2),
        ("coinbase phishing", 1.2), ("landing page kit", 1.0), ("antibot", 1.0),
        ("anti-bot", 1.0), ("antidetect", 1.0), ("cloaking", 0.9), ("IP cloaking", 1.0),
        ("redirect blocker", 1.0), ("geo filter", 0.8), ("bot filter", 0.8), ("SMS OTP bot", 1.2),
        ("credential capture", 1.0), ("login capture", 1.0), ("phishing service", 1.3),
        ("scam letter", 1.0), ("telegram logger", 1.0), ("email logger", 1.0),
        ("victim panel", 1.0), ("clone site", 1.0), ("brand impersonation", 1.0),
        ("fake checkout", 1.1), ("fake payment page", 1.2),
        ("results panel", 0.5), ("mirror site", 0.5),
    ],
    "malware_botnet_rental": [
        ("botnet rental", 1.6), ("DDoS for hire", 1.6), ("stresser", 1.4), ("booter", 1.4),
        ("booter service", 1.5), ("IP stresser", 1.5), ("botnet panel", 1.4),
        ("bot rental", 1.4), ("pay per install", 1.4), ("bulletproof hosting", 1.5),
        ("bulletproof server", 1.5),
        ("botnet", 1.0), ("DDoS attack", 1.0), ("layer 7 attack", 1.0), ("layer 4 attack", 1.0),
        ("amplification attack", 1.0), ("reflection attack", 1.0), ("UDP flood", 1.0),
        ("SYN flood", 1.0), ("HTTP flood", 1.0), ("slowloris", 1.0), ("CC attack", 0.9),
        ("take down site", 1.0), ("knock offline", 1.0), ("bypass Cloudflare", 1.0),
        ("bypass DDoS protection", 1.1), ("C2 infrastructure", 1.0), ("command and control", 0.9),
        ("zombie hosts", 1.1), ("infected hosts", 1.0), ("IoT botnet", 1.2), ("Mirai", 1.2),
        ("Qbot", 1.2), ("Gafgyt", 1.2), ("Meris", 1.2), ("infected router", 1.0),
        ("infected camera", 1.0), ("install service", 1.0), ("PPI", 0.9), ("traffic seller", 1.0),
        ("residential proxy", 1.0), ("mobile proxy", 1.0), ("SOCKS5 proxy", 0.9),
        ("proxy seller", 1.0), ("backconnect proxy", 1.0), ("offshore hosting", 1.1),
        ("DMCA ignored", 1.2), ("abuse ignored", 1.2), ("fast flux", 1.1), ("domain fronting", 1.0),
        ("Gbps", 0.5), ("Tbps", 0.6),
    ],
    "money_laundering": [
        ("money laundering", 1.6), ("launder money", 1.6), ("clean your coins", 1.6),
        ("trade-based money laundering", 1.6), ("bitcoin mixer", 1.5), ("BTC mixer", 1.5),
        ("coin mixer", 1.5), ("cryptocurrency mixing", 1.5), ("Tornado Cash", 1.5),
        ("ChipMixer", 1.6), ("money mule", 1.5), ("mule recruitment", 1.5),
        ("cashout service", 1.4), ("underground bank", 1.5), ("black market peso exchange", 1.6),
        ("crypto laundering", 1.6), ("washed coins", 1.5), ("clean funds", 1.2),
        ("dirty money", 1.0), ("structuring", 0.9), ("smurfing", 1.0), ("shell bank", 1.2),
        ("offshore banking", 1.0), ("tax haven", 0.9), ("nominee director", 1.1),
        ("bearer shares", 1.1), ("front company", 1.1), ("over-invoicing", 1.1),
        ("under-invoicing", 1.1), ("hawala", 1.2), ("hundi", 1.2), ("tumbler", 1.2),
        ("Wasabi wallet", 1.2), ("Monero swap", 1.2), ("chain hopping", 1.2), ("peel chain", 1.2),
        ("cross-chain swap", 1.0), ("drop account", 1.1), ("bank drop", 1.2),
        ("bank logs cashout", 1.3), ("ATM cashout", 1.2), ("dumps cashout", 1.3),
        ("prepaid card cashout", 1.2), ("gift card cashout", 1.2), ("crypto debit card", 1.0),
        ("no-KYC exchange", 1.2), ("exchanger office", 1.0), ("digital currency exchanger", 1.1),
        ("unlicensed MSB", 1.2), ("flying money", 1.2), ("cash courier", 1.1),
        ("bulk cash smuggling", 1.3), ("privacy coin", 0.5), ("p2p exchange", 0.5),
    ],
    "insider_threat": [
        ("insider threat", 1.5), ("insider access", 1.5), ("recruit insider", 1.6),
        ("rogue admin", 1.5), ("rogue employee", 1.5), ("internal access for sale", 1.6),
        ("sell company access", 1.6), ("looking for insider", 1.6), ("insider wanted", 1.6),
        ("paid insider", 1.6), ("bribe employee", 1.5), ("corporate mole", 1.5),
        ("planted backdoor", 1.4),
        ("insider", 0.6), ("employee access", 1.1), ("corporate insider", 1.3),
        ("disgruntled employee", 1.2), ("privileged user abuse", 1.2), ("sysadmin access", 1.0),
        ("database admin access", 1.1), ("executive access", 1.1), ("data exfiltration", 1.0),
        ("exfiltrate data", 1.0), ("USB exfiltration", 1.2), ("cloud upload leak", 1.0),
        ("sabotage", 0.9), ("logic bomb", 1.2), ("time bomb", 1.0), ("backdoor account", 1.1),
        ("internal network access", 1.1), ("source code theft", 1.3), ("R&D theft", 1.3),
        ("merger leak", 1.1), ("earnings leak", 1.1), ("insider trading tip", 1.2),
        ("customer database access", 1.1), ("sensitive internal documents", 1.0),
        ("employee bribe", 1.3), ("mole", 0.6),
        ("payroll data", 0.5), ("HR data", 0.5), ("jump host", 0.4),
    ],
    "cyber_espionage": [
        ("cyber espionage", 1.6), ("state-sponsored", 1.4), ("nation-state actor", 1.6),
        ("advanced persistent threat", 1.4), ("APT28", 1.6), ("APT29", 1.6), ("APT41", 1.6),
        ("Lazarus Group", 1.6), ("Kimsuky", 1.6), ("Turla", 1.5), ("Fancy Bear", 1.6),
        ("Cozy Bear", 1.6), ("Equation Group", 1.6), ("Shadow Brokers", 1.5),
        ("industrial espionage", 1.6), ("commercial espionage", 1.5), ("espionage for hire", 1.6),
        ("trade secret theft", 1.5), ("cyber warfare", 1.4), ("supply chain attack", 1.3),
        ("exfiltrate classified", 1.6),
        ("APT", 0.7), ("intelligence agency leak", 1.2), ("NSA tools", 1.2), ("CIA tools", 1.2),
        ("information operations", 1.0), ("influence operations", 1.0),
        ("disinformation campaign", 1.0), ("hack and leak", 1.1), ("watering hole attack", 1.2),
        ("spear phishing campaign", 1.1), ("targeted intrusion", 1.1), ("classified document", 1.0),
        ("top secret", 0.9), ("diplomatic cable", 1.1), ("defense contractor", 1.0),
        ("critical infrastructure", 1.0), ("SCADA", 1.0), ("power grid attack", 1.3),
        ("military secrets", 1.2), ("weapons design", 1.2), ("missile technology", 1.2),
        ("nuclear technology", 1.2), ("dual-use technology", 1.1), ("ITAR violation", 1.2),
        ("reverse engineer blueprints", 1.2), ("recruited asset", 1.1),
        ("ICS", 0.4), ("HUMINT", 0.5), ("SIGINT", 0.5), ("export controlled", 0.5),
        ("compartmented", 0.5), ("NOFORN", 0.6),
    ],
    # Detection-only (route to quarantine, never retained — TG-G4 / IR-001). See
    # QUARANTINE_CATEGORIES in security.py and the gate in db_writer.process_classification.
    "child_exploitation": [
        ("child sexual abuse material", 2.0), ("child sexual abuse imagery", 2.0),
        ("child exploitation material", 2.0), ("child abuse imagery", 2.0),
        ("child pornography", 2.0), ("indecent images of children", 2.0),
        ("self-generated CSAM", 2.0), ("sextortion of a minor", 2.0), ("child grooming", 1.8),
        ("online enticement of a minor", 2.0), ("child sex tourism", 2.0),
        ("CSAM collection", 2.0), ("CSAM forum", 2.0), ("produce CSAM", 2.0),
        ("distribute CSAM", 2.0),
        ("CSAM", 1.4), ("child exploitation", 1.4), ("grooming a minor", 1.6),
        ("minor-attracted", 1.2), ("hurtcore", 1.6), ("child model nude", 1.8),
        ("abuse video of child", 2.0),
        ("jailbait", 0.9), ("lolita content", 1.0), ("pthc", 1.4), ("cheese pizza", 0.8),
        ("hard candy", 0.8), ("cp link", 1.2),
    ],
}

# Word-boundary-aware compile (also respects string start/end and punctuation).
_BOUNDARY_START = r"(?<!\w)"
_BOUNDARY_END = r"(?!\w)"


def _compile_phrase(phrase: str) -> "re.Pattern[str]":
    return re.compile(_BOUNDARY_START + re.escape(phrase) + _BOUNDARY_END, re.IGNORECASE)


# ----------------------------------------------------------------------
# 1b. EXTRA PHRASES — second-wave expansion (web-researched current named
# entities + curated slang, ~1k phrases). Merged into CATEGORY_PHRASES below with
# case-insensitive dedup. Ambiguous single-word slang is deliberately weighted very
# low (0.2-0.5) so it only contributes alongside other in-category signals and never
# classifies a benign page on its own. child_exploitation is intentionally excluded.
# ----------------------------------------------------------------------
EXTRA_PHRASES: Dict[str, List[Tuple[str, float]]] = {
    "ransomware": [
        ("Qilin", 1.5), ("Agenda ransomware", 1.5), ("RansomHub", 1.6), ("Cyclops", 1.2),
        ("Knight ransomware", 1.4), ("Medusa ransomware", 1.5), ("Cl0p", 1.5), ("BlackSuit", 1.5),
        ("Rhysida", 1.5), ("INC Ransom", 1.5), ("8Base", 1.4), ("Cactus ransomware", 1.5),
        ("Hunters International", 1.5), ("BlackByte", 1.5), ("Mallox", 1.5), ("3AM ransomware", 1.4),
        ("Money Message", 1.4), ("Lynx ransomware", 1.4), ("Embargo", 1.2), ("Helldown", 1.4),
        ("Interlock ransomware", 1.4), ("Fog ransomware", 1.3), ("Termite", 1.2), ("DragonForce", 1.5),
        ("RA World", 1.3), ("Brain Cipher", 1.4), ("encryptor", 0.9), ("data leak portal", 1.2),
        ("name and shame", 1.2), ("triple extortion", 1.4), ("crypto-locker", 1.2), ("file locker", 1.0),
        ("ransomware affiliate", 1.3), ("ransom demand", 1.2), ("dedicated leak site", 1.4),
        ("victim shaming", 1.2), ("wiper malware", 1.2), ("WannaCry", 1.4), ("NotPetya", 1.4),
        ("Cerber", 1.3), ("CryptoLocker", 1.4), ("SamSam", 1.4), ("MegaCortex", 1.4), ("Zeppelin", 1.3),
        ("Quantum ransomware", 1.3), ("your network has been encrypted", 1.5), ("readme ransom", 1.1),
        ("how to decrypt", 1.0), ("tox id ransom", 1.2), ("data auction", 1.3), ("auction stolen data", 1.3),
        ("affiliate recruitment ransomware", 1.4), ("ransom negotiation", 1.1), ("ransomware blog", 1.0),
    ],
    "malware_sale": [
        ("Lumma", 1.5), ("LummaC2", 1.6), ("Lumma Stealer", 1.6), ("StealC", 1.5), ("ACRStealer", 1.5),
        ("Rhadamanthys", 1.5), ("Atomic Stealer", 1.5), ("AMOS stealer", 1.5), ("Aurora Stealer", 1.4),
        ("Mystic Stealer", 1.4), ("Titan Stealer", 1.4), ("WhiteSnake", 1.3), ("Phemedrone", 1.3),
        ("Nova stealer", 1.2), ("SmokeLoader", 1.5), ("PrivateLoader", 1.5), ("GuLoader", 1.4),
        ("DanaBot", 1.5), ("BumbleBee", 1.4), ("IcedID", 1.5), ("Emotet", 1.5), ("TrickBot", 1.5),
        ("QakBot", 1.5), ("Pikabot", 1.4), ("Latrodectus", 1.4), ("Amadey", 1.4), ("Glupteba", 1.3),
        ("XWorm", 1.5), ("DCRat", 1.4), ("PlugX", 1.4), ("Gh0st RAT", 1.4), ("Sliver C2", 1.4),
        ("Brute Ratel", 1.4), ("Havoc C2", 1.3), ("cryptojacking", 1.2), ("XMRig", 0.9), ("coin miner", 1.0),
        ("crypto miner", 1.0), ("malware as a service", 1.4), ("ransomware builder", 1.5), ("maldoc", 1.1),
        ("dropper", 0.8), ("downloader malware", 1.0), ("rootkit", 1.1), ("bootkit", 1.2),
        ("HVNC", 1.3), ("hidden VNC", 1.3), ("banking trojan", 1.4), ("banker trojan", 1.4),
        ("Cerberus", 1.1), ("Anubis", 0.9), ("Octo malware", 1.3), ("crypto clipper", 1.3),
        ("seed stealer", 1.4), ("wallet stealer", 1.4), ("Discord token grabber", 1.3),
        ("browser cookie stealer", 1.3), ("password grabber", 1.2), ("scantime fud", 1.2),
        ("runtime fud", 1.2), ("polymorphic malware", 1.2), ("dropper builder", 1.2),
        ("loader builder", 1.2), ("ransomware kit", 1.4), ("stealer panel", 1.3), ("traffers", 1.3),
        ("traffer team", 1.3), ("malware crypting", 1.2), ("crypter service", 1.3),
    ],
    "credential_leak": [
        ("ulp file", 1.2), ("url login password", 1.3), ("logs marketplace", 1.3), ("cloud of logs", 1.3),
        ("stealer log shop", 1.4), ("Russian Market", 1.4), ("Genesis Market", 1.4), ("breach compilation", 1.3),
        ("RockYou2024", 1.3), ("collection #1", 1.3), ("plaintext passwords", 1.1), ("hashcat", 0.7),
        ("john the ripper", 0.8), ("antipublic", 1.2), ("BreachForums", 1.4), ("leakbase", 1.2),
        ("dehashed", 1.0), ("session cookies", 1.0), ("cookie logs", 1.2), ("token theft", 1.0),
        ("stealer cloud", 1.3), ("fresh logs daily", 1.2), ("private logs", 1.1), ("corporate logs", 1.3),
        ("kerberos tickets", 1.0), ("ntlm dump", 1.1), ("vpn config leak", 1.2),
    ],
    "access_broker": [
        ("AnyDesk access", 1.2), ("TeamViewer access", 1.2), ("ScreenConnect", 1.1), ("ESXi access", 1.3),
        ("vCenter access", 1.3), ("hypervisor access", 1.2), ("kerberoasting", 1.0), ("pass the hash", 1.1),
        ("golden ticket", 1.1), ("NTDS.dit", 1.2), ("LSASS dump", 1.1), ("Mimikatz", 1.1),
        ("credential harvesting", 1.0), ("exposed RDP", 1.2), ("RDWeb", 1.1), ("OWA access", 1.1),
        ("webmail access", 1.0), ("WHM access", 1.1), ("database access for sale", 1.4), ("MSSQL access", 1.1),
        ("SAP access", 1.2), ("SCADA access", 1.4), ("citrix netscaler", 1.2), ("globalprotect", 1.1),
        ("fortios", 1.1), ("Exchange server access", 1.2), ("okta access", 1.2), ("azure ad access", 1.3),
        ("o365 global admin", 1.4), ("aws root access", 1.4), ("gcp access", 1.2), ("kubernetes access", 1.2),
        ("jenkins access", 1.1), ("gitlab access", 1.1),
    ],
    "data_leak": [
        ("infostealer logs leak", 1.2), ("leaked API keys", 1.2), ("AWS keys leaked", 1.3),
        ("hardcoded credentials", 1.0), ("git secrets", 1.0), ("env file leak", 1.2), ("backup leak", 1.0),
        ("S3 bucket exposed", 1.3), ("elasticsearch exposed", 1.2), ("mongodb exposed", 1.2),
        ("unsecured database", 1.2), ("HR records leak", 1.2), ("payroll leak", 1.2), ("KYC documents leak", 1.4),
        ("driver license leak", 1.3), ("voter database", 1.1), ("telecom data leak", 1.2),
        ("healthcare data leak", 1.4), ("genetic data leak", 1.3), ("government data leak", 1.3),
        ("rdp config", 1.0),
    ],
    "drug_trafficking": [
        ("yayo", 1.0), ("yeyo", 1.0), ("nose candy", 0.9), ("8-ball", 0.9), ("eight ball", 0.9),
        ("coke", 0.6), ("white girl", 0.6), ("smack", 0.5), ("china white", 1.1), ("brown sugar", 0.5),
        ("skag", 0.9), ("chiva", 0.9), ("tar heroin", 1.1), ("ice meth", 1.1), ("glass meth", 1.0),
        ("crank", 0.5), ("ganja", 0.7), ("reefer", 0.7), ("sticky icky", 0.9), ("og kush", 1.0),
        ("girl scout cookies", 0.8), ("gelato strain", 0.9), ("moonrock", 0.9), ("fent", 1.0), ("fenty", 0.9),
        ("china girl", 1.0), ("nitazene", 1.2), ("isotonitazene", 1.3), ("xylazine", 1.2), ("tranq dope", 1.3),
        ("zannies", 1.0), ("M30", 0.8), ("perc 30", 1.0), ("roxy", 0.7), ("roxies", 0.9),
        ("pressed pills", 1.0), ("counterfeit pills", 1.1), ("fake oxy", 1.1), ("mdma crystals", 1.0),
        ("pingers", 0.7), ("acid tab", 1.0), ("tabs of acid", 1.1), ("liquid lsd", 1.1), ("nbome", 1.0),
        ("2c-i", 1.0), ("2c-e", 1.0), ("changa", 0.9), ("kratom", 0.5), ("etizolam", 1.1),
        ("clonazolam", 1.2), ("flualprazolam", 1.2), ("methadone", 0.8), ("suboxone", 0.8), ("dilaudid", 1.0),
        ("hydromorphone", 1.0), ("opana", 1.0), ("hash oil", 0.9), ("THC vape", 0.8), ("drug plug", 1.1),
        ("trap house", 0.9), ("re rock", 0.9), ("fish scale coke", 1.1), ("peruvian flake", 1.1),
        ("colombian cocaine", 1.1), ("mexican brown", 1.0), ("covert shipping", 1.0), ("decoy packaging", 1.1),
        ("levamisole", 1.0), ("benzocaine cut", 1.0), ("marquis reagent", 1.0), ("speedball", 1.1),
        ("bulk discount drugs", 1.0), ("wholesale kilos", 1.2), ("stamp bag heroin", 1.2), ("glassine bag", 1.0),
        ("teener", 0.9), ("dime bag", 0.8), ("brick of coke", 1.1), ("pound of weed", 1.0), ("qp weed", 1.0),
        ("zip of weed", 0.9), ("dnm vendor", 1.1), ("dnm market", 1.2), ("uncut cocaine", 1.1),
        ("crack rocks", 1.1), ("number 4 heroin", 1.1), ("afghan heroin", 1.1), ("meth shards", 1.1),
        ("shake and bake", 1.0), ("weed plug", 1.0), ("zaza", 0.7), ("exotic weed", 0.7), ("thca flower", 0.9),
        ("snow", 0.2), ("blow", 0.2), ("charlie", 0.2), ("dope", 0.3), ("crystal", 0.3), ("tina", 0.3),
        ("bars", 0.3), ("blues", 0.3), ("plug connect", 0.9), ("covert vacuum seal", 1.0),
    ],
    "weapons_trafficking": [
        ("privately made firearm", 1.4), ("Polymer80", 1.4), ("p80 frame", 1.2), ("glock switch", 1.5),
        ("auto switch", 1.4), ("full auto switch", 1.5), ("lightning link", 1.4), ("forced reset trigger", 1.4),
        ("FRT-15", 1.4), ("machine gun conversion", 1.5), ("auto sear", 1.4), ("solvent trap", 1.2),
        ("threaded barrel", 1.0), ("drum magazine", 1.0), ("subsonic ammo", 1.0), ("smokeless powder", 1.0),
        ("Tannerite", 1.1), ("blasting caps", 1.3), ("dynamite", 1.3), ("RDX", 1.4), ("PETN", 1.4),
        ("plastic explosive", 1.4), ("ghost gun kit", 1.4), ("unserialized", 1.2), ("no serial number", 1.2),
        ("MP5", 1.3), ("Uzi", 1.3), ("Tec-9", 1.4), ("MAC-10", 1.4), ("Draco pistol", 1.3),
        ("RPG launcher", 1.5), ("grenade launcher", 1.5), ("auto key card", 1.4), ("swift link", 1.3),
        ("destructive device", 1.3), ("40mm grenade", 1.4), ("flashbang", 1.1), ("80 percent lower", 1.3),
        ("build kit firearm", 1.2), ("bulk ammo", 1.0), ("armor piercing rounds", 1.3), ("antitank", 1.3),
    ],
    "terrorism_extremism": [
        ("Islamic State", 1.4), ("ISIS-K", 1.5), ("Amaq", 1.4), ("al-Naba", 1.4),
        ("Hayat Tahrir al-Sham", 1.4), ("Jabhat al-Nusra", 1.4), ("Tehrik-i-Taliban", 1.4),
        ("Lashkar-e-Taiba", 1.5), ("Jaish-e-Mohammed", 1.5), ("Abu Sayyaf", 1.4), ("AQIS", 1.5),
        ("Kataib Hezbollah", 1.4), ("sovereign citizen", 1.0), ("boogaloo", 1.2), ("accelerationist", 1.3),
        ("Order of Nine Angles", 1.5), ("Terrorgram", 1.6), ("great replacement", 1.3),
        ("active shooter", 1.1), ("school shooting plan", 1.7), ("manifesto upload", 1.5),
        ("martyrdom operation", 1.7), ("VBIED", 1.6), ("car bomb", 1.5), ("dirty bomb", 1.6),
        ("chemical attack", 1.5), ("nerve agent", 1.4), ("anthrax attack", 1.5), ("ricin", 1.3),
        ("sarin", 1.4), ("incendiary device", 1.3), ("molotov", 1.0), ("recruitment propaganda", 1.3),
        ("foreign terrorist fighter", 1.4), ("attack manual", 1.5), ("how to make explosives", 1.7),
        ("anarchist cookbook", 1.4), ("target reconnaissance", 1.3), ("kill list", 1.4),
        ("glorification of terrorism", 1.3), ("violent extremism", 1.2), ("terror cell", 1.4),
        ("sleeper cell", 1.4), ("operational planning attack", 1.5),
    ],
    "human_trafficking": [
        ("commercial sexual exploitation", 1.6), ("survival sex", 1.0), ("trafficking ring", 1.5),
        ("forced begging", 1.3), ("forced criminality", 1.3), ("indentured servitude", 1.4),
        ("bonded labor", 1.4), ("smuggling network", 1.3), ("migrant exploitation", 1.3), ("sex tourism", 1.3),
        ("brothel network", 1.3), ("massage parlor trafficking", 1.4), ("organ harvesting", 1.6),
        ("kidney for sale", 1.5), ("baby selling", 1.6), ("forced sex work", 1.6), ("trafficked women", 1.5),
        ("trafficked minors", 1.7), ("recruited for trafficking", 1.4), ("held against will", 1.3),
        ("victims for sale", 1.6), ("people for sale", 1.4), ("slave auction", 1.7), ("bottom girl", 1.2),
    ],
    "scam": [
        ("pig butchering", 1.6), ("sha zhu pan", 1.5), ("CryptoRom", 1.4), ("romance baiting", 1.4),
        ("rug pull", 1.4), ("exit scam", 1.3), ("smishing campaign", 1.2), ("vishing call", 1.2),
        ("OTP bot scam", 1.3), ("bank drop service", 1.3), ("fraud bible", 1.5), ("scam method", 1.2),
        ("refund glitch", 1.2), ("FTID", 1.2), ("SE method", 1.0), ("crypto investment scam", 1.4),
        ("fake job scam", 1.2), ("task scam", 1.2), ("sextortion scam", 1.2), ("blackmail scam", 1.2),
        ("deepfake scam", 1.3), ("voice cloning scam", 1.4), ("quishing", 1.3), ("scareware", 1.2),
        ("invoice redirection", 1.2), ("mandate fraud", 1.2), ("authorized push payment", 1.3),
        ("money flip", 1.2), ("cash flip", 1.2), ("address poisoning", 1.2), ("approval phishing", 1.3),
        ("ice phishing", 1.3), ("malicious dapp", 1.3), ("honeypot token", 1.3), ("fraud method pdf", 1.3),
        ("cc to btc", 1.3), ("gift card flip", 1.2), ("logs to cash", 1.2), ("bank log cashout", 1.3),
        ("drops for hire", 1.3), ("cash gifting", 1.1), ("blessing loom", 1.2),
    ],
    "counterfeit_documents": [
        ("novelty ID maker", 1.3), ("template passport", 1.3), ("PSD template", 1.2), ("photoshopped ID", 1.2),
        ("forged signature", 1.0), ("notary fraud", 1.2), ("fake COVID certificate", 1.2),
        ("fake vaccine card", 1.3), ("fake proof of address", 1.2), ("doc vendor", 1.1), ("scannable fake", 1.3),
        ("MRZ generator", 1.3), ("counterfeit notes", 1.4), ("fake currency printing", 1.4), ("supernote", 1.4),
        ("fake passport vendor", 1.4), ("registered passport", 1.3), ("biometric passport fake", 1.4),
        ("fake schengen visa", 1.3), ("fake work permit", 1.2), ("fake residence permit", 1.3),
        ("counterfeit id vendor", 1.4), ("fake euro notes", 1.3),
    ],
    "financial_fraud": [
        ("ACH kiting", 1.2), ("synthetic credit", 1.3), ("bust out fraud", 1.4), ("first party fraud", 1.2),
        ("merchant fraud", 1.1), ("payment processor fraud", 1.2), ("crypto rug pull", 1.4),
        ("wash trading", 1.3), ("ramp and dump", 1.3), ("short and distort", 1.3), ("microcap fraud", 1.3),
        ("affinity fraud", 1.3), ("trade finance fraud", 1.3), ("letter of credit fraud", 1.3),
        ("EIDL fraud", 1.4), ("unemployment fraud", 1.3), ("tax refund fraud", 1.3),
        ("stolen identity refund fraud", 1.4), ("BEC wire", 1.3), ("vendor impersonation", 1.2),
        ("escrow fraud", 1.2), ("NFT wash trading", 1.3), ("liquidity scam", 1.2),
    ],
    "identity_theft": [
        ("synthetic ID fraud", 1.5), ("CPN package", 1.4), ("tradeline", 1.0), ("piggyback credit", 1.1),
        ("credit muling", 1.2), ("new credit file", 1.2), ("scan front and back", 1.2), ("KYC pack", 1.3),
        ("doxing service", 1.3), ("DL scan", 1.0), ("identity verification bypass", 1.3),
        ("face match bypass", 1.3), ("liveness bypass", 1.4), ("deepfake KYC", 1.5), ("AI face swap KYC", 1.4),
        ("ssn lookup service", 1.2), ("tradeline boost", 1.1), ("cpn with tradelines", 1.3),
        ("primary tradeline", 1.1), ("ein only credit", 1.2),
    ],
    "exploit_trading": [
        ("nday exploit", 1.2), ("exploit chain", 1.3), ("kernel LPE", 1.3), ("UAF exploit", 1.2),
        ("use-after-free", 1.0), ("type confusion", 1.0), ("EDR bypass", 1.2), ("AMSI bypass", 1.1),
        ("UAC bypass", 1.0), ("PrintNightmare", 1.3), ("ProxyShell", 1.3), ("ProxyLogon", 1.3),
        ("Log4Shell", 1.3), ("EternalBlue", 1.3), ("BlueKeep", 1.3), ("Zerologon", 1.3), ("Follina", 1.2),
        ("Citrix Bleed", 1.4), ("MOVEit exploit", 1.4), ("Ivanti exploit", 1.4), ("Fortinet exploit", 1.3),
        ("PAN-OS exploit", 1.3), ("0click exploit", 1.5), ("one-click exploit", 1.3), ("weaponized PoC", 1.4),
        ("memory corruption", 0.9), ("webshell upload", 1.1), ("exploit broker", 1.5), ("vuln for sale", 1.4),
        ("private 0day", 1.5), ("ios 0day", 1.5), ("android 0day", 1.5), ("chrome 0day", 1.5),
        ("windows 0day", 1.5), ("vpn 0day", 1.4),
    ],
    "phishing_kits": [
        ("adversary in the middle", 1.4), ("AiTM phishing", 1.5), ("Evilginx", 1.5), ("EvilProxy", 1.5),
        ("Tycoon 2FA", 1.5), ("Mamba 2FA", 1.4), ("Greatness kit", 1.4), ("Caffeine kit", 1.3),
        ("reverse proxy phishing", 1.4), ("cookie theft phishing", 1.3), ("smishing kit", 1.3),
        ("fake captcha page", 1.2), ("ClickFix", 1.3), ("browser in the browser", 1.4), ("BitB attack", 1.3),
        ("phishlet", 1.4), ("MFA fatigue", 1.2), ("push bombing", 1.2), ("OTP relay", 1.3),
        ("o365 phishlet", 1.4), ("crypto wallet phishing", 1.3), ("seed phrase stealer page", 1.4),
        ("wallet drainer kit", 1.5), ("bulletproof smtp", 1.2), ("scampage undetected", 1.3),
        ("bank scampage", 1.3), ("crypto scampage", 1.3), ("letter sender", 1.0),
    ],
    "malware_botnet_rental": [
        ("Mirai variant", 1.3), ("Mozi botnet", 1.3), ("RapperBot", 1.3), ("Condi botnet", 1.2),
        ("DDoS botnet", 1.3), ("L7 stresser", 1.4), ("L4 stresser", 1.3), ("IP booter panel", 1.4),
        ("api stresser", 1.2), ("DDoS panel", 1.3), ("network stresser", 1.3), ("DNS amplification", 1.1),
        ("memcached amplification", 1.2), ("carpet bombing ddos", 1.3), ("botnet for rent", 1.5),
        ("rent a botnet", 1.5), ("boot offline", 1.2), ("residential botnet", 1.3), ("911 proxy", 1.2),
        ("socks5 botnet", 1.3), ("malware loader rental", 1.3), ("pay per install network", 1.4),
        ("traffic distribution system", 1.3), ("malvertising", 1.2), ("bulletproof VPS", 1.4),
        ("offshore VPS", 1.1), ("DMCA ignore hosting", 1.3), ("private booter", 1.2), ("lifetime booter", 1.1),
        ("ddos service", 1.3),
    ],
    "money_laundering": [
        ("Tornado Cash", 1.5), ("Blender.io", 1.5), ("Sinbad", 1.5), ("Samourai Wallet", 1.4),
        ("Bitcoin Fog", 1.5), ("Helix mixer", 1.5), ("JoinMarket", 1.2), ("CoinJoin", 1.2), ("Whirlpool mix", 1.2),
        ("eXch", 1.2), ("FixedFloat", 1.2), ("instant swap no kyc", 1.4), ("anonymous exchange", 1.3),
        ("chain peeling", 1.3), ("nested exchange", 1.3), ("OTC desk laundering", 1.4), ("Huione", 1.4),
        ("Huione Guarantee", 1.5), ("guarantee market", 1.2), ("USDT laundering", 1.4), ("tether laundering", 1.4),
        ("stablecoin laundering", 1.3), ("crypto cashout", 1.3), ("funnel account", 1.3), ("mule account", 1.4),
        ("mule herder", 1.4), ("smurf accounts", 1.3), ("layered transfers", 1.2), ("gift card laundering", 1.3),
        ("casino laundering", 1.3), ("NFT wash trading", 1.2), ("real estate laundering", 1.2),
        ("nominee account", 1.2), ("money laundering service", 1.5), ("clean btc", 1.3), ("washed btc", 1.4),
        ("dirty btc cleaning", 1.4), ("crypto tumbling service", 1.5), ("p2p no kyc", 1.2), ("LocalMonero", 1.2),
        ("atomic swap laundering", 1.2), ("decentralized mixer", 1.3), ("monero conversion", 1.2),
        ("western union flip", 1.3), ("moneygram flip", 1.3), ("zelle transfer service", 1.2), ("laundered funds", 1.3),
    ],
    "insider_threat": [
        ("recruiting insiders", 1.4), ("insider recruitment", 1.5), ("malicious insider", 1.4),
        ("insider for hire", 1.5), ("employee for hire", 1.3), ("telecom insider", 1.4), ("SIM swap insider", 1.5),
        ("bank insider", 1.4), ("call center insider", 1.3), ("KYC insider", 1.4), ("crypto exchange insider", 1.5),
        ("warehouse insider", 1.2), ("logistics insider", 1.2), ("courier insider", 1.2), ("airport insider", 1.4),
        ("port insider", 1.3), ("physical access insider", 1.3), ("plant a device", 1.2), ("rogue device", 1.1),
        ("pay for access insider", 1.4), ("data theft by employee", 1.3),
    ],
    "cyber_espionage": [
        ("Lazarus", 1.5), ("Kimsuky", 1.5), ("Andariel", 1.5), ("BlueNoroff", 1.5), ("APT37", 1.5),
        ("APT38", 1.5), ("Volt Typhoon", 1.5), ("Salt Typhoon", 1.5), ("Flax Typhoon", 1.5), ("Silk Typhoon", 1.4),
        ("Mustang Panda", 1.5), ("APT10", 1.5), ("APT40", 1.5), ("Stone Panda", 1.4), ("Sandworm", 1.5),
        ("APT44", 1.5), ("Midnight Blizzard", 1.5), ("Gamaredon", 1.5), ("Snake malware", 1.3),
        ("Charming Kitten", 1.5), ("APT35", 1.5), ("MuddyWater", 1.5), ("OilRig", 1.5), ("APT34", 1.4),
        ("Scattered Spider", 1.5), ("Comment Crew", 1.4), ("APT1", 1.2), ("Winnti", 1.4), ("FIN7", 1.5),
        ("FIN8", 1.4), ("Carbanak", 1.5), ("Cobalt Group", 1.4), ("Wizard Spider", 1.4), ("APT42", 1.4),
        ("APT43", 1.4), ("Star Blizzard", 1.4), ("ToddyCat", 1.3), ("cyber mercenary", 1.4), ("hack for hire", 1.4),
        ("spyware vendor", 1.3), ("Pegasus spyware", 1.5), ("NSO Group", 1.4), ("Predator spyware", 1.4),
        ("Intellexa", 1.4), ("zero-click spyware", 1.5), ("supply-chain implant", 1.4), ("SolarWinds", 1.3),
        ("UEFI implant", 1.4), ("firmware implant", 1.3), ("strategic web compromise", 1.2),
        ("ministry of defense hack", 1.3), ("embassy hack", 1.3), ("election interference", 1.2),
        ("telecom espionage", 1.3), ("defense industrial base", 1.1), ("classified leak", 1.2),
        ("espionage operation", 1.2), ("offensive cyber", 1.0),
    ],
}

# Merge EXTRA into CATEGORY_PHRASES with case-insensitive dedup (within and across).
for _cat, _extra in EXTRA_PHRASES.items():
    _seen = {p.lower() for p, _ in CATEGORY_PHRASES.get(_cat, [])}
    _dst = CATEGORY_PHRASES.setdefault(_cat, [])
    for _p, _w in _extra:
        if _p.lower() not in _seen:
            _dst.append((_p, _w))
            _seen.add(_p.lower())

# Second expansion wave — merged the same way (keeps the diff reviewable in batches).
EXTRA_PHRASES_2: Dict[str, List[Tuple[str, float]]] = {
    "ransomware": [
        ("SafePay", 1.4), ("Underground ransomware", 1.4), ("Kill Security", 1.3), ("Beast ransomware", 1.3),
        ("Cicada3301", 1.4), ("RansomHub affiliate", 1.4), ("data exfiltration extortion", 1.3),
        ("encrypt and leak", 1.3), ("pure extortion", 1.1), ("no encryption extortion", 1.1),
        ("Cl0p MOVEit", 1.4), ("we will leak", 1.1), ("countdown to leak", 1.2), ("pay or leak", 1.3),
        ("ransom in monero", 1.0), ("blog post victim", 0.8), ("affiliate wanted ransomware", 1.4),
    ],
    "malware_sale": [
        ("Vidar", 1.4), ("Raccoon", 1.2), ("Kraken stealer", 1.2), ("Luca stealer", 1.2), ("Lumar", 1.2),
        ("Stealerium", 1.2), ("Strela stealer", 1.3), ("Poseidon stealer", 1.3), ("Banshee stealer", 1.4),
        ("Cthulhu stealer", 1.3), ("Laplas clipper", 1.3), ("crypto drainer", 1.4), ("Inferno drainer", 1.4),
        ("Angel Drainer", 1.4), ("Pink Drainer", 1.4), ("RAT for sale", 1.4), ("android rat", 1.3),
        ("apk binder", 1.2), ("apk crypter", 1.2), ("loader as a service", 1.3), ("crypting as a service", 1.3),
        ("openbullet config", 1.2), ("silverbullet config", 1.2), ("combo checker", 1.1), ("account cracker", 1.2),
        ("proxyless checker", 1.0), ("config for sale", 0.7),
    ],
    "credential_leak": [
        ("logs shop", 1.3), ("fresh stealer logs", 1.3), ("mail pass logs", 1.2), ("crypto logs", 1.2),
        ("banking logs", 1.3), ("paypal logs", 1.2), ("amazon logs", 1.1), ("cookie session sale", 1.2),
        ("vpn accounts", 0.9), ("rdp for sale", 1.1), ("cpanel for sale", 1.1), ("smtp for sale", 1.1),
        ("webmail for sale", 1.0),
    ],
    "access_broker": [
        ("corporate vpn access", 1.4), ("admin credentials sale", 1.3), ("network compromise sale", 1.4),
        ("fortune 500 access", 1.3), ("US company access", 1.2), ("EU company access", 1.2),
        ("healthcare network access", 1.4), ("government network access", 1.4), ("vpn gateway access", 1.2),
        ("citrix gateway", 1.1), ("rdp dedicated", 1.0),
    ],
    "data_leak": [
        ("leaked credentials database", 1.2), ("linkedin scrape", 0.9), ("breach data sale", 1.3),
        ("customer database leak", 1.3), ("financial records leak", 1.3), ("tax records leak", 1.3),
        ("insurance data leak", 1.2), ("school data leak", 1.1), ("user records leak", 1.1),
        ("subscriber data leak", 1.0),
    ],
    "drug_trafficking": [
        ("flakka", 1.1), ("alpha-pvp", 1.2), ("mephedrone", 1.2), ("4-mmc", 1.1), ("3-mmc", 1.1),
        ("cathinone", 1.0), ("u-47700", 1.2), ("acetyl fentanyl", 1.2), ("furanyl fentanyl", 1.2),
        ("gray death", 1.2), ("710 oil", 0.7), ("distillate cart", 0.8), ("disposable cart", 0.6),
        ("press kit pills", 1.0), ("punch press", 0.7), ("cut and press", 0.9), ("dutch mdma", 1.0),
        ("crystal mdma", 1.0), ("lab tested drugs", 0.9), ("ghb gbl", 1.1), ("gbl cleaner", 1.0),
        ("nps research chem", 1.0), ("precursor chemicals", 1.1), ("pseudoephedrine bulk", 1.1),
        ("red phosphorus", 0.9), ("p2p synthesis", 1.0), ("safrole", 1.1), ("pmk glycidate", 1.3),
        ("bmk glycidate", 1.3), ("apaan", 1.2), ("ephedrine bulk", 1.0), ("kilo cocaine", 1.2),
        ("wholesale narcotics", 1.2), ("bulk mdma", 1.1), ("bulk ketamine", 1.1), ("top vendor dnm", 1.0),
        ("verified vendor dnm", 1.0), ("multi kilo", 1.0),
    ],
    "weapons_trafficking": [
        ("receiver blank", 1.2), ("80% glock", 1.3), ("ghost glock", 1.3), ("untraceable pistol", 1.4),
        ("converted full auto", 1.5), ("select fire conversion", 1.5), ("suppressor for sale", 1.3),
        ("silencer for sale", 1.3), ("explosives for sale", 1.5), ("parts kit firearm", 1.2),
        ("night vision scope", 0.7), ("ballistic plates", 0.7),
    ],
    "terrorism_extremism": [
        ("how to build a bomb", 1.7), ("ied construction", 1.7), ("detonator wiring", 1.5), ("suicide belt", 1.7),
        ("jihad funding", 1.4), ("propaganda distribution", 1.1), ("extremist forum", 1.2), ("violent jihad", 1.4),
        ("armed struggle", 0.9), ("mass shooting plan", 1.7), ("armed jihad", 1.3),
    ],
    "human_trafficking": [
        ("sex worker control", 1.2), ("trafficking for labor", 1.4), ("forced labor ring", 1.5),
        ("human smuggling fee", 1.2), ("coyote fee", 1.1), ("debt to traffickers", 1.3),
        ("escort trafficking", 1.3), ("minor exploitation ring", 1.6), ("trafficking advertisement", 1.4),
    ],
    "scam": [
        ("refund fraud method", 1.3), ("did not arrive method", 1.1), ("empty box method", 1.2),
        ("chargeback method", 1.2), ("dropshipping fraud", 1.1), ("fake tracking", 1.1), ("carded goods", 1.2),
        ("carded electronics", 1.2), ("crypto doubler", 1.3), ("investment doubler", 1.3),
        ("forex signals scam", 1.2), ("recovery scam", 1.3), ("fake recovery service", 1.3),
        ("seized funds scam", 1.2), ("inheritance fraud", 1.2), ("charity fraud", 1.2),
        ("disaster relief scam", 1.2), ("fake escrow site", 1.3), ("middleman scam", 1.1),
    ],
    "counterfeit_documents": [
        ("fake degree certificate", 1.3), ("fake transcript", 1.2), ("fake medical license", 1.4),
        ("fake police id", 1.4), ("fake press card", 1.2), ("counterfeit luxury", 0.9), ("replica watches", 0.7),
        ("counterfeit electronics", 0.8),
    ],
    "financial_fraud": [
        ("account opening fraud", 1.2), ("new account fraud", 1.2), ("loan stacking", 1.3),
        ("invoice factoring fraud", 1.2), ("credit washing", 1.3), ("section 609 dispute", 1.0),
        ("credit repair fraud", 1.2), ("cash advance fraud", 1.2), ("balance transfer fraud", 1.2),
        ("merchant account fraud", 1.2), ("account takeover fraud", 1.1),
    ],
    "identity_theft": [
        ("identity for sale", 1.4), ("full identity profile", 1.4), ("ssn and dob for sale", 1.4),
        ("dl front and back", 1.1), ("selfie verification bypass", 1.4), ("face spoof", 1.3), ("3d mask kyc", 1.3),
        ("us identity profile", 1.1), ("uk identity profile", 1.1),
    ],
    "exploit_trading": [
        ("rce zero day", 1.5), ("auth bypass zero day", 1.4), ("deserialization rce", 1.2),
        ("sandbox escape chain", 1.4), ("exploit acquisition", 1.3), ("vulnerability acquisition", 1.3),
        ("0day market", 1.5), ("exploit marketplace", 1.4), ("private exploit kit", 1.4), ("router 0day", 1.4),
        ("firewall 0day", 1.4), ("pre-auth exploit", 1.3),
    ],
    "phishing_kits": [
        ("scam page seller", 1.3), ("office365 scampage", 1.3), ("bank login page", 1.2),
        ("crypto login page", 1.2), ("2fa otp bypass", 1.3), ("real time phishing", 1.3),
        ("phishing redirect", 1.1), ("smtp cracker", 1.1), ("inbox mailer", 1.1), ("letter html", 0.9),
    ],
    "malware_botnet_rental": [
        ("ddos for hire service", 1.4), ("stresser subscription", 1.3), ("vip booter", 1.2),
        ("layer 4 stresser", 1.3), ("layer 7 stresser", 1.3), ("ovh bypass", 1.1), ("cloudflare uam bypass", 1.2),
        ("tcp ack flood", 1.1), ("dns flood", 1.0), ("game server down", 0.9),
    ],
    "money_laundering": [
        ("clean dirty crypto", 1.4), ("crypto cleaning service", 1.5), ("btc washing", 1.4), ("xmr laundering", 1.4),
        ("convert dirty btc", 1.4), ("underground exchanger", 1.4), ("no kyc swap", 1.3),
        ("instant exchange no kyc", 1.4), ("cashout dirty money", 1.4), ("money mule network", 1.4),
        ("drop bank account", 1.3), ("verified bank drops", 1.4), ("ach drop", 1.2), ("clean account payout", 1.2),
        ("dirty money cleaning", 1.4),
    ],
    "insider_threat": [
        ("insider data for sale", 1.4), ("employee credentials sale", 1.3), ("recruit employees data", 1.4),
        ("corporate insider wanted", 1.5), ("telco insider sim swap", 1.5), ("bank teller insider", 1.4),
        ("paid mole", 1.4), ("inside job", 0.9),
    ],
    "cyber_espionage": [
        ("Earth Lusca", 1.4), ("Earth Estries", 1.4), ("APT45", 1.4), ("Konni", 1.4), ("ScarCruft", 1.5),
        ("Bitter APT", 1.4), ("SideWinder", 1.4), ("Transparent Tribe", 1.4), ("Patchwork apt", 1.3),
        ("Donot team", 1.4), ("TraderTraitor", 1.4), ("UNC3886", 1.4), ("Storm-0558", 1.4),
        ("state sponsored hackers", 1.3), ("intelligence service hack", 1.3), ("cyber espionage campaign", 1.3),
        ("long term implant", 1.0), ("data theft nation state", 1.2), ("government targeted attack", 1.1),
        ("APT subgroup", 1.0),
    ],
}

for _cat, _extra in EXTRA_PHRASES_2.items():
    _seen = {p.lower() for p, _ in CATEGORY_PHRASES.get(_cat, [])}
    _dst = CATEGORY_PHRASES.setdefault(_cat, [])
    for _p, _w in _extra:
        if _p.lower() not in _seen:
            _dst.append((_p, _w))
            _seen.add(_p.lower())

# Pre-compile all phrases once at import (long-lived consumer process).
CATEGORY_REGEX: Dict[str, List[Tuple["re.Pattern[str]", float]]] = {
    cat: [(_compile_phrase(phr), w) for phr, w in phrases]
    for cat, phrases in CATEGORY_PHRASES.items()
}

# ----------------------------------------------------------------------
# 2. IOC-BASED SIGNAL BOOSTS — small additive weights on entity presence.
# ----------------------------------------------------------------------
IOC_RULES: Dict[str, Dict[str, float]] = {
    "cves": {
        "ransomware": 0.5, "malware_sale": 0.5, "access_broker": 0.3, "data_leak": 0.3,
        "exploit_trading": 0.6, "cyber_espionage": 0.3,
    },
    "btc_addresses": {
        "ransomware": 0.2, "malware_sale": 0.2, "access_broker": 0.2,
        "drug_trafficking": 0.2, "weapons_trafficking": 0.2, "scam": 0.2,
        "credential_leak": 0.1, "money_laundering": 0.3, "financial_fraud": 0.2,
        "phishing_kits": 0.1,
    },
    "xmr_addresses": {
        "ransomware": 0.3, "malware_sale": 0.2,
        "drug_trafficking": 0.2, "weapons_trafficking": 0.2, "money_laundering": 0.4,
    },
    "eth_addresses": {"scam": 0.2, "malware_sale": 0.1, "money_laundering": 0.2, "financial_fraud": 0.1},
    "email_addresses": {"scam": 0.1, "credential_leak": 0.3, "phishing_kits": 0.2, "identity_theft": 0.1},
    "domains": {"scam": 0.3, "malware_sale": 0.2, "ransomware": 0.2, "phishing_kits": 0.3, "malware_botnet_rental": 0.2},
    "ip_addresses": {"access_broker": 0.3, "malware_sale": 0.1, "malware_botnet_rental": 0.3, "cyber_espionage": 0.1},
    "pgp_fingerprints": {
        "ransomware": 0.2, "malware_sale": 0.2, "access_broker": 0.2,
        "drug_trafficking": 0.2, "weapons_trafficking": 0.2, "scam": 0.2,
    },
    "telegram_handles": {"scam": 0.1, "drug_trafficking": 0.1},
    "jabber_ids": {"scam": 0.1, "drug_trafficking": 0.1},
    "onion_addresses": {
        "drug_trafficking": 0.4, "weapons_trafficking": 0.4, "malware_sale": 0.4,
        "access_broker": 0.4, "ransomware": 0.3, "scam": 0.3, "credential_leak": 0.2,
        "counterfeit_documents": 0.3, "money_laundering": 0.2, "phishing_kits": 0.2,
        "malware_botnet_rental": 0.3, "identity_theft": 0.2,
    },
}

# ----------------------------------------------------------------------
# 2b. NEGATIVE CONTEXT — markers that a page is reference / educational /
# discussion material, NOT a transaction. The lexicon is context-blind and
# over-fires on technical prose (a privacy essay mentioning a drug name once, a
# defensive-security wiki mentioning "VPN"/"shell"), so we subtract a penalty from
# EVERY category score when these dominate. A real listing (drug name + price +
# shipping, score ~3-4) survives the penalty; a reference page (one stray keyword,
# score ~1) drops below threshold and correctly becomes "unknown".
# ----------------------------------------------------------------------
NEGATIVE_MARKERS: List[Tuple[str, float]] = [
    ("initializing search", 1.5),   # mkdocs documentation chrome (e.g. OPSEC Bible)
    ("skip to content", 1.0),
    ("table of contents", 1.0),
    ("operational security", 1.2),
    ("opsec bible", 1.5),
    ("harm reduction", 1.5),         # a harm-reduction discussion is not trafficking
    ("substance testing", 1.2),
    ("educational purpose", 1.0),
    ("for educational", 1.0),
    ("step-by-step guide", 0.8),
    ("documentation", 0.6),
    # Prevention / reporting / compliance / research context — the broader lexicons
    # (CSAM, money_laundering, exploit_trading, cyber_espionage) over-fire on pages
    # that DISCUSS the crime rather than commit it. These knock those pages down.
    ("report child abuse", 2.0), ("report abuse", 1.0), ("ncmec", 2.0),
    ("internet watch foundation", 2.0), ("missing children", 1.2), ("child safety", 1.0),
    ("anti-money laundering", 1.4), ("aml compliance", 1.5), ("kyc compliance", 1.2),
    ("compliance training", 1.2), ("regulatory", 0.6),
    ("threat intelligence report", 1.2), ("security advisory", 1.2),
    ("vulnerability disclosure", 1.0), ("cve database", 1.2), ("security research", 1.0),
    ("incident report", 0.8), ("law enforcement", 0.8), ("prevention", 0.6),
    ("how to report", 1.0), ("tip line", 1.0),
    # News / research / law-enforcement reporting context. APT/gang/malware NAMES are
    # great recall signals on a criminal forum but appear constantly in security news,
    # blog write-ups, and arrest announcements — which are NOT findings. A real
    # marketplace listing never says "were arrested" / "researchers report" / "takedown".
    ("security researcher", 1.2), ("security researchers", 1.3), ("researchers report", 1.3),
    ("threat researcher", 1.0), ("advisory published", 1.2), ("CISA advisory", 1.4),
    ("were arrested", 1.5), ("was arrested", 1.4), ("arrested", 0.7), ("indicted", 1.2),
    ("sentenced to", 1.0), ("pleaded guilty", 1.2), ("law enforcement operation", 1.5),
    ("takedown operation", 1.5), ("takedown", 0.9), ("dismantled", 1.1), ("seized by", 1.0),
    ("according to", 0.6), ("attributed to", 1.0), ("we assess", 1.0), ("our analysis", 0.9),
    ("indicators of compromise", 1.1), ("mitre att&ck", 1.0), ("blog post", 0.7),
    ("press release", 1.0), ("threat report", 1.0), ("victimology", 1.0),
]
_NEG_REGEX: List[Tuple["re.Pattern[str]", float]] = [
    (_compile_phrase(p), w) for p, w in NEGATIVE_MARKERS
]
NEG_PENALTY_CAP = float(os.environ.get("CLASSIFY_NEG_PENALTY_CAP", "2.5"))


def _negative_penalty(content: str) -> float:
    """Sum the weights of distinct reference/discussion markers present, capped."""
    total = 0.0
    for regex, w in _NEG_REGEX:
        if regex.search(content):
            total += w
    return min(total, NEG_PENALTY_CAP)


# Direct content signal: email:password lines indicate a credential dump.
CREDENTIAL_DUMP_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\s*[:;]\s*\S+"
)
CRED_DUMP_MIN_MATCHES = 3


def _add_ioc_signals(entities: dict, scores: Dict[str, float]) -> None:
    for entity_type, cats_weights in IOC_RULES.items():
        if not entities.get(entity_type):
            continue
        for cat, weight in cats_weights.items():
            scores[cat] += weight


# ----------------------------------------------------------------------
# 3. EVIDENCE EXTRACTION
# ----------------------------------------------------------------------
def _find_best_evidence(content: str,
                        matched_phrases: List[Tuple[str, float, int, int]]) -> str:
    """Pick the highest-weight matched phrase (ties -> first occurrence) and return
    up to 300 chars of surrounding text as an exact substring of `content`."""
    if not matched_phrases:
        return ""

    best = max(matched_phrases, key=lambda x: (x[1], -x[2]))
    start, end = best[2], best[3]

    context_radius = 150
    snippet_start = max(0, start - context_radius)
    snippet_end = min(len(content), end + context_radius)

    if snippet_start > 0:
        while snippet_start < start and content[snippet_start] != " ":
            snippet_start += 1
    if snippet_end < len(content):
        while snippet_end > end and content[snippet_end - 1] != " ":
            snippet_end -= 1

    evidence = content[snippet_start:snippet_end]
    if len(evidence) > 300:
        evidence = evidence[:300]
    return evidence


# ----------------------------------------------------------------------
# 4. CONFIDENCE — exponential CDF: 1 - exp(-0.6 * weight_sum).
#   0.5 -> 0.259 | 1.0 -> 0.451 | 1.5 -> 0.593 | 2.0 -> 0.699
#   2.5 -> 0.777 | 3.0 -> 0.835 | 4.0 -> 0.909
# ----------------------------------------------------------------------
def _confidence(weight_sum: float) -> float:
    if weight_sum <= 0:
        return 0.0
    return 1.0 - math.exp(-0.6 * weight_sum)


# ----------------------------------------------------------------------
# 5. SUMMARY GENERATION
# ----------------------------------------------------------------------
def _generate_summary(category: str, matched_phrases: List[Tuple[str, float, int, int]],
                      entities: dict) -> str:
    top_phrases = sorted(matched_phrases, key=lambda x: x[1], reverse=True)[:3]
    phrase_texts = [p[0] for p in top_phrases]

    ioc_parts: List[str] = []
    if entities.get("cves"):
        ioc_parts.append(f"CVEs: {', '.join(entities['cves'][:3])}")
    if entities.get("btc_addresses"):
        ioc_parts.append(f"BTC: {entities['btc_addresses'][0]}")
    if entities.get("email_addresses"):
        email = entities["email_addresses"][0]
        ioc_parts.append(f"Email: {email.get('address', '') if isinstance(email, dict) else email}")
    if entities.get("domains"):
        dom = entities["domains"][0]
        ioc_parts.append(f"Domain: {dom.get('domain', '') if isinstance(dom, dict) else dom}")

    summary = f"[{category}] Signals: {', '.join(phrase_texts)}. "
    summary += ("IOC: " + "; ".join(ioc_parts) + ".") if ioc_parts else "No IOCs extracted."
    return summary[:500]


# ----------------------------------------------------------------------
# 6. MAIN CLASSIFICATION FUNCTION
# ----------------------------------------------------------------------
def classify(content: str, entities: dict) -> dict:
    """Classify hostile content into exactly one category. Returns a dict with
    keys: category, confidence, summary, entities, evidence_quote."""
    content = (content or "")[:CLASSIFY_MAX_CHARS]
    entities = entities or {}

    scores: Dict[str, float] = {cat: 0.0 for cat in CATEGORY_REGEX}
    all_matched: List[Tuple[str, float, int, int]] = []

    # 6.1 Phrase matching — unique phrase per category counts once.
    for category, patterns in CATEGORY_REGEX.items():
        cat_matched: set = set()
        for regex, weight in patterns:
            for m in regex.finditer(content):
                phrase = m.group(0)
                if phrase not in cat_matched:
                    cat_matched.add(phrase)
                    scores[category] += weight
                    all_matched.append((phrase, weight, m.start(), m.end()))

    # 6.2 Content credential-dump signal.
    if len(CREDENTIAL_DUMP_REGEX.findall(content)) >= CRED_DUMP_MIN_MATCHES:
        scores["credential_leak"] += 1.5

    # 6.3 IOC signals.
    _add_ioc_signals(entities, scores)

    # 6.3b Negative-context penalty: reference/educational/discussion pages get every
    # category score knocked down, so a stray keyword in prose no longer becomes a
    # finding while a genuine transaction page (much higher score) survives.
    penalty = _negative_penalty(content)
    if penalty:
        for cat in scores:
            scores[cat] = max(0.0, scores[cat] - penalty)

    # 6.4 Category selection. max() returns the first-inserted on ties (deterministic).
    best_cat = max(scores, key=scores.get)
    best_score = scores[best_cat]

    if best_score < 0.5:
        category = "unknown"
        conf = 1.0 - _confidence(best_score)  # confident it fits no known category
    else:
        category = best_cat
        conf = _confidence(best_score)
        # Conservative override: drop a high-risk label we are not sure about.
        if category in {"terrorism_extremism", "human_trafficking"} and conf < 0.7:
            category = "unknown"
            conf = 1.0 - conf

    # Contract: evidence_quote is "" for unknown; otherwise an exact substring.
    # child_exploitation is also forced empty — a CSAM hit must NOT carry a verbatim
    # snippet of the page anywhere downstream (it is quarantined, not retained).
    evidence_quote = ("" if category in ("unknown", "child_exploitation")
                      else _find_best_evidence(content, all_matched))

    # 6.5 Flat entities dict (scalar values for cross-source corroboration).
    flat_entities: Dict[str, str] = {}
    for key, val in entities.items():
        if not val:
            continue
        first = val[0]
        if isinstance(first, str):
            flat_entities[key] = first
        elif isinstance(first, dict):
            for sub_key, sub_val in first.items():
                flat_entities[f"{key}_{sub_key}"] = str(sub_val)
            if key == "email_addresses":
                flat_entities["email_address"] = str(first.get("address", ""))
                flat_entities["email_domain"] = str(first.get("domain", ""))
            elif key == "domains":
                flat_entities["domain"] = str(first.get("domain", ""))
                flat_entities["tld"] = str(first.get("tld", ""))
            elif key == "pgp_fingerprints":
                flat_entities["pgp_fingerprint"] = str(first.get("fingerprint", ""))
            elif key == "persons":
                flat_entities["person_name"] = str(first.get("name", ""))

    return {
        "category": category,
        "confidence": round(conf, 4),
        "summary": _generate_summary(category, all_matched, entities),
        "entities": flat_entities,
        "evidence_quote": evidence_quote,
    }
