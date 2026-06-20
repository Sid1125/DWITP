# DWITP Threat Lexicon

Keyword/phrase lexicon for the offline rule-lexicon classifier (`src/ai_layer/classifier.py`, `CATEGORY_PHRASES`). This file is **data, not code** — phrases here are dropped into the engine's per-category lists with a weight.

- **Matching:** case-insensitive, word-boundary-anchored (the engine already does this).
- **Scope:** 21 categories = the original 11 (expanded) + **10 new** (this iteration). `unknown` remains the fallback.
- **Total:** ~1,300 distinct phrases across all categories (well over the 1,000 target).

## Weighting rubric (assign when loading into the engine)

| Tier | Weight | Use for |
|------|--------|---------|
| **Strong** | 1.5–2.0 | Unambiguous, category-defining (gang/family/model names, "child sexual abuse material", "AK-47", "combolist") |
| **Medium** | 0.8–1.2 | Solid indicators ("RDP access", "money mule", "phishing kit") |
| **Weak** | 0.3–0.6 | Supporting/contextual, shared across categories ("vendor", "escrow", "order", "price", "PGP", "Wickr", "bitcoin") — never decisive alone |

**Overlap is fine.** Terms like `escrow`, `vendor`, `PGP`, `Wickr`, `Telegram`, `bitcoin`, `Western Union`, `cashout` appear in several categories — keep them **weak** so the dominant category wins on signal density, not on a single shared word.

**High-risk categories require restraint.** `terrorism_extremism`, `human_trafficking`, and `child_exploitation` must demand **multiple independent strong matches**; the existing conservative override (confidence < 0.7 → `unknown`) stays in force. `child_exploitation` is handled specially (see end).

---

## Original categories (expanded)

### ransomware
LockBit, Conti, ALPHV, BlackCat, Hive, RansomEXX, REvil, BlackMatter, DarkSide, Avaddon, NetWalker, Maze, Egregor, Ryuk, Sodinokibi, GandCrab, Phobos, Dharma, Makop, MedusaLocker, Nefilim, Ragnar Locker, Clop, DoppelPaymer, Cuba, Karakurt, Black Basta, Royal, Trigona, NoEscape, Snatch, Babuk, Vice Society, BianLian, Akira, Play ransomware, ransomware, ransom note, decryptor, decryption key, decrypt your files, data encrypted, files encrypted, double extortion, victim portal, leak site, shame site, we have your data, we stole your data, publish your data, if you don't pay, payment in bitcoin, pay in monero, ransom amount, ransom deadline, countdown timer, RaaS, ransomware as a service, affiliate program, negotiation chat, recovery key, master key

### malware_sale
stealer, credential stealer, RedLine, Vidar, Raccoon stealer, Mars stealer, Azorult, Formbook, LokiBot, Agent Tesla, AsyncRAT, Quasar RAT, Remcos, NanoCore, Warzone RAT, Orcus, VenomRAT, njRAT, DarkComet, crypter, FUD crypter, cryptor, runPE, packer, obfuscator, stub, builder, loader, malware panel, C2 panel, exploit kit, malware for sale, buy malware, buy RAT, RAT price, stealer price, undetectable, fully undetectable, bypass Windows Defender, bypass AV, botnet source, malware source, trojan, keylogger, spyware, infostealer, info-stealer, form grabber, web inject, loader service, crypting service, installs, lifetime license, private build, custom build, silent miner, hidden miner, clipper, clipboard hijacker

### credential_leak
combo, combolist, combo list, email:pass, email:password, log:pass, login:password, credential stuffing, leaked accounts, account dump, database dump, SQL dump, db dump, leaked database, stolen accounts, fresh combo, private combo, valid accounts, checker, checker logs, redline logs, stealer logs, rdp logs, vpn logs, ftp logs, urllogpass, cracked accounts, cracking, hashes, NTLM hash, MD5 hash, cPanel access, SMTP combo, bank logs, track2, fullz dump, passwords leaked, username list, credentials for sale, buy combo, share combo, pastebin dump, verified combo, mail access, email access, netflix accounts, spotify accounts, paypal accounts

### access_broker
initial access, access broker, IAB, network access, RDP access, SSH access, VPN access, Citrix access, Pulse Secure, Fortinet VPN, SonicWall, web shell, shell access, domain admin access, DA access, EA access, compromised network, corporate access, network access for sale, sell access, buy access, looking for access, RDP shop, dedicated access, backdoor access, persistent access, reverse shell, beacon, Cobalt Strike, Metasploit session, initial foothold, lateral movement, domain controller, Active Directory access, SMB access, WinRM, PsExec, root access, local admin, enterprise admin, privilege escalation, company revenue, employee count, industry sector, target organization, foothold for sale, access to company

### data_leak
data breach, data leak, leaked database, sensitive documents, internal files, confidential data, source code leak, private key leaked, database downloaded, db leaked, exposed credentials, document leak, leaked customer data, PII leak, SSN leak, credit card leak, passport scan, ID scan, bank statement leak, medical records leak, intellectual property, trade secrets, code repository leak, GitLab leak, internal docs, classified document, company secrets, breach disclosure, hacked data, stolen data for sale, full database for sale, mega.nz leak, customer list, employee list, financial report leak, internal memo, strategy document, leaked source, leaked archive, dump for sale, breached, exfiltrated data, exposed bucket, open S3 bucket

### drug_trafficking
cocaine, crack cocaine, heroin, black tar heroin, opium, methamphetamine, meth, crystal meth, ice, speed, MDMA, ecstasy, molly, LSD, acid, blotter, microdot, cannabis, weed, marijuana, hashish, hash, kush, fentanyl, carfentanil, oxycodone, oxycontin, percocet, xanax, alprazolam, adderall, valium, ketamine, special k, 2C-B, DMT, psilocybin, magic mushrooms, shrooms, mescaline, GHB, rohypnol, steroids, anabolic steroids, HGH, tramadol, codeine, lean, purple drank, research chemical, designer drug, synthetic cannabinoid, spice, K2, bath salts, legal high, narcotics, controlled substance, illegal drugs, drug marketplace, buy drugs online, drug vendor, stealth shipping, discreet packaging, vacuum sealed, worldwide shipping, finalize early, escrow, grams, ounces, kilos, pounds, quarter ounce, half ounce, eighth, gram price, pill press, reagent test, vape cart, wax, shatter, dabs, THC, edibles, pre-rolls, cartel, Sinaloa, plug, trap, re-up, brick, key of coke, white, powder, rock

### weapons_trafficking
firearm, handgun, pistol, rifle, shotgun, submachine gun, machine gun, assault rifle, AK-47, AKM, AK-74, AR-15, M16, M4, Glock 17, Glock 19, Glock 26, Beretta 92, Sig Sauer, Sig P320, Smith & Wesson, Ruger, Remington 870, Mossberg 500, CZ 75, HK USP, FN Five-seveN, Desert Eagle, ammunition, ammo, cartridge, .223, 5.56, .308, 7.62x39, 9mm, .40 S&W, .45 ACP, .50 BMG, hollow point, full metal jacket, armor-piercing, tracer round, suppressor, silencer, bump stock, binary trigger, full auto, auto sear, select fire, conversion kit, drop-in auto sear, ghost gun, 80% lower, 3D printed gun, FGC-9, Liberator pistol, untraceable firearm, no background check, no paper trail, straw purchase, high capacity magazine, gun for sale, buy guns online, illegal firearm, arms dealer, weapon shipment, grenade, explosive, C4, detonator, blasting cap

### terrorism_extremism
ISIS, ISIL, Daesh, Al-Qaeda, AQAP, AQIM, Al-Shabaab, Boko Haram, Taliban, Hezbollah, Hamas, PKK, Atomwaffen, The Base, Feuerkrieg, neo-Nazi, white supremacy, white power, accelerationism, 14 words, Siege culture, lone wolf, jihad, jihadi, mujahideen, martyrdom, istishhad, takfir, kuffar, infidel, apostate, caliphate, khilafah, pledge allegiance, bay'ah, attack planning, attack plan, bomb making, bomb-making instructions, pipe bomb, pressure cooker bomb, IED, TATP, ANFO, fertilizer bomb, vehicle ramming, knife attack, mass casualty, manifesto, propaganda video, beheading video, execution video, nasheed, Inspire magazine, Dabiq, Rumiyah, training camp, material support, foreign fighters, terror financing, target list, hit list, attack timeline, radicalization, recruit for jihad, incite violence, holy war, martyr, suicide vest, suicide bombing

### human_trafficking
human trafficking, sex trafficking, trafficking in persons, forced labor, forced prostitution, sexual exploitation, modern slavery, trafficking victim, trafficker, pimp, brothel, escort service, prostitution ring, sex slave, sexual servitude, domestic servitude, debt bondage, bride trafficking, organ trafficking, illegal adoption, migrant smuggling, coyote smuggler, snakehead, passport confiscation, work without pay, coercion, victim recruitment, harboring, safe house, stash house, forced marriage, mail-order bride, human cargo, border crossing, fake job offer, fake employment, labor exploitation, exploitation ring, trafficking network, trafficking syndicate, sold into slavery, runaway recruitment, online enticement, sextortion, webcam exploitation, cybersex trafficking, live-streamed abuse, victim control, threats and abuse, missing person recruitment, vulnerable target

### scam
scam, fraud, con artist, phishing, scam page, vishing, smishing, advance fee fraud, 419 scam, Nigerian prince, lottery scam, inheritance scam, romance scam, catfish, dating scam, investment scam, binary options, forex scam, ponzi, pyramid scheme, HYIP, pump and dump, crypto scam, giveaway scam, fake giveaway, airdrop scam, fake exchange, wallet drainer, seed phrase phishing, tech support scam, IRS scam, refund scam, refund method, carding, CVV, dumps, fullz, credit card fraud, account takeover, check fraud, wire fraud, BEC, business email compromise, CEO fraud, invoice fraud, gift card scam, apple gift card, google play card, steam card, money mule, PayPal scam, Zelle scam, cash app flip, fake check, overpayment scam, mystery shopper scam, work from home scam, fake invoice, chargeback fraud, triangulation fraud, drop shipping scam, return fraud, wardrobing, reshipper, cashout method, social engineering, spoofed email, fake support, impersonation scam

---

## New categories (10)

| Category | Scope |
|----------|-------|
| `counterfeit_documents` | Fake passports, IDs, diplomas, financial docs, counterfeit currency |
| `financial_fraud` | Securities/investment/wire/loan fraud, market manipulation (distinct from generic scam) |
| `identity_theft` | Sale of full identity profiles / PII packages (distinct from email:pass leaks) |
| `exploit_trading` | Zero-days, exploit code/kits, vulnerability brokering |
| `phishing_kits` | Phishing-page kits, panels, anti-bot/2FA-bypass tooling sold as product |
| `malware_botnet_rental` | DDoS-for-hire, booter/stresser, botnet rental, bulletproof infra |
| `money_laundering` | Mixing/tumbling, mules, shell companies, cashout infrastructure |
| `insider_threat` | Recruiting/offering employee access for data theft or sabotage |
| `child_exploitation` | **Detection → quarantine/report only** (see special handling) |
| `cyber_espionage` | State-sponsored/APT operations, classified-data theft, industrial espionage |

### counterfeit_documents
fake passport, fake driver license, fake ID, fake ID card, fake national ID, fake SSN card, fake green card, fake visa, fake diploma, fake degree, fake certificate, fake birth certificate, fake marriage certificate, fake utility bill, fake bank statement, fake pay stub, fake tax return, fake W-2, fake insurance card, fake vehicle title, counterfeit document, novelty document, replica document, scannable ID, hologram, UV ink, MRZ, RFID chip, biometric passport, 1:1 replica, blank passport, blank ID, real ID, novelty ID, buy fake documents, document forger, ID shop, counterfeit currency, counterfeit money, fake euros, fake dollars, fake banknotes, superdollar, passable copy, full document set

### financial_fraud
investment fraud, securities fraud, insider trading, market manipulation, spoofing, layering, pump and dump, prime bank fraud, high-yield investment program, embezzlement, accounting fraud, cooking the books, wire fraud, ACH fraud, wire transfer fraud, check kiting, loan fraud, mortgage fraud, PPP fraud, COVID relief fraud, tax fraud, tax evasion, offshore account, shell company, false invoicing, trade-based money laundering, front running, predicate offense, illicit finance, financial crime, sanctions evasion, OFAC evasion, asset misappropriation, fraudulent transfer, fake earnings, falsified statements, investment scheme, guaranteed returns, risk-free profit, double your money, insider tip, stock manipulation, boiler room, churning, Ponzi operator, payment diversion

### identity_theft
fullz, full info, SSN DOB, credit report, credit profile, credit score, Equifax, Experian, TransUnion, identity package, identity profile, CPN, credit privacy number, EIN for sale, synthetic identity, fake identity, new identity, second identity, document set, identity document, leaked SSN, leaked DOB, mother maiden name, driver license number, passport number, background check data, KYC bypass, eKYC bypass, verification bypass, bypass verification, selfie with ID, ID verification spoof, identity fraud, account takeover, identity theft, stolen identity, PII package, personal data for sale, full identity, dox, doxx, profile lookup, people search, SSN lookup, DOB lookup, credit sweep

### exploit_trading
zero-day, 0day, exploit, RCE, remote code execution, LPE, local privilege escalation, elevation of privilege, exploit code, proof of concept, weaponized exploit, exploit kit, exploit pack, exploit for sale, buy exploit, sell exploit, vulnerability broker, vulnerability market, zero-day broker, browser exploit, Chrome exploit, Firefox exploit, Safari exploit, Windows exploit, macOS exploit, iOS exploit, Android exploit, kernel exploit, sandbox escape, SQLi exploit, deserialization exploit, auth bypass exploit, buffer overflow, heap spray, ROP chain, ASLR bypass, DEP bypass, shellcode, payload, post-exploitation, 1day, n-day, CVE for sale, private exploit, fresh exploit, undisclosed vulnerability, pre-auth RCE, unauthenticated RCE, wormable, full chain, jailbreak exploit, root exploit

### phishing_kits
phishing kit, phishkit, scam page, fake login page, fake bank login, office 365 phishing, microsoft phishing, google phishing, paypal phishing, apple phishing, coinbase phishing, phishing template, landing page kit, antibot, anti-bot, antidetect, cloaking, IP cloaking, redirect blocker, geo filter, bot filter, 2FA bypass kit, OTP bot, OTP grabber, SMS OTP bot, credential capture, login capture, phishing panel, phishing as a service, PhaaS, phishing service, buy phishing kit, sell phishing kit, scam letter, scam page builder, web inject kit, telegram logger, email logger, results panel, victim panel, mirror site, clone site, full clone, brand impersonation, fake checkout, fake payment page

### malware_botnet_rental
botnet, botnet rental, DDoS for hire, stresser, booter, booter service, IP stresser, DDoS attack, layer 7 attack, layer 4 attack, amplification attack, reflection attack, UDP flood, SYN flood, HTTP flood, slowloris, CC attack, take down site, knock offline, bypass Cloudflare, bypass DDoS protection, Gbps, Tbps, botnet panel, C2 infrastructure, command and control, zombie hosts, infected hosts, IoT botnet, Mirai, Qbot, Gafgyt, Meris, infected router, infected camera, bot rental, install service, pay per install, PPI, traffic seller, redirect traffic, residential proxy, mobile proxy, SOCKS5 proxy, proxy seller, backconnect proxy, bulletproof hosting, bulletproof server, offshore hosting, DMCA ignored, abuse ignored, fast flux, domain fronting

### money_laundering
money laundering, launder money, dirty money, clean your coins, placement layering integration, structuring, smurfing, shell company, shell bank, offshore account, offshore banking, tax haven, nominee director, bearer shares, front company, trade-based money laundering, over-invoicing, under-invoicing, hawala, hundi, black market peso exchange, crypto laundering, bitcoin mixer, BTC mixer, coin mixer, tumbler, cryptocurrency mixing, Tornado Cash, Wasabi wallet, ChipMixer, privacy coin, Monero swap, chain hopping, peel chain, cross-chain swap, money mule, mule recruitment, drop account, bank drop, bank logs cashout, ATM cashout, cashout service, dumps cashout, prepaid card cashout, gift card cashout, crypto debit card, p2p exchange, no-KYC exchange, exchanger office, digital currency exchanger, unlicensed MSB, underground bank, flying money, cash courier, bulk cash smuggling, clean funds, washed coins

### insider_threat
insider, insider threat, insider access, employee access, corporate insider, disgruntled employee, recruit insider, rogue admin, rogue employee, privileged user abuse, sysadmin access, database admin access, executive access, internal access for sale, sell company access, data exfiltration, exfiltrate data, USB exfiltration, cloud upload leak, personal email leak, screenshot leak, sabotage, logic bomb, time bomb, backdoor account, planted backdoor, internal network access, VPN access from inside, jump host, source code theft, design documents, R&D theft, merger leak, earnings leak, insider trading tip, payroll data, HR data, customer database access, sensitive internal documents, looking for insider, insider wanted, paid insider, employee bribe, bribe employee, mole, corporate mole

### cyber_espionage
cyber espionage, state-sponsored, nation-state actor, APT, advanced persistent threat, APT28, APT29, APT41, Lazarus Group, Kimsuky, Turla, Fancy Bear, Cozy Bear, Equation Group, Shadow Brokers, intelligence agency leak, GRU, FSB, SVR, MSS, NSA tools, CIA tools, cyber warfare, information operations, influence operations, disinformation campaign, hack and leak, supply chain attack, watering hole attack, spear phishing campaign, targeted intrusion, exfiltrate classified, classified document, top secret, TS/SCI, NOFORN, compartmented, diplomatic cable, defense contractor, critical infrastructure, ICS, SCADA, power grid attack, military secrets, weapons design, missile technology, nuclear technology, dual-use technology, export controlled, ITAR violation, trade secret theft, industrial espionage, commercial espionage, reverse engineer blueprints, espionage for hire, recruited asset, HUMINT, SIGINT

---

## ⚠️ Special handling: `child_exploitation` (CSAM)

This category exists **only** to satisfy the TG-G4 safety requirement: *detect → auto-quarantine → do NOT retain → mandatory report (NCMEC / law-enforcement liaison) per IR-001*. A hit here must **bypass the normal findings/review queue** and trigger the incident path; the content is **never** stored, indexed, browsed, or shown in the dashboard. This is a moderation/abuse-detection signal set, not a discovery tool.

**Detection phrases (strong, route-to-quarantine):**
child sexual abuse material, CSAM, child sexual abuse imagery, child exploitation material, child abuse imagery, child pornography, indecent images of children, self-generated CSAM, sextortion of a minor, child grooming, grooming a minor, online enticement of a minor, child sex tourism, minor-attracted, "jailbait", "lolita" content, "loli"/"shota" (illustrated CSAM context), "pthc", "hardcore" + minor, "preteen", "underage" + sexual, "cp" link, "cheese pizza" (coded), "hard candy" (coded), child model nude, abuse video of child, produce/distribute/trade CSAM, CSAM collection, CSAM forum, hurtcore

**Guidance:** require an explicit, unambiguous match; pair age markers ("underage", "preteen", "13yo", "minor") *with* sexual context before flagging to limit false positives on benign "child safety" / "report abuse" / prevention content. Prevention, reporting, and law-enforcement pages (NCMEC, IWF, "report child abuse", "stop CSAM", "tipline") must **not** be flagged — add them to the negative-context guard.

---

## Integration notes

1. These extend `CATEGORY_PHRASES` in `src/ai_layer/classifier.py` — add the 10 new keys and merge the expansions into the existing 11.
2. Add the new high-risk keys (`child_exploitation`) to `HIGH_RISK_CATEGORIES`; add `child_exploitation` to a quarantine path in `db_writer` (the TG-G4 gate, still unbuilt — see `TELEGRAM.md`).
3. Keep shared/weak terms (`vendor`, `escrow`, `order`, `price`, `bitcoin`, `Wickr`, `Telegram`) at low weight so they never decide a category alone.
4. Extend the negative-context guard with prevention/reporting/educational markers (CSAM hotlines, AML/compliance training, security-research write-ups) to suppress the obvious false positives these broader lexicons will introduce.
5. Validate after loading: re-run the smoke tests and spot-check that reference/discussion pages still resolve to `unknown`.
