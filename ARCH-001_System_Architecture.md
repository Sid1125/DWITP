# ARCH-001 — System Architecture
## Dark Web Intelligence & Threat Monitoring Platform (DWITP)

**Version:** 1.0
**Classification:** Architecture Standard

---

# Purpose

This document defines the mandatory architecture of the Dark Web Intelligence & Threat Monitoring Platform (DWITP).

All implementations must conform to the security constraints defined in SEC-001.

Security requirements override architectural convenience.

---

# Mission Statement

The purpose of DWITP is to:

- Collect intelligence from approved dark web sources.
- Extract structured intelligence.
- Identify threat actors.
- Detect ransomware activity.
- Monitor credential leaks.
- Generate analyst-facing intelligence products.

The system is not designed to interact with threat actors.

The system is not designed to conduct offensive operations.

---

# Core Architecture

Dark Web Sources
↓
Tor Gateway
↓
Crawler Layer
↓
Raw Evidence Store
↓
Sanitization Layer
↓
Analysis Layer
↓
AI Classification Layer
↓
Data Storage Layer
↓
Dashboard Layer

---

# Component Definitions

## Tor Gateway

Responsibilities:

- Route all outbound traffic.
- Prevent clearnet leakage.
- Support circuit rotation.

Forbidden:

- Direct source access bypassing Tor.

---

## Crawler Layer

Responsibilities:

- Collect approved content.
- Store evidence.
- Generate crawl metadata.

Forbidden:

- Database writes.
- AI interaction.
- File downloads.

---

## Raw Evidence Store

Responsibilities:

- Preserve original content.
- Maintain chain of custody.
- Store immutable evidence.

Requirements:

- Write once.
- Read many.

---

## Sanitization Layer

Responsibilities:

- Remove hostile content.
- Detect prompt injections.
- Normalize text.

All records must pass through this layer.

---

## Analysis Layer

Responsibilities:

- Entity extraction.
- Correlation.
- Classification preparation.

---

## AI Layer

Responsibilities:

- Classification.
- Summarization.
- Entity validation.

Forbidden:

- Tool use.
- Network access.
- Filesystem access.
- Database writes.

---

## Data Storage Layer

Components:

- PostgreSQL
- OpenSearch
- Neo4j

---

## Dashboard Layer

Responsibilities:

- Read-only presentation.
- Analyst workflows.
- Investigation support.

---

# Data Flow Rules

1. No component may bypass the queue.
2. No component may write directly into another component's storage.
3. Dashboard never accesses raw evidence.
4. AI never accesses raw HTML.

---

# Technology Stack

| Layer | Technology |
|---------|-------------|
| Crawler | Python |
| Queue | RabbitMQ |
| Database | PostgreSQL |
| Search | OpenSearch |
| Graph | Neo4j |
| AI | Anthropic / Ollama |
| Containers | Docker |
| IaC | Terraform |

---

# End of Document