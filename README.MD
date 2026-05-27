# AI Phishing Detector

An AI powered cybersecurity tool that analyzes suspicious emails 
and detects phishing attempts using LLaMA 3.3 70B via Groq API.

---

## The Problem
Basic keyword filters miss sophisticated phishing attacks.
Spear phishing emails are crafted to bypass traditional security
systems by mimicking legitimate communication patterns.

## The Solution
This tool uses LLaMA 3.3 70B to analyze email intent and context,
not just keywords — catching sophisticated attacks that traditional
systems miss.

---

## Features
- AI powered analysis using LLaMA 3.3 70B
- Threat score from 0 to 10
- Three verdict levels: SAFE, SUSPICIOUS, PHISHING
- Detailed indicators explaining detection logic
- Actionable recommendations
- Full timestamped audit log for accountability
- Exponential backoff — handles API rate limits gracefully
- Demo mode — works offline for client presentations

---

## Threat Score Scale
| Score | Verdict | Meaning |
|-------|---------|---------|
| 0-3 | SAFE | Legitimate email |
| 4-6 | SUSPICIOUS | Treat with caution |
| 7-10 | PHISHING | Do not interact |

---

## QA Test Results
| Email Type | Verdict | Score |
|-----------|---------|-------|
| Obvious phishing | PHISHING | 9/10 |
| Legitimate email | SAFE | 2/10 |
| Subtle phishing | PHISHING | 8/10 |

---

## Built With
- Python 3.13
- Groq API - fastest AI inference available
- LLaMA 3.3 70B - 70 billion parameter open source model
- Python-dotenv - secure credential management

---

## How to Run
1. Clone the repo
2. Install dependencies:
   pip install -r requirements.txt
3. Create .env file:
   GROQ_API_KEY=your_groq_api_key
   DEMO_MODE=false
4. Run:
   python phishing_detector.py
5. Paste suspicious email and type END

---

## Technical Challenges Solved

**1. Structured AI output**
Prompted LLaMA to respond strictly in JSON format then parsed
into Python dictionary for consistent programmatic processing.

**2. API reliability**
Implemented exponential backoff — retries 3 times with doubling
wait time on rate limit errors, falls back to demo mode if all
retries fail. Ensures zero crashes during client demonstrations.

**3. Consistent scoring**
Enforced scoring scale in the prompt — SAFE 0-3, SUSPICIOUS 4-6,
PHISHING 7-10 — ensuring consistent verdicts across all email types.

---

## Real World Use Cases
- Email security screening
- Security awareness training
- Phishing simulation for penetration testing
- SOC analyst assistance tool
- Enterprise email compliance auditing