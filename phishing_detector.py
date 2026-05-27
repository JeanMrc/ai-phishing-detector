import os
import json
import getpass
import logging
import time
import email
import dns.resolver
from datetime import datetime
from groq import Groq
from dotenv import load_dotenv

# -- Config --
load_dotenv()
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "phishing_log.txt")
KEY_FILE = os.path.join(BASE_DIR, "config.json")

DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() == "true"

DEMO_RESPONSE = {
    "threat_score": 9,
    "verdict": "PHISHING",
    "indicators": [
        "Urgency tactic detected",
        "Suspicious URL not matching official domain",
        "Impersonation of trusted institution"
    ],
    "recommendation": "Do not click any links. Contact the institution directly using official contact information."
}

# -- Logging --
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s — %(message)s"
)


# -- API Key Setup --
def load_api_key():
    # First check environment variable
    env_key = os.getenv("GROQ_API_KEY")
    if env_key:
        return env_key

    # Then check saved config
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "r") as f:
            config = json.load(f)
            if config.get("groq_api_key"):
                return config["groq_api_key"]

    # Ask user
    print("=" * 50)
    print("AI Phishing Detector — First Time Setup")
    print("=" * 50)
    print("A free Groq API key is required to run this tool.")
    print("Get yours at: https://console.groq.com")
    print("-" * 50)
    api_key = getpass.getpass("Enter your Groq API key: ").strip()

    if not api_key:
        print("No API key provided. Switching to demo mode.")
        return None

    # Save for next time
    with open(KEY_FILE, "w") as f:
        json.dump({"groq_api_key": api_key}, f)
    print("API key saved. You won't need to enter it again.")
    print("-" * 50)

    return api_key


# -- Parse EML File --
def parse_eml(filepath):
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        msg = email.message_from_file(f)

    subject  = msg.get("Subject",  "No Subject")
    sender   = msg.get("From",     "Unknown")
    reply_to = msg.get("Reply-To", "Not set")
    received = msg.get("Received", "Unknown")

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_payload(decode=True).decode("utf-8", errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode("utf-8", errors="ignore")
        else:
            body = msg.get_payload()

    return {
        "subject":  subject,
        "sender":   sender,
        "reply_to": reply_to,
        "received": received,
        "body":     body
    }


# -- Check SPF/DKIM/DMARC --
def check_email_auth(sender):
    domain  = sender.split("@")[-1].strip(">")
    results = {
        "spf":   "not found",
        "dkim":  "not found",
        "dmarc": "not found"
    }

    try:
        spf_records = dns.resolver.resolve(domain, "TXT")
        for record in spf_records:
            if "v=spf1" in str(record):
                results["spf"] = "found"
                break
    except Exception:
        pass

    try:
        dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for record in dmarc_records:
            if "v=DMARC1" in str(record):
                results["dmarc"] = "found"
                break
    except Exception:
        pass

    try:
        dkim_records = dns.resolver.resolve(f"default._domainkey.{domain}", "TXT")
        if dkim_records:
            results["dkim"] = "found"
    except Exception:
        pass

    return results


# -- Analyze Email --
def analyze_email(groq_client, email_text, email_data=None, auth_results=None):
    if DEMO_MODE or groq_client is None:
        print("Running in demo mode.")
        return DEMO_RESPONSE

    context = ""
    if email_data:
        context = f"""
Email Headers:
- Subject  : {email_data['subject']}
- From     : {email_data['sender']}
- Reply-To : {email_data['reply_to']}
- Received : {email_data['received']}
"""
    if auth_results:
        context += f"""
Authentication Results:
- SPF      : {auth_results['spf']}
- DKIM     : {auth_results['dkim']}
- DMARC    : {auth_results['dmarc']}
"""

    prompt = f"""You are a cybersecurity expert specializing in phishing detection.

Analyze the following email and provide:
1. Threat score (0-10, where 10 is definitely phishing)
2. Verdict (SAFE for 0-3, SUSPICIOUS for 4-6, PHISHING for 7-10)
3. Key indicators found
4. Recommendation

{context}

Email Body:
{email_text}

Respond in JSON format only, no other text:
{{
    "threat_score": 0,
    "verdict": "SAFE",
    "indicators": ["indicator1", "indicator2"],
    "recommendation": "your recommendation here"
}}"""

    max_retries = 3
    wait_time   = 2

    for attempt in range(max_retries):
        try:
            message = groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                max_tokens=1024,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            response_text = message.choices[0].message.content
            try:
                result = json.loads(response_text)
            except json.JSONDecodeError:
                clean  = response_text.strip().strip("```json").strip("```").strip()
                result = json.loads(clean)
            return result

        except Exception as e:
            if "429" in str(e):
                print(f"Rate limited. Waiting {wait_time} seconds...")
                time.sleep(wait_time)
                wait_time *= 2
            else:
                print(f"Error: {e}")
                print("Switching to demo mode.")
                return DEMO_RESPONSE

    print("Max retries reached. Switching to demo mode.")
    return DEMO_RESPONSE


# -- Display Result --
def display_result(email_text, result):
    verdict = result["verdict"]
    score   = result["threat_score"]

    print("=" * 50)
    print(f"Verdict     : {verdict}")
    print(f"Threat Score: {score}/10")
    print("-" * 50)
    print("Indicators:")
    for indicator in result["indicators"]:
        print(f"  - {indicator}")
    print("-" * 50)
    print(f"Recommendation: {result['recommendation']}")
    print("=" * 50)

    logging.info(f"Verdict: {verdict} | Score: {score}/10 | Indicators: {result['indicators']} | Email: {email_text[:50]}...")


# -- Main --
def main():
    api_key     = load_api_key()
    groq_client = Groq(api_key=api_key) if api_key else None

    print("AI Phishing Detector")
    print("-" * 50)
    print("Options:")
    print("  1. Analyze .eml file")
    print("  2. Paste email text")
    print("-" * 50)

    choice = input("Enter 1 or 2: ").strip()

    if choice == "1":
        filepath = input("Enter path to .eml file: ").strip()
        if not os.path.exists(filepath):
            print("File not found.")
            return

        email_data   = parse_eml(filepath)
        auth_results = check_email_auth(email_data["sender"])
        email_text   = email_data["body"]

        print(f"Subject  : {email_data['subject']}")
        print(f"From     : {email_data['sender']}")
        print(f"SPF      : {auth_results['spf']}")
        print(f"DKIM     : {auth_results['dkim']}")
        print(f"DMARC    : {auth_results['dmarc']}")
        print("-" * 50)

    else:
        print("Paste email content below.")
        print("Type END on a new line when done.")
        print("-" * 50)

        lines = []
        while True:
            line = input()
            if line.strip() == "END":
                break
            lines.append(line)

        email_text   = "\n".join(lines)
        email_data   = None
        auth_results = None

    if not email_text.strip():
        print("No email content found.")
        return

    print("Analyzing...")
    result = analyze_email(groq_client, email_text, email_data, auth_results)
    display_result(email_text, result)


# -- Run --
main()