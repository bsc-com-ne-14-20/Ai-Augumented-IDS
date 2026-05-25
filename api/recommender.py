import os
from groq import Groq
from dotenv import load_dotenv
from pathlib import Path

load_dotenv(dotenv_path=str(Path(__file__).parent / ".env"))
_client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def get_recommendation(result: dict, geo: dict) -> str:
    """
    Ask Groq LLM to recommend admin actions based on the detection result.
    Returns a concise recommendation string.
    """
    attack_type  = result.get("attack_type", "Unknown")
    stage        = result.get("stage")
    confidence   = result.get("confidence", 0)
    crs_score    = result.get("crs_score", 0)
    country      = geo.get("country", "Unknown")
    city         = geo.get("city", "Unknown")
    is_vpn       = geo.get("is_vpn", False)
    isp          = geo.get("isp", "Unknown")

    prompt = f"""
You are a cybersecurity expert advising a web application administrator.
An intrusion detection system has flagged the following HTTP request:

- Attack Type: {attack_type}
- Detected by: {stage} stage
- Confidence: {confidence:.1%}
- CRS Anomaly Score: {crs_score}
- Source Location: {city}, {country}
- ISP: {isp}
- VPN/Proxy Detected: {"Yes" if is_vpn else "No"}

Provide a concise, actionable recommendation for the administrator in 3-5 bullet points.
Focus on: immediate mitigation, root cause, and prevention.
Be specific to the attack type. Keep it under 150 words.
"""
    try:
        response = _client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=300,
            temperature=0.3,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"Recommendation unavailable: {str(e)}"
