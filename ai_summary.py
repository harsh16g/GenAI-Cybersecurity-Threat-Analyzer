import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("GROQ_API_KEY")

client = Groq(api_key=api_key)


# Read detected threats
with open("detected_threats.txt", "r") as f:
    threat_data = f.read()

prompt = f"""
You are a Security Operations Center (SOC) analyst.

Analyze the following cybersecurity threat report and generate
a professional incident summary.

Include:
- Overall risk level
- Summary of detected attacks
- Potential impact
- Recommended mitigation actions

Threat Report:
{threat_data}
"""

response = client.chat.completions.create(
    model="llama-3.1-8b-instant",
    messages=[
        {"role": "system", "content": "You are a cybersecurity expert."},
        {"role": "user", "content": prompt}
    ],
    temperature=0.3,
)

summary = response.choices[0].message.content

# Save AI-generated summary
with open("ai_summary.txt", "w") as f:
    f.write(summary)

print("AI incident report generated using Groq.")
print("Output saved as ai_summary.txt")
