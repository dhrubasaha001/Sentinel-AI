from flask import Flask, render_template, request, jsonify
import re
import requests

# Flask app initialization
app = Flask(__name__)

# OPTIONAL: Configure OpenAI or custom logic (You can use OpenAI models for analysis)
# openai.api_key = "YOUR_OPENAI_API_KEY"
known_phishing_domains = [
    "trycloudflare.com",
    "ngrok.io",
    "localxpose.io",
    "localhost.run",
    "serveo.net"
]
# Function to detect suspicious URLs
def is_suspicious_url(url):
    suspicious_patterns = re.compile(r"([a-zA-Z0-9]+[\.])+([a-zA-Z]{2,})|\d{1,3}(\.\d{1,3}){3}|\.(top|xyz|club|biz|click|link|info|work)$")
    return bool(suspicious_patterns.search(url))

# Function to check for phishing keywords
def detect_phishing_keywords(message):
    phishing_keywords = [
        "verify your account", "suspended", "click here", "confirm your identity", "urgent", "security alert"
    ]
    for keyword in phishing_keywords:
        if keyword.lower() in message.lower():
            return True
    return False

# Function to check URLs using Google Safe Browsing API
def check_url_with_google_safe_browsing(url):
    api_key = 'AIzaSyCGmJdULuYCTQQ4lnIuNhaZb06sBB3N1Ls'  # Replace with your API Key
    endpoint = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
    
    payload = {
        "client": {
            "clientId": "your-client-id",
            "clientVersion": "1.5.2"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    response = requests.post(endpoint, json=payload, params={"key": api_key})
    result = response.json()
    if 'matches' in result:
        return True  # URL is malicious
    return False  # URL is safe

# Function to analyze text and detect phishing
def analyze_text_for_phishing(text):
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    suspicious_urls = [url for url in urls if is_suspicious_url(url)]
    
    # Check if the URLs are safe using Google Safe Browsing API
    unsafe_urls = [url for url in suspicious_urls if check_url_with_google_safe_browsing(url)]
    
    # Check for phishing keywords
def analyze_text_for_phishing(text):
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    
    suspicious_urls = [url for url in urls if is_suspicious_url(url)]
    unsafe_urls = [url for url in suspicious_urls if check_url_with_google_safe_browsing(url)]
    
    # NEW: Check for known phishing/tunneling domains
    flagged_domains = []
    for url in urls:
        for domain in known_phishing_domains:
            if domain in url:
                flagged_domains.append(domain)

    suspicious_keywords = detect_phishing_keywords(text)
    
    if flagged_domains:
        return {
            "threat_level": "High",
            "reason": f"Known phishing/tunneling domain(s) detected: {', '.join(set(flagged_domains))}",
            "suggestion": "Do not click or trust these URLs."
        }
    elif unsafe_urls:
        return {
            "threat_level": "High",
            "reason": "Unsafe URLs detected via Safe Browsing",
            "suggestion": "Do not click on the links."
        }
    elif suspicious_urls:
        return {
            "threat_level": "Medium",
            "reason": "Suspicious URLs detected",
            "suggestion": "Verify the URLs before clicking."
        }
    elif suspicious_keywords:
        return {
            "threat_level": "Medium",
            "reason": "Phishing keywords detected",
            "suggestion": "Proceed with caution and verify the sender."
        }
    else:
        return {
            "threat_level": "Safe",
            "reason": "No suspicious patterns detected",
            "suggestion": "Proceed with caution as usual."
        }

# Flask route to serve the homepage
@app.route("/")
def home():
    return render_template("index.html")

# Flask route to handle text analysis
@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json
    user_input = data.get("text", "")

    # Call analyze_text_for_phishing function
    response = analyze_text_for_phishing(user_input)

    return jsonify(response)

if __name__ == "__main__":
    app.run(debug=True)
