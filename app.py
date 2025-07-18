from flask import Flask, render_template, request, jsonify
import re
import requests
from urllib.parse import urlparse

# Flask app initialization
app = Flask(__name__)

# Known phishing/tunneling domains
known_phishing_domains = [
    "trycloudflare.com",
    "ngrok.io",
    "localxpose.io",
    "localhost.run",
    "serveo.net"
]

# Function to detect suspicious URLs
def is_suspicious_url(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
            r'[a-z0-9]{20,}',  # Very long random strings
            r'[0-9]+[a-z]{2,}',  # Numbers followed by letters
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, domain):
                return True
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.top', '.xyz', '.club', '.biz', '.click', '.link', '.info', '.work', '.tk', '.ml', '.ga', '.cf']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                return True
        
        return False
    except:
        return True  # If URL parsing fails, consider it suspicious

# Function to check for phishing keywords
def detect_phishing_keywords(message):
    phishing_keywords = [
        "verify your account", "suspended", "click here", "confirm your identity", 
        "urgent", "security alert", "immediate action required", "account locked",
        "verify now", "click below", "act now", "limited time", "winner",
        "congratulations", "prize", "lottery", "inheritance", "tax refund",
        "suspended account", "unusual activity", "confirm payment"
    ]
    
    message_lower = message.lower()
    found_keywords = []
    
    for keyword in phishing_keywords:
        if keyword.lower() in message_lower:
            found_keywords.append(keyword)
    
    return found_keywords

# Function to check URLs using Google Safe Browsing API
def check_url_with_google_safe_browsing(url):
    # Note: You'll need to replace with your actual API key
    api_key = 'YOUR_GOOGLE_SAFE_BROWSING_API_KEY'
    
    if api_key == 'YOUR_GOOGLE_SAFE_BROWSING_API_KEY':
        # Skip API check if no valid key is provided
        return False
    
    endpoint = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
    
    payload = {
        "client": {
            "clientId": "sentinel-ai-phishing-detector",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(endpoint, json=payload, params={"key": api_key}, timeout=10)
        response.raise_for_status()
        result = response.json()
        
        if 'matches' in result and result['matches']:
            return True  # URL is malicious
        return False  # URL is safe
    except requests.exceptions.RequestException as e:
        print(f"Error checking URL with Safe Browsing API: {e}")
        return False  # Assume safe if API call fails

# Function to extract URLs from text
def extract_urls(text):
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, text)
    return urls

# Main function to analyze text and detect phishing
def analyze_text_for_phishing(text):
    if not text or not text.strip():
        return {
            "threat_level": "Safe",
            "reason": "No content to analyze",
            "suggestion": "Please provide text to analyze."
        }
    
    # Extract URLs from text
    urls = extract_urls(text)
    
    # Check for known phishing/tunneling domains
    flagged_domains = []
    for url in urls:
        for domain in known_phishing_domains:
            if domain in url.lower():
                flagged_domains.append(domain)
    
    # Check for suspicious URLs
    suspicious_urls = [url for url in urls if is_suspicious_url(url)]
    
    # Check URLs with Google Safe Browsing API
    unsafe_urls = []
    for url in urls:
        if check_url_with_google_safe_browsing(url):
            unsafe_urls.append(url)
    
    # Check for phishing keywords
    found_keywords = detect_phishing_keywords(text)
    
    # Determine threat level based on findings
    if flagged_domains:
        return {
            "threat_level": "High",
            "reason": f"Known phishing/tunneling domain(s) detected: {', '.join(set(flagged_domains))}",
            "suggestion": "Do not click or trust these URLs. These domains are commonly used for phishing attacks.",
            "details": {
                "flagged_domains": list(set(flagged_domains)),
                "urls_found": urls,
                "keywords_found": found_keywords
            }
        }
    elif unsafe_urls:
        return {
            "threat_level": "High",
            "reason": "Malicious URLs detected via Google Safe Browsing",
            "suggestion": "Do not click on these links. They have been flagged as dangerous.",
            "details": {
                "unsafe_urls": unsafe_urls,
                "urls_found": urls,
                "keywords_found": found_keywords
            }
        }
    elif suspicious_urls and found_keywords:
        return {
            "threat_level": "High",
            "reason": "Suspicious URLs and phishing keywords detected",
            "suggestion": "High likelihood of phishing. Verify the sender and do not click any links.",
            "details": {
                "suspicious_urls": suspicious_urls,
                "keywords_found": found_keywords
            }
        }
    elif suspicious_urls:
        return {
            "threat_level": "Medium",
            "reason": "Suspicious URLs detected",
            "suggestion": "Verify the URLs and sender before clicking. Check if the domain is legitimate.",
            "details": {
                "suspicious_urls": suspicious_urls,
                "urls_found": urls
            }
        }
    elif found_keywords:
        return {
            "threat_level": "Medium",
            "reason": f"Phishing keywords detected: {', '.join(found_keywords[:3])}{'...' if len(found_keywords) > 3 else ''}",
            "suggestion": "Proceed with caution and verify the sender. Be wary of urgent requests.",
            "details": {
                "keywords_found": found_keywords
            }
        }
    elif urls:
        return {
            "threat_level": "Low",
            "reason": "URLs found but no obvious threats detected",
            "suggestion": "Always verify links before clicking, even if they appear safe.",
            "details": {
                "urls_found": urls
            }
        }
    else:
        return {
            "threat_level": "Safe",
            "reason": "No suspicious patterns detected",
            "suggestion": "Content appears safe, but always remain vigilant online.",
            "details": {}
        }

# Flask route to serve the homepage
@app.route("/")
def home():
    return render_template("index.html")

# Flask route to handle text analysis
@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No JSON data received"}), 400
        
        user_input = data.get("text", "")
        
        if not user_input:
            return jsonify({"error": "No text provided for analysis"}), 400
        
        # Call analyze_text_for_phishing function
        response = analyze_text_for_phishing(user_input)
        
        return jsonify(response)
    
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

# Health check endpoint
@app.route("/health")
def health_check():
    return jsonify({"status": "healthy", "service": "Sentinel AI Phishing Detection"})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
