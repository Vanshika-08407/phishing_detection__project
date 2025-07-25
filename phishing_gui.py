import streamlit as st
import re
from urllib.parse import urlparse
import csv
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline

# Load model once at startup
model_name = "najla45/phishing_detection_fine_tuned_bert"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(model_name)
bert_classifier = pipeline("text-classification", model=model, tokenizer=tokenizer)

def is_phishing_url(url):
    suspicious_keywords = ['secure', 'account', 'update', 'free', 'login', 'verify', 'banking']
    domain = urlparse(url).netloc
    path = urlparse(url).path

    score = 0
    if re.match(r'https?://\d{1,3}(\.\d{1,3}){3}', url):
        score += 2
    if '-' in domain:
        score += 1
    if not url.startswith("https://"):
        score += 3
    if any(keyword in url.lower() for keyword in suspicious_keywords):
        score += 2
    if len(url) > 75:
        score += 1
    if '@' in url:
        score += 2

    return score

def log_to_csv(input_text, rule_score, bert_label, bert_score, final_decision):
    with open("phishing_log.csv", "a", newline='') as f:
        writer = csv.writer(f)
        writer.writerow([input_text, rule_score, bert_label, f"{bert_score:.2f}", final_decision])

def combined_phishing_detector(url):
    rule_score = 0
    if url.startswith("http"):
        rule_score = is_phishing_url(url)
        rule_result = "Phishing" if rule_score >= 3 else "Safe"
    else:
        rule_result = "Not Applicable"

    bert_result = bert_classifier(url)[0]
    label_map = {"LABEL_0": "safe", "LABEL_1": "phishing"}
    bert_label = label_map.get(bert_result["label"].upper(), "unknown")
    bert_score = bert_result["score"]

    if rule_result == "Phishing" and (bert_label == "phishing" and bert_score > 0.75):
        final_decision = "Phishing"
    else:
        final_decision = "Safe"

    log_to_csv(url, rule_score, bert_label, bert_score, final_decision)
    return final_decision

# ---------------- STREAMLIT UI ----------------

st.set_page_config(page_title="Phishing Detector", page_icon="🔍")
st.title("🔐 Phishing URL & Message Detector")

user_input = st.text_area("Paste a URL or email message below:")

if st.button("Check"):
    if user_input.strip():
        result = combined_phishing_detector(user_input.strip())
        if result == "Phishing":
            st.error(f"🚨 Detected as: {result}")
        else:
            st.success(f"✅ Detected as: {result}")
    else:
        st.warning("⚠️ Please enter a valid URL or message.")     