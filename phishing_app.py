import gradio as gr
import re
from urllib.parse import urlparse
import csv
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
import torch
#URL model
url_tokenizer = AutoTokenizer.from_pretrained("najla45/phishing_detection_fine_tuned_bert")
url_model = AutoModelForSequenceClassification.from_pretrained("najla45/phishing_detection_fine_tuned_bert")
url_classifier = pipeline("text-classification", model=url_model, tokenizer=url_tokenizer)

#email model
email_tokenizer = AutoTokenizer.from_pretrained("cybersectony/phishing-email-detection-distilbert_v2.4.1")
email_model = AutoModelForSequenceClassification.from_pretrained("cybersectony/phishing-email-detection-distilbert_v2.4.1")

#logic for checking the state of url
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

#logic checking for phishing email
def predict_email(email_text):
    inputs = email_tokenizer(email_text, return_tensors="pt", truncation=True, max_length=512)
    with torch.no_grad():
        outputs = email_model(**inputs)
        probs = torch.nn.functional.softmax(outputs.logits, dim=-1)[0].tolist()

    labels = {
        "legitimate_email": probs[0],
        "phishing_url": probs[1],
        "legitimate_url": probs[2],
        "phishing_url_alt": probs[3]
    }

    max_label, max_score = max(labels.items(), key=lambda x: x[1])
    return max_label, max_score, labels


#LOGGING ALL DATA TO CSV FILE
import os
LOG_FILE = os.path.join(os.path.dirname(__file__), "phishing_log.csv")
def log_to_csv(url, rule_score, bert_label, bert_score, final_decision):
    try:
        file_exists = os.path.isfile(LOG_FILE)
        with open(LOG_FILE, "a", newline='') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["Input", "Rule Score", "BERT Label", "Confidence", "Final Decision"])
            writer.writerow([url, rule_score, bert_label, f"{bert_score:.2f}", final_decision])
    except Exception as e:
        print(f"Error writing to CSV: {e}")


#Combining URL and email checking logic
def combined_phishing_detector(url, input_type, log=True):
    if input_type == "URL":
        rule_score = is_phishing_url(url)
        rule_result = "Phishing" if rule_score >= 3 else "Safe"

        bert_result = url_classifier(url)[0]
        label_map = {"LABEL_0": "safe", "LABEL_1": "phishing"}
        bert_label = label_map.get(bert_result["label"].upper(), "unknown")
        bert_score = bert_result["score"]

        final_decision = "Phishing" if rule_result == "Phishing" and bert_label == "phishing" and bert_score > 0.75 else "Safe"

    elif input_type == "Email/Message":
        bert_label, bert_score, bert_probs = predict_email(url)
        rule_score = "N/A"
        rule_result = "Not Applicable"
        final_decision = "Phishing" if bert_label.startswith("phishing") and bert_score > 0.7 else "Safe"

    if log:
        log_to_csv(url, rule_score, bert_label, bert_score, final_decision)

    return url, rule_score, bert_label, bert_score, final_decision



def run_detector(text, input_type):
    url,rule_score, bert_label, bert_score,final_decision = combined_phishing_detector(text, input_type,log=True)
    
    # Add emoji based on result
    if final_decision.lower() == "phishing":
        emoji =  "🚨"   # warning
    elif final_decision.lower() == "safe":
        emoji = "✅"  # check mark
    else:
        emoji = "❓"

    message = (
        f"{emoji} Result: {final_decision}\n"
        f"📊 Rule Score: {rule_score}\n"
        f"🤖 BERT Label: {bert_label}\n"
        f"🔍 Confidence: {bert_score:.2f}"
    )
    return message,LOG_FILE

#---GUI-----
gr.HTML("""
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
<h1 style='text-align:center; color:white; font-family: "Poppins", sans-serif;'>🔐 Phishing URL & Email Detector (BERT + Rules) 🔐</h1>
""")

with gr.Blocks(css="""
.gradio-container {
    background-image: url('https://c8.alamy.com/comp/M79X4X/cyber-security-buzzwords-phishing-alert-with-blue-numbers-in-background-M79X4X.jpg');
    background-size: cover;
    background-position: center;
    background-repeat: no-repeat;
    font-family: 'Poppins', sans-serif;
    color: white;
}
input, textarea, button, label, .gr-box, .gr-button, .gr-textbox, .gr-radio, .gr-file {
    font-family: 'Poppins', sans-serif !important;
    color: white;
}
""") as demo:

    gr.HTML("<h1 style='text-align:center; color:white;'>🔐 Phishing URL & Email Detector (BERT + Rules) 🔐</h1>")

    with gr.Row():
        input_text = gr.Textbox(label="Enter URL or Email", lines=5)
        input_type = gr.Radio(["URL", "Email/Message"], label="Input Type")

    result_output = gr.Textbox(label="Detection Result", lines=4, interactive=False)
    log_file_output = gr.File(label="Download Log File")

    detect_button = gr.Button("Detect")

    detect_button.click(fn=run_detector, inputs=[input_text, input_type], outputs=[result_output, log_file_output])

    
demo.launch()



