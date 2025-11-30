🔐 AI-Based Phishing Email & URL Detection System

An AI-powered cybersecurity tool that detects phishing emails and malicious URLs using pre-trained BERT-based models.
This project helps users and security enthusiasts quickly identify suspicious content before interacting with it.

📌 Features

✅ Phishing URL Detection – Classifies URLs as Phishing or Legitimate using an AI model.

✅ Phishing Email / Message Detection – Analyzes email text or messages and flags phishing attempts.

✅ Unified Input – Single interface to analyze both URLs and email/message content.

✅ User-Friendly Interface – Built using Gradio / Streamlit (update according to what you used).

✅ Result Logging – Saves detection results (input, prediction, timestamp) into a CSV file for analysis.

✅ Real-Time Inference – Fast prediction using optimized transformer models.

🧠 Tech Stack

Language & Core:

Python 3.x

NLP with Transformer-based models

AI / ML Libraries:

transformers – for loading pre-trained BERT models

torch – deep learning backend

scikit-learn (if used for metrics / preprocessing)

Web UI:

Gradio or Streamlit (whichever you used for your app)

Others:

re, urllib.parse – URL parsing & pattern checks

csv – logging outputs

pandas (optional) – result handling & analysis
