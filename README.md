# 🛡️ SOC Log Analyzer

A web-based **Security Operations Center (SOC) Log Analyzer** built with **Python** and **Flask** that analyzes authentication log files, detects suspicious login activities, identifies potential brute-force attacks, and presents security insights through an interactive dashboard.

---

## 📌 Overview

SOC Log Analyzer simulates the day-to-day responsibilities of a **SOC L1 Analyst** by processing authentication logs and extracting meaningful security events. It identifies suspicious users based on repeated failed login attempts and displays the analysis through a clean, responsive web interface.

This project demonstrates practical cybersecurity concepts such as log analysis, authentication monitoring, threat detection, and basic security event analysis.

---

## ✨ Features

* 📂 Upload authentication log files (`.log`)
* 🔍 Analyze login events
* ✅ Count successful logins
* ❌ Count failed logins
* 👤 Detect suspicious users
* 🌐 Count unique IP addresses
* 🚨 Identify possible brute-force attacks
* 📊 Interactive security dashboard
* 🎨 Clean and responsive web interface
* ⚡ Fast log processing using Python

---

## 🛠️ Technologies Used

### Backend

* Python
* Flask

### Frontend

* HTML5
* CSS3
* Bootstrap

### Security Concepts

* Log Analysis
* Authentication Monitoring
* Brute Force Detection
* Security Event Analysis
* Blue Team Fundamentals

---

## 📂 Project Structure

```text
SOC-Log-Analyzer/
│
├── app.py
├── analyzer.py
├── requirements.txt
├── sample.log
│
├── uploads/
│
├── templates/
│   ├── index.html
│   └── result.html
│
├── static/
│   └── style.css
│
├── dashboard.png
│
└── README.md
```

---

## ⚙️ Installation

### Clone the repository

```bash
git clone https://github.com/Soumya-CSE/SOC-Log-Analyzer.git
```

### Navigate to the project directory

```bash
cd SOC-Log-Analyzer
```

### Install dependencies

```bash
pip install -r requirements.txt
```

or

```bash
pip install flask
```

---

## ▶️ Run the Application

```bash
python app.py
```

Open your browser and visit:

```text
http://127.0.0.1:5000
```

---

## 🚀 How to Use

1. Launch the Flask application.
2. Open the web interface in your browser.
3. Upload a `.log` authentication file.
4. Click **Analyze Log**.
5. View the security dashboard containing:

   * Total Log Entries
   * Successful Logins
   * Failed Logins
   * Unique IP Addresses
   * Suspicious Users
   * Threat Severity

---

## 🔍 Threat Detection Workflow

```text
Authentication Log File
          │
          ▼
      Upload File
          │
          ▼
      Log Parsing
          │
          ▼
Extract Users & IP Addresses
          │
          ▼
Detect Failed Login Attempts
          │
          ▼
Identify Suspicious Users
          │
          ▼
Generate Security Dashboard
```
---
## 📸 Application Preview

### 🏠 Dashboard

<img width="1847" height="897" alt="Dashboard" src="https://github.com/user-attachments/assets/cb5733eb-a1a4-47cd-b796-5a198c0aa6ef" />

---

### 📊 Analysis Report

<img width="1855" height="877" alt="Analysis report" src="https://github.com/user-attachments/assets/e24de03b-125f-4849-8b11-0f8d5686036b" />

---
## 🔐 Security Features

* Authentication Log Analysis
* Failed Login Detection
* Brute Force Attack Detection
* Suspicious User Identification
* IP Address Monitoring
* Security Event Classification
* Real-Time Dashboard Visualization

---

## 📋 Requirements

* Python 3.8+
* Flask

Install using:

```bash
pip install flask
```

or

```bash
pip install -r requirements.txt
```

---

## 🚀 Future Enhancements

* 📈 Interactive Charts using Chart.js
* 🌍 IP Geolocation
* 📄 Export Security Report as PDF
* 📧 Email Alert Notifications
* 🔐 User Authentication
* 🛰️ Real-Time Log Monitoring
* 🧠 Machine Learning-Based Anomaly Detection
* 🛡️ MITRE ATT&CK Technique Mapping
* ☁️ SIEM Integration
* 📊 Advanced Threat Analytics

---

## 🎯 Learning Outcomes

This project demonstrates practical experience with:

* Python Programming
* Flask Web Development
* File Handling
* Regular Expressions (Regex)
* Log Parsing
* Authentication Log Analysis
* Threat Detection
* Blue Team Security Concepts
* SOC Monitoring Workflow

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository.
2. Create a feature branch.
3. Commit your changes.
4. Push the branch.
5. Open a Pull Request.

---

## 📜 License

This project is licensed under the **MIT License**.

---

## 👨‍💻 Author

**Soumya Hazra**

Computer Science & Engineering Student

Aspiring SOC Analyst | Cybersecurity Enthusiast

**GitHub:** https://github.com/Soumya-CSE

---

## ⭐ Support

If you found this project useful, consider giving it a **⭐ Star** on GitHub. Your support helps motivate future improvements and open-source contributions.
