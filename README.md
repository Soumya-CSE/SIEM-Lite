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
├── storage.py
├── mailer.py
├── requirements.txt
|
|
├── tests/
│   ├── testanalyzer.py
|
├── uploads/
|   ├── sample.log
│
|
├── templates/
│   ├── index.html
│   
│
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

### 🏠 Home Page 

<img width="1907" height="1029" alt="Home1" src="https://github.com/user-attachments/assets/8b561e80-7a07-4a98-815c-a9d4204fc9b5" />
<img width="1907" height="1027" alt="Home2" src="https://github.com/user-attachments/assets/f7b882ba-413c-42e5-8443-5e8ca5c8abc0" />



---

### 📈 Analysing Log Files

<img width="1895" height="1017" alt="Analyzing_logfile" src="https://github.com/user-attachments/assets/59c08719-0fb3-4f14-aa27-9a617cbd1680" />

---



### 📊 Analysis Report
<img width="1910" height="1012" alt="Dashboard1" src="https://github.com/user-attachments/assets/0df6a34b-3964-478f-a1da-47109580faad" />
<img width="1891" height="1026" alt="Dashboard2" src="https://github.com/user-attachments/assets/4c585e28-8b30-474e-ac38-85d2ca5a1057" />
<img width="1889" height="1021" alt="Dashboard3" src="https://github.com/user-attachments/assets/b5fd3480-788a-4eeb-8ea0-3a13b943904e" />


---

### 🕰️ Analysis History
<img width="1920" height="1016" alt="Analysis_History" src="https://github.com/user-attachments/assets/8cf97c3f-9902-4fd2-96dc-0802a9109b2f" />

---

### 🚨 Alerts
<img width="1897" height="1015" alt="Alerts" src="https://github.com/user-attachments/assets/9802812d-3617-4c08-9db9-226eea684f07" />

---

### ⚙️ Settings
<img width="1896" height="1010" alt="Settings1" src="https://github.com/user-attachments/assets/3eb84020-9ea4-450a-a875-acebf94b65eb" />
<img width="1902" height="1024" alt="Settings2" src="https://github.com/user-attachments/assets/fc0902b6-9bdb-4bbe-a89a-d7738f533432" />


---

### 📖 About
<img width="1906" height="1029" alt="About1" src="https://github.com/user-attachments/assets/6dd32059-0875-4c1d-b65b-1c3dc3e678e9" />
<img width="1907" height="1025" alt="About2" src="https://github.com/user-attachments/assets/1c64a80d-fb04-45cc-8efc-56697a443f2e" />

---

### 📧 Emailed Scanned Reports
<img width="1920" height="1010" alt="Emailed-Scan-Report1" src="https://github.com/user-attachments/assets/a604ce22-e40d-49cf-852e-6b68c7d3e974" />
<img width="1920" height="1010" alt="Emailed-Scan-Report" src="https://github.com/user-attachments/assets/d2cd827b-8c1b-4f84-9f9b-efd3ccff819a" />

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

## 📩 Contact Us

**Reach out to us at** siemliteofficial@gmail.com

## 👨‍💻 Author

**Soumya Hazra**

Computer Science & Engineering Student

Aspiring SOC Analyst | Cybersecurity Enthusiast

**GitHub:** https://github.com/Soumya-CSE

---

## ⭐ Support

If you found this project useful, consider giving it a **⭐ Star** on GitHub. Your support helps motivate future improvements and open-source contributions.
