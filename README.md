# 🛡️ Centralized AI Threat Intelligence Platform

A FastAPI-based threat intelligence system that analyzes Indicators of Compromise (IOCs), assigns risk scores, and provides a centralized dashboard for security monitoring.

---

## 🚀 Features

* 🔍 Upload and analyze IOCs
* 🧠 AI-based threat scoring logic
* 📊 Real-time dashboard summary
* ⚡ FastAPI backend with interactive Swagger UI
* 🗂 Clean and modular project structure

---

## 🏗️ Tech Stack

* **Backend:** FastAPI (Python)
* **Server:** Uvicorn
* **API Testing:** Swagger UI
* **Version Control:** Git & GitHub

---

## 📁 Project Structure

```
centralized-ai-threat-intelligence/
│
├── backend/
│   └── main.py
│
├── frontend/
├── docs/
├── requirements.txt
└── README.md
```

---

## ⚙️ Setup Instructions

### 1️⃣ Clone the repository

```bash
git clone https://github.com/Rishikahj/AI-threat-intelligence-platform.git
cd centralized-ai-threat-intelligence
```

### 2️⃣ Create virtual environment

```bash
python -m venv venv
```

**Activate (Windows):**

```bash
venv\Scripts\activate
```

**Activate (Mac/Linux):**

```bash
source venv/bin/activate
```

### 3️⃣ Install dependencies

```bash
pip install -r requirements.txt
```

### 4️⃣ Run the server

```bash
uvicorn backend.main:app --reload
```

---

## 📡 API Documentation

After running the server, open:

```
http://127.0.0.1:8000/docs
```

### Available Endpoints

* `GET /` → Health check
* `POST /upload-ioc` → Upload and analyze IOC
* `GET /iocs` → Retrieve stored IOCs
* `GET /dashboard-summary` → View threat dashboard summary

---

## 🧪 Example IOC Payload

```json
{
  "ioc_value": "5.5.5.5",
  "ioc_type": "ip",
  "threat_type": "malware",
  "confidence": "high"
}
```

---

## 🎯 Future Improvements

* 🔐 Database integration (PostgreSQL/MongoDB)
* 🤖 Advanced ML-based threat scoring
* 📈 Interactive frontend dashboard
* 🌐 External threat intelligence feed integration


