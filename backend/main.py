from fastapi import FastAPI
from pydantic import BaseModel
from typing import List

app = FastAPI()

# -------- Root API --------
@app.get("/")
def read_root():
    return {"message": "Centralized AI Threat Intelligence Platform is running"}


# -------- IOC Model --------
class IOC(BaseModel):
    ioc_value: str
    ioc_type: str
    threat_type: str
    confidence: str


# -------- Temporary storage --------
ioc_database: List[dict] = []


# -------- Threat scoring function --------
def calculate_threat_score(confidence: str):
    confidence_map = {
        "Low": 30,
        "Medium": 60,
        "High": 90
    }

    base_score = confidence_map.get(confidence, 50)

    # simplified scoring formula (MVP)
    threat_score = (
        base_score * 0.3 +
        70 * 0.3 +      # exploit activity (dummy)
        80 * 0.2 +      # asset criticality (dummy)
        60 * 0.2        # frequency (dummy)
    )

    return round(threat_score, 2)


# -------- Upload IOC API --------
@app.post("/upload-ioc")
def upload_ioc(ioc: IOC):
    score = calculate_threat_score(ioc.confidence)

    record = ioc.dict()
    record["threat_score"] = score

    ioc_database.append(record)

    return {
        "status": "IOC stored successfully",
        "threat_score": score,
        "total_iocs": len(ioc_database)
    }


# -------- View all IOCs --------
@app.get("/iocs")
def get_iocs():
    return ioc_database
# -------- Dashboard Summary --------
@app.get("/dashboard-summary")
def dashboard_summary():
    total_iocs = len(ioc_database)

    high_risk = [ioc for ioc in ioc_database if ioc.get("threat_score", 0) >= 75]
    high_risk_count = len(high_risk)

    avg_score = (
        sum(ioc.get("threat_score", 0) for ioc in ioc_database) / total_iocs
        if total_iocs > 0 else 0
    )

    return {
        "total_iocs": total_iocs,
        "high_risk_iocs": high_risk_count,
        "average_threat_score": round(avg_score, 2)
    }