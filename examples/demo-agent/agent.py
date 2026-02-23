"""
Treeship Demo Agent
A simple loan processing agent with built-in verification.
"""

import os
import random
from datetime import datetime
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from treeship_sdk import Treeship

# Configuration
AGENT_NAME = "demo-loan-agent"

# Initialize
app = FastAPI(title="Treeship Demo Agent")
ts = Treeship(api_key=os.getenv("TREESHIP_API_KEY"))


class LoanApplication(BaseModel):
    applicant: str
    amount: float
    credit_score: int = 700
    income: float = 75000


class LoanDecision(BaseModel):
    decision: str
    amount: float
    reason: str
    verification_url: str
    timestamp: str


def analyze_application(app: LoanApplication) -> dict:
    """Simulate AI analysis of a loan application."""
    risk_score = 0
    reasons = []
    
    # Credit score analysis
    if app.credit_score >= 750:
        risk_score += 30
        reasons.append("Excellent credit score")
    elif app.credit_score >= 700:
        risk_score += 20
        reasons.append("Good credit score")
    elif app.credit_score >= 650:
        risk_score += 10
        reasons.append("Fair credit score")
    else:
        reasons.append("Low credit score")
    
    # Debt-to-income ratio
    monthly_payment = app.amount / 60  # 5-year loan
    dti = monthly_payment / (app.income / 12)
    
    if dti < 0.28:
        risk_score += 30
        reasons.append("Low debt-to-income ratio")
    elif dti < 0.36:
        risk_score += 20
        reasons.append("Acceptable debt-to-income ratio")
    else:
        reasons.append("High debt-to-income ratio")
    
    # Amount check
    if app.amount <= app.income * 0.5:
        risk_score += 20
        reasons.append("Conservative loan amount")
    elif app.amount <= app.income:
        risk_score += 10
        reasons.append("Moderate loan amount")
    else:
        reasons.append("Large loan relative to income")
    
    return {
        "risk_score": risk_score,
        "reasons": reasons,
        "approved": risk_score >= 50
    }


@app.get("/")
def root():
    return {
        "agent": AGENT_NAME,
        "status": "running",
        "verification_page": f"https://treeship.dev/verify/{AGENT_NAME}",
        "docs": "/docs"
    }


@app.post("/process", response_model=LoanDecision)
def process_application(application: LoanApplication):
    """Process a loan application and create a verified attestation."""
    
    # Analyze the application
    analysis = analyze_application(application)
    
    decision = "approved" if analysis["approved"] else "denied"
    reason = "; ".join(analysis["reasons"])
    
    # Create attestation
    attestation = ts.attest(
        agent=AGENT_NAME,
        action=f"Loan {decision}: ${application.amount:,.0f} for {application.applicant}",
        inputs_hash=ts.hash({
            "applicant": application.applicant,
            "amount": application.amount,
            "credit_score": application.credit_score,
            "income": application.income
        }),
        metadata={
            "decision": decision,
            "risk_score": analysis["risk_score"]
        }
    )
    
    return LoanDecision(
        decision=decision,
        amount=application.amount,
        reason=reason,
        verification_url=attestation.verify_url,
        timestamp=datetime.utcnow().isoformat()
    )


@app.get("/verify/{attestation_id}")
def verify_attestation(attestation_id: str):
    """Verify an existing attestation."""
    result = ts.verify(attestation_id)
    return result


@app.get("/history")
def get_history():
    """Get recent attestations for this agent."""
    return {
        "agent": AGENT_NAME,
        "verification_page": f"https://treeship.dev/verify/{AGENT_NAME}",
        "note": "View all attestations at the verification page"
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
