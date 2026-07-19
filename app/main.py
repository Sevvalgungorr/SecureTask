from fastapi import FastAPI

app = FastAPI(
    title="SecureTask",
    description="OAuth2 ve OpenID Connect destekli güvenli görev yönetim sistemi",
    version="0.1.0",
)


@app.get("/")
def home():
    return {
        "application": "SecureTask",
        "message": "SecureTask API çalışıyor.",
        "status": "ok",
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"} 