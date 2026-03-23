from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import auth, scans, dashboard
from app.core.database import Base, engine

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="ForensiQ API",
    description="Web security testing & digital forensics platform",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api")
app.include_router(scans.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")


@app.get("/")
def root():
    return {"status": "ok", "app": "ForensiQ", "version": "1.0.0"}


@app.get("/health")
def health():
    return {"status": "healthy"}
