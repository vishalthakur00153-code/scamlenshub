import os
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.models import MessageScanRequest, UrlScanRequest, ScanResult
from app.engine import analyze_message, analyze_url

app = FastAPI(
    title="ScamLens API",
    description="A transparent, rule-based scam indicator detection engine.",
    version="1.0.0",
)

# Enable Cross-Origin Resource Sharing (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    serializable_errors = []
    for err in exc.errors():
        serializable_errors.append({
            "loc": [str(x) for x in err.get("loc", [])],
            "msg": str(err.get("msg", "")),
            "type": str(err.get("type", "")),
        })
    first_msg = serializable_errors[0]["msg"] if serializable_errors else "Invalid input data."
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": first_msg, "errors": serializable_errors},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An unexpected error occurred while analyzing the input."},
    )


@app.get("/health", summary="Health check")
@app.get("/api/health", summary="API health check")
def health_check():
    """Returns the operational status of the ScamLens detection engine."""
    return {
        "status": "healthy",
        "service": "ScamLens",
        "version": "1.0.0",
        "storage": "stateless (no user inputs stored)",
    }


@app.post("/api/scan/message", response_model=ScanResult, summary="Scan text message")
def scan_message_endpoint(payload: MessageScanRequest):
    """
    Accepts raw text (internship offer, lottery notification, SMS, etc.)
    and detects transparent rule-based scam indicators.
    Privacy note: Input text is never persisted or logged.
    """
    try:
        return analyze_message(payload.text)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error evaluating message: {str(exc)}",
        )


@app.post("/api/scan/url", response_model=ScanResult, summary="Scan URL structure")
def scan_url_endpoint(payload: UrlScanRequest):
    """
    Accepts a web URL and performs static structural analysis without fetching the remote server.
    Privacy note: URL is never visited or persisted.
    """
    try:
        return analyze_url(payload.url)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error evaluating URL: {str(exc)}",
        )


# Mount frontend static files
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
