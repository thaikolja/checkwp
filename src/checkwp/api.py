# Copyright (c) 2024 checkwp authors and contributors

"""
FastAPI entry point for the checkwp web API.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import uuid
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from checkwp import __version__
from checkwp.ai.analyzer import AIAnalyzer
from checkwp.cli import DEFAULT_AI_ENDPOINT, resolve_ai_endpoint
from checkwp.report.generator import generate_html_report, generate_json_report
from checkwp.scanner.engine import Scanner

# Configuration for persistent report storage
REPORTS_DIR = Path(os.environ.get("CHECKWP_REPORTS_DIR", "reports")).resolve()
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Initialize the main FastAPI application instance
app = FastAPI(
    # Set the visible title of the API
    title="CheckWP API",
    # Set the API description
    description="Scan WordPress plugins for malware, backdoors, and common security vulnerabilities.",
    # Set version
    version=__version__,
)

# Enable CORS for cross-domain requests from the Nuxt front end
app.add_middleware(
    CORSMiddleware,
    # In a production environment, you should restrict this to your Nuxt app's domain
    allow_origins=os.environ.get("CHECKWP_CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount the reports directory to serve static HTML files
app.mount("/static/reports", StaticFiles(directory=str(REPORTS_DIR)), name="reports")


# Define a lightweight service index for automation and docs links
@app.get("/")
def api_index() -> dict[str, object]:
    """Return a lightweight service index for automation and docs links."""
    return {
        "service":             "checkwp-api",
        "version":             __version__,
        "docs":                "/docs",
        "openapi":             "/openapi.json",
        "health":              "/health",
        "scan":                "/scan",
        "default_ai_endpoint": DEFAULT_AI_ENDPOINT,
    }


# Define a health check endpoint for monitoring
@app.get("/health")
def health_check() -> dict[str, str]:
    """Simple endpoint to verify the service is running."""
    # Return a status dictionary
    return {"status": "ok", "service": "checkwp-api", "version": __version__}


# Explicitly return the API version
@app.get("/version")
def version() -> dict[str, str]:
    """Return the API version explicitly."""
    return {"version": __version__}


# Define the main scan endpoint for file uploads
@app.post("/scan")
async def scan_plugin(
    # Handle the multipart ZIP file upload
    file: UploadFile = File(...),
    # Optional API key to enable AI verification
    ai_key: str | None = Query(default=None, description="Enable AI verification with this key."),
    # AI endpoint URL
    ai_endpoint: str = Query(
        default=DEFAULT_AI_ENDPOINT,
        description="OpenAI-compatible base URL. Defaults to OpenAI.",
    ),
    # AI model to use
    ai_model: str = Query(default="gpt-4o", description="Model to use for AI verification."),
    # AI temperature setting
    ai_temperature: float = Query(default=0.1, ge=0.0, le=2.0),
    # Requested output format
    format: str = Query(default="json", pattern="^(json|html)$"),
    # Enable deep/offline heuristics during the scan
    deep: bool = Query(default=True, description="Enable deep/offline heuristics during the scan."),
    # Number of threads for scanning
    threads: int = Query(default=4, ge=1, le=64),
) -> JSONResponse:
    """
    Ingest a ZIP file, validate it, and return a JSON envelope or stored HTML report.
    """
    # Ensure the upload has a usable filename before further validation
    if not file.filename:
        # Raise bad request error if the filename is missing
        raise HTTPException(status_code=400, detail="Uploaded file must include a filename.")

    # Verify the uploaded file has a .zip extension
    if not file.filename.lower().endswith(".zip"):
        # Raise bad request error if not a ZIP
        raise HTTPException(status_code=400, detail="Only .zip files are supported.")

    # Create a unique temporary directory for this request
    temp_dir = tempfile.mkdtemp(prefix="checkwp_api_")
    # Build the path where the ZIP will be saved
    zip_path = Path(temp_dir) / Path(file.filename).name

    try:
        # Open the local file for binary writing
        with zip_path.open("wb") as buffer:
            # Stream the uploaded content to the disk
            while chunk := file.file.read(1024 * 64):
                # Write the current upload chunk to disk
                buffer.write(chunk)

        # Initialize the scanner engine with the saved ZIP
        scanner = Scanner(
            # Target the uploaded ZIP
            target_path=str(zip_path),
            # Enable deep scanning as requested
            deep_scan=deep,
            # Use the specified number of threads
            threads=threads
        )

        # Perform the scan
        result = scanner.scan()

        # Surface fatal scan errors as clean HTTP responses instead of returning broken reports
        fatal_error = next(
            (
                error
                for error in result.errors
                if error.startswith(
                (
                    "Invalid WordPress plugin:",
                    "Invalid ZIP archive:",
                    "Failed to extract ZIP:",
                    "No scannable files found",
                    "Target must be a directory or a valid .zip file.",
                )
            )
            ),
            None,
        )
        if fatal_error:
            raise HTTPException(status_code=400, detail=fatal_error)

        # Determine effective API key, prioritizing explicit, env var, then legacy AI key
        effective_ai_key = ai_key or os.environ.get("CHECKWP_API_KEY") or os.environ.get("CHECKWP_AI_KEY")
        if effective_ai_key:
            try:
                # Resolve the base URL for the API provider
                base_url = resolve_ai_endpoint(ai_endpoint)
                # Initialize AI analyzer for this request
                analyzer = AIAnalyzer(
                    # Set key
                    api_key=effective_ai_key,
                    # Set model
                    model=ai_model,
                    # Set base URL
                    base_url=base_url,
                    # Set temperature
                    temperature=ai_temperature,
                )
                # Verify connectivity before spending time on batch analysis
                analyzer.check_connection()
                # Run deep analysis on findings
                result = analyzer.analyze_findings(result)
                # Record metadata
                result.ai_model = ai_model
                # Record estimated token usage
                result.ai_tokens = len(result.findings) * 850 + 1200
            except ValueError as exc:
                # Handle value errors from the AI analyzer as client-side issues
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            except Exception as exc:
                # Degrade gracefully and return the scan result with a clear warning
                result.errors.append(f"AI analysis failed: {exc}")

        # Determine how to return the results based on the format parameter
        if format == "html":
            # Generate the HTML string using the sleek theme
            html_content = generate_html_report(result)

            # Generate a unique ID for persistent storage
            report_id = str(uuid.uuid4())
            report_filename = f"{report_id}.html"
            report_path = REPORTS_DIR / report_filename

            # Save the report to the persistent directory
            report_path.write_text(html_content, encoding="utf-8")

            # Return wrapped in a JSON envelope with the report ID and static URL
            return JSONResponse(
                content={
                    "html":       html_content,
                    "report_id":  report_id,
                    "report_url": f"/static/reports/{report_filename}",
                    "summary":    json.loads(generate_json_report(result))["summary"],
                }
            )

        # Default to JSON format
        json_report = generate_json_report(result)
        # Return as raw JSON object for front-end consumption
        return JSONResponse(content=json.loads(json_report))
    finally:
        # Close the uploaded file handle if it is still open
        await file.close()
        # Always clean up temporary files regardless of success or failure
        shutil.rmtree(temp_dir, ignore_errors=True)


def run() -> None:
    """Run the API with uvicorn for local or packaged deployments."""
    import uvicorn

    uvicorn.run(
        "checkwp.api:app",
        host=os.environ.get("CHECKWP_API_HOST", "127.0.0.1"),
        port=int(os.environ.get("CHECKWP_API_PORT", "8000")),
        reload=False,
    )
