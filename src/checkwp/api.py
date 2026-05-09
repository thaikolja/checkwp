"""
FastAPI entry point for the checkwp Web Interface API.
This module provides the backend infrastructure for the Nuxt-based front end.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import uuid
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from checkwp.ai.analyzer import AIAnalyzer
from checkwp.report.generator import generate_html_report, generate_json_report
from checkwp.scanner.engine import Scanner

# Initialize the main FastAPI application instance
app = FastAPI(
    # Set the visible title of the API
    title="CheckWP API",
    # Set the API description
    description="API for scanning WordPress plugin ZIP files.",
    # Set version
    version="1.0.0",
)

# Enable CORS for cross-domain requests from the Nuxt front end
app.add_middleware(
    CORSMiddleware,
    # In a production environment, you should restrict this to your Nuxt app's domain
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration for persistent report storage
REPORTS_DIR = os.environ.get("CHECKWP_REPORTS_DIR", "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# Mount the reports directory to serve static HTML files
app.mount("/static/reports", StaticFiles(directory=REPORTS_DIR), name="reports")


# Define a health check endpoint for monitoring
@app.get("/health")
def health_check():
    """Simple endpoint to verify the service is running."""
    # Return a status dictionary
    return {"status": "ok", "service": "checkwp-api"}


# Define the main scan endpoint for file uploads
@app.post("/scan")
async def scan_plugin(
    # Handle the multipart ZIP file upload
    file: UploadFile = File(...),
    # Optional flag to enable AI analysis
    ai_enabled: bool = False,
    # Optional API key for AI provider
    ai_key: str | None = None,
    # Preferred AI model name
    ai_model: str = "gpt-4.1",
    # Requested output format
    format: str = "json"
):
    """
    Ingest a ZIP file, validate its content, and perform a security scan.
    Returns either a detailed JSON report or pre-rendered HTML content.
    """
    # Ensure the upload has a usable filename before further validation
    if not file.filename:
        # Raise bad request error if the filename is missing
        raise HTTPException(status_code=400, detail="Uploaded file must include a filename.")

    # Verify the uploaded file has a .zip extension
    if not file.filename.lower().endswith(".zip"):
        # Raise bad request error if not a ZIP
        raise HTTPException(status_code=400, detail="Only .zip files are supported.")

    # Validate the requested output format explicitly
    if format not in {"json", "html"}:
        # Raise bad request error for unsupported response formats
        raise HTTPException(status_code=400, detail="Format must be either 'json' or 'html'.")

    # Create a unique temporary directory for this request
    temp_dir = tempfile.mkdtemp()
    # Build the path where the ZIP will be saved
    zip_path = os.path.join(temp_dir, Path(file.filename).name)

    try:
        # Open the local file for binary writing
        with open(zip_path, "wb") as buffer:
            # Stream the uploaded content to the disk
            while chunk := file.file.read(1024 * 64):
                # Write the current upload chunk to disk
                buffer.write(chunk)

        # Initialize the scanner engine with the saved ZIP
        scanner = Scanner(
            # Target the uploaded ZIP
            target_path=zip_path,
            # Force deep scanning for web uploads
            deep_scan=True,
            # Use 4 parallel threads
            threads=4
        )

        # Perform the scan
        result = scanner.scan()

        # Surface fatal scan errors as clean HTTP responses instead of returning broken reports
        if result.errors:
            # Report invalid plugin packages as a client-side validation problem
            if any(error.startswith("Invalid WordPress plugin:") for error in result.errors):
                raise HTTPException(status_code=400, detail=result.errors[0])
            # Report archive extraction failures as bad uploads
            if any(
                error.startswith(prefix)
                for prefix in ("Invalid ZIP archive:", "Failed to extract ZIP:", "No scannable files found")
                for error in result.errors
            ):
                raise HTTPException(status_code=400, detail=result.errors[0])

        # Perform AI processing if the feature was requested
        if ai_enabled:
            # Determine API key priority
            api_key = ai_key or os.environ.get("CHECKWP_AI_KEY")
            # Ensure we have a key to work with
            if not api_key:
                # Return configuration error
                raise HTTPException(status_code=400, detail="AI enabled but no AI key provided.")

            try:
                # Initialize AI analyzer for this request
                analyzer = AIAnalyzer(
                    # Set key
                    api_key=api_key,
                    # Set model
                    model=ai_model,
                )
                # Verify connectivity before spending time on batch analysis
                analyzer.check_connection()
                # Run deep analysis on findings
                result = analyzer.analyze_findings(result)
                # Record metadata
                result.ai_model = ai_model
                # Record estimated token usage
                result.ai_tokens = len(result.findings) * 850 + 1200
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
            report_path = os.path.join(REPORTS_DIR, report_filename)

            # Save the report to the persistent directory
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(html_content)

            # Return wrapped in a JSON envelope with the report ID and static URL
            return JSONResponse(
                content={
                    "html":       html_content,
                    "report_id":  report_id,
                    "report_url": f"/static/reports/{report_filename}"
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
