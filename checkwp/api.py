"""
FastAPI entry point for the checkwp Web Interface API.
This module provides the backend infrastructure for the Nuxt-based front end.
"""

# Import os for environment and path management
import os
# Import shutil for file copying and cleanup
import shutil
# Import tempfile for managing uploaded ZIPs
import tempfile
# Import Optional for type safety
from typing import Optional

# Import FastAPI components for web request handling
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
# Import JSONResponse for structured API returns
from fastapi.responses import JSONResponse

# Import scanner engine to process plugins
from checkwp.scanner.engine import Scanner
# Import AI analyzer for deep verification
from checkwp.ai.analyzer import AIAnalyzer
# Import report generators for final output
from checkwp.report.generator import generate_json_report, generate_html_report

# Initialize the main FastAPI application instance
app = FastAPI(
    # Set the visible title of the API
    title="WordPress Plugin Security Checker API",
    # Set the API description
    description="API for scanning WordPress plugin ZIP files.",
    # Set version
    version="1.0.0",
)

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
    ai_key: Optional[str] = None,
    # Preferred AI model name
    ai_model: str = "gpt-4o",
    # Requested output format
    format: str = "json"
):
    """
    Ingest a ZIP file, validate its content, and perform a security scan.
    Returns either a detailed JSON report or pre-rendered HTML content.
    """
    # Verify the uploaded file has a .zip extension
    if not file.filename.endswith(".zip"):
        # Raise bad request error if not a ZIP
        raise HTTPException(status_code=400, detail="Only .zip files are supported.")

    # Create a unique temporary directory for this request
    temp_dir = tempfile.mkdtemp()
    # Build the path where the ZIP will be saved
    zip_path = os.path.join(temp_dir, file.filename)
    
    try:
        # Open the local file for binary writing
        with open(zip_path, "wb") as buffer:
            # Stream the uploaded content to the disk
            shutil.copyfileobj(file.file, buffer)
            
        # Initialize the scanner engine with the saved ZIP
        scanner = Scanner(
            # Target the uploaded ZIP
            target_path=zip_path,
            # Force deep scanning for web uploads
            deep_scan=True,
            # Use 4 parallel threads
            threads=4
        )
        
        # Execute the scan and handle potential validation errors
        try:
            # Perform the scan
            result = scanner.scan()
        except Exception as e:
            # Check if the error is related to plugin structure
            if "Not a valid WordPress plugin directory" in str(e) or "No valid WordPress plugin header" in str(e):
                # Return validation error to client
                raise HTTPException(status_code=400, detail="The uploaded ZIP is not a valid WordPress plugin.")
            # Handle unexpected engine errors
            raise HTTPException(status_code=500, detail=str(e))
            
        # Perform AI processing if the feature was requested
        if ai_enabled:
            # Determine API key priority
            api_key = ai_key or os.environ.get("CHECKWP_AI_KEY")
            # Ensure we have a key to work with
            if not api_key:
                # Return configuration error
                raise HTTPException(status_code=400, detail="AI enabled but no AI key provided.")
                
            # Initialize AI analyzer for this request
            analyzer = AIAnalyzer(
                # Set key
                api_key=api_key,
                # Set model
                model=ai_model
            )
            # Run deep analysis on findings
            result = analyzer.analyze_findings(result)
            # Record metadata
            result.ai_model = ai_model
            # Record estimated token usage
            result.ai_tokens = len(result.findings) * 850 + 1200
            
        # Determine how to return the results based on the format parameter
        if format == "html":
            # Generate the HTML string using the sleek theme
            html_content = generate_html_report(result)
            # Return wrapped in a JSON envelope
            return JSONResponse(content={"html": html_content})
            
        # Default to JSON format
        json_report = generate_json_report(result)
        # Import json module to decode the string
        import json
        # Return as raw JSON object for front-end consumption
        return JSONResponse(content=json.loads(json_report))

    finally:
        # Always clean up temporary files regardless of success or failure
        shutil.rmtree(temp_dir, ignore_errors=True)
