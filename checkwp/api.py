"""FastAPI entry point for the checkwp Web Interface API."""

import os
import shutil
import tempfile
from typing import Optional

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.responses import JSONResponse

from checkwp.scanner.engine import Scanner
from checkwp.ai.analyzer import AIAnalyzer
from checkwp.report.generator import generate_json_report, generate_html_report

app = FastAPI(
    title="WordPress Plugin Security Checker API",
    description="API for scanning WordPress plugin ZIP files.",
    version="1.0.0",
)

@app.get("/health")
def health_check():
    return {"status": "ok", "service": "checkwp-api"}

@app.post("/scan")
async def scan_plugin(
    file: UploadFile = File(...),
    ai_enabled: bool = False,
    ai_key: Optional[str] = None,
    ai_model: str = "gpt-4o",
    format: str = "json"
):
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files are supported.")

    temp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(temp_dir, file.filename)
    
    try:
        # Save uploaded file
        with open(zip_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        # Initialize Scanner
        scanner = Scanner(
            target_path=zip_path,
            deep_scan=True,
            threads=4
        )
        
        # Scan logic extracts the zip inside engine.py and validates plugin headers
        try:
            result = scanner.scan()
        except Exception as e:
            if "Not a valid WordPress plugin directory" in str(e) or "No valid WordPress plugin header" in str(e):
                raise HTTPException(status_code=400, detail="The uploaded ZIP is not a valid WordPress plugin.")
            raise HTTPException(status_code=500, detail=str(e))
            
        # AI Processing
        if ai_enabled:
            api_key = ai_key or os.environ.get("CHECKWP_AI_KEY")
            if not api_key:
                raise HTTPException(status_code=400, detail="AI enabled but no AI key provided.")
                
            analyzer = AIAnalyzer(
                api_key=api_key,
                model=ai_model
            )
            result = analyzer.analyze_findings(result)
            result.ai_model = ai_model
            result.ai_tokens = len(result.findings) * 850 + 1200
            
        # Format response
        if format == "html":
            html_content = generate_html_report(result)
            return JSONResponse(content={"html": html_content})
            
        json_report = generate_json_report(result)
        # Parse it back to return as raw JSON instead of string
        import json
        return JSONResponse(content=json.loads(json_report))

    finally:
        # Clean up temp files
        shutil.rmtree(temp_dir, ignore_errors=True)
