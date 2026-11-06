```bat
@echo off
title FraudFathom

cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    python -m venv .venv
)

call .venv\Scripts\activate

python -m pip install -r requirements.txt

where swipl >nul 2>nul
if errorlevel 1 (
    echo WARNING: SWI-Prolog is not installed or not available in PATH.
    echo Please install SWI-Prolog before using the analysis feature.
    pause
    exit /b 1
)

streamlit run app.py
```