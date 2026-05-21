@echo off
setlocal

set "PYEXE=..\.venv\Scripts\python.exe"
if exist "%PYEXE%" (
  "%PYEXE%" -m pip install -r requirements.txt
  if not exist model.pkl "%PYEXE%" train_model.py
  "%PYEXE%" -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
) else (
  py -3.12 -m pip install -r requirements.txt
  if not exist model.pkl py -3.12 train_model.py
  py -3.12 -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
)

endlocal
