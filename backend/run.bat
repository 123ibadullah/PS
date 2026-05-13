@echo off
setlocal

py -3.12 -m pip install -r requirements.txt
if not exist model.pkl py -3.12 train_model.py
py -3.12 -m uvicorn main:app --reload --host 127.0.0.1 --port 8000

endlocal
