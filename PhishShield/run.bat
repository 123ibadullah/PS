@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "ROOT=%~dp0"
set "BACKEND_DIR=%ROOT%..\PhisShield-Backend"
set "FRONTEND_DIR=%ROOT%artifacts\phishshield"

if not exist "%BACKEND_DIR%\main.py" (
  echo [ERROR] FastAPI backend not found at "%BACKEND_DIR%".
  pause
  exit /b 1
)

if not exist "%FRONTEND_DIR%\package.json" (
  echo [ERROR] Frontend app not found at "%FRONTEND_DIR%".
  pause
  exit /b 1
)

set "BACKEND_HEALTH_URL=http://127.0.0.1:8000/health"
set "FRONTEND_URL=http://127.0.0.1:5173"

echo Starting PhishShield AI...
echo.
echo   Frontend: http://localhost:5173
echo   Backend : http://localhost:8000
echo.

powershell -NoProfile -Command "try { $r = Invoke-WebRequest -UseBasicParsing -Uri '%BACKEND_HEALTH_URL%' -TimeoutSec 3; if ($r.StatusCode -eq 200) { exit 0 } else { exit 1 } } catch { exit 1 }"
if not errorlevel 1 goto backend_ready

for /f "tokens=5" %%P in ('netstat -ano ^| findstr /R /C:":8000 .*LISTENING"') do (
  echo [INFO] Releasing stale process on port 8000 - PID %%P...
  taskkill /PID %%P /F >nul 2>&1
)
start "PhishShield Backend" cmd /k "cd /d ""%BACKEND_DIR%"" && py -3.12 -m uvicorn main:app --reload --port 8000"
timeout /t 3 >nul
goto frontend_check

:backend_ready
echo [INFO] Backend already running. Reusing existing service on port 8000.

:frontend_check
powershell -NoProfile -Command "try { $r = Invoke-WebRequest -UseBasicParsing -Uri '%FRONTEND_URL%' -TimeoutSec 3; if ($r.StatusCode -ge 200) { exit 0 } else { exit 1 } } catch { exit 1 }"
if not errorlevel 1 goto frontend_ready

start "PhishShield Frontend" cmd /k "cd /d ""%FRONTEND_DIR%"" && pnpm dev"
goto done

:frontend_ready
echo [INFO] Frontend already running. Reusing existing Vite server.

:done
echo Frontend: http://localhost:5173
echo Backend:  http://localhost:8000
echo Launch sequence complete.
endlocal
