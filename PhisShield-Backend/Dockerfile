FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y curl

COPY requirements.txt ./
RUN python - <<'PY'
from pathlib import Path

skip = {"torch", "transformers", "datasets", "accelerate", "shap", "lime"}
runtime_requirements = []
for raw_line in Path("requirements.txt").read_text(encoding="utf-8").splitlines():
	line = raw_line.strip()
	if not line or line.startswith("#"):
		continue
	package_name = line.split("==", 1)[0].split(">=", 1)[0].split("<=", 1)[0].split("[", 1)[0].strip().lower()
	if package_name in skip:
		continue
	runtime_requirements.append(raw_line)

Path("/tmp/runtime-requirements.txt").write_text("\n".join(runtime_requirements) + "\n", encoding="utf-8")
PY
RUN pip install --no-cache-dir -r /tmp/runtime-requirements.txt

COPY . .

EXPOSE 8000

HEALTHCHECK CMD curl --fail http://localhost:8000/health || exit 1

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
