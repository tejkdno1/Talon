FROM mcr.microsoft.com/playwright/python:v1.58.0-jammy

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY talon_v1.py /app/talon_v1.py

# Keep runtime output outside image layers.
RUN mkdir -p /app/evidence

ENTRYPOINT ["python", "/app/talon_v1.py"]
