FROM python:3.11-slim

WORKDIR /app

# Tkinter + GUI deps (needed because main.py uses tkinter)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-tk tk \
    libx11-6 libxext6 libxrender1 libxtst6 libxi6 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "main.py"]
