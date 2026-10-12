FROM python:3.12-slim
WORKDIR /app
# gdal-bin provides ogr2ogr, used by the admin shapefile-upload feature to load a new layer
# the same way it would be loaded by hand from a terminal.
RUN apt-get update && apt-get install -y --no-install-recommends gdal-bin && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
