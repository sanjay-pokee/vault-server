# =============================================================================
# Dockerfile — vault-server (FastAPI)
# =============================================================================
# WHAT THIS DOES:
#   Packages the vault-server into a Docker container so it can run
#   anywhere — locally, on a cloud VM, or in a container service.
#
# HOW TO USE LOCALLY:
#   docker build -t vault-server .
#   docker run -p 8000:8000 vault-server
#
# The server will be available at http://localhost:8000
# =============================================================================

FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

# Copy requirements first (Docker caches this layer if requirements don't change)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# The server listens on port 8000
EXPOSE 8000

# Start the FastAPI server with uvicorn
CMD ["uvicorn", "server.api:app", "--host", "0.0.0.0", "--port", "8000"]
