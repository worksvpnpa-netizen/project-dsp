# FOSS IoT Security Tool Dockerfile
# Maintainer: flatmarstheory (GitHub/BMAC)
# https://github.com/flatmarstheory

FROM python:3.10-slim

# Set up a non-root user for security
RUN useradd -ms /bin/bash iotuser
USER iotuser
WORKDIR /home/iotuser/app

# Copy requirements and install dependencies
COPY --chown=iotuser:iotuser requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the code
COPY --chown=iotuser:iotuser . .

# Expose no ports (GUI app)

# Entry point: run the PyQt5 GUI
CMD ["python", "main.py"] 