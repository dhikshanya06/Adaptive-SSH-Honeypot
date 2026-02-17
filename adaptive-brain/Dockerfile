FROM python:3.11-slim

WORKDIR /app

COPY adaptive-brain/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire src directory to preserve structure
COPY src /app/src

# Set python path so imports work as if running from root
ENV PYTHONPATH=/app/src

CMD ["python3", "-u", "/app/src/cowrie/adaptive/live_adaptive_controller.py"]
