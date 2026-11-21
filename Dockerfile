FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
# Hosts like Render/Railway/Fly inject $PORT; default 8501 locally.
EXPOSE 8501
HEALTHCHECK CMD python -c "import urllib.request,os;urllib.request.urlopen('http://localhost:'+os.getenv('PORT','8501')+'/_stcore/health')"
CMD ["sh", "-c", "streamlit run agentshield/app.py --server.port=${PORT:-8501} --server.address=0.0.0.0"]
