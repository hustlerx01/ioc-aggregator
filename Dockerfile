FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir stix2
ENTRYPOINT ["python", "-m", "iocagg.cli"]
CMD ["--fetch", "-o", "results"]
