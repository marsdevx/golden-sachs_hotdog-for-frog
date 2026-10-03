FROM python:3.12-slim
WORKDIR /service
COPY pyproject.toml ./
COPY firewall_app ./firewall_app
RUN pip install --no-cache-dir .
EXPOSE 8001
CMD ["uvicorn", "firewall_app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8001"]
