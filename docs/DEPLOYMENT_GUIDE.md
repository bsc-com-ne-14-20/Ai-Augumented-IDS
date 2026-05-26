# AA-IDS Deployment Guide

## 1. Prerequisites
- Python 3.9+
- SQLite (for development) or PostgreSQL (for production)
- DigitalOcean Droplet (Ubuntu 22.04 recommended for production)

## 2. Environment Configuration

Copy the `.env.example` file to `.env`:
```bash
cp .env.example .env
```

Configure the following key environment variables:
- `IDS_API_KEY`: A strong secret key used for authentication from Django middleware.
- `FLASK_SECRET_KEY`: Flask session secret key.
- `SOCKETIO_CORS_ORIGINS`: Origins allowed to connect via WebSocket (e.g., `http://localhost:3000` for Flutter dashboard).
- `ML_MODEL_PATH`, `ML_SCALER_PATH`, `ML_FEATURE_NAMES_PATH`: Paths to the serialized ML models.
- `DB_PATH`: Database URI (e.g., `sqlite:///ids.db` or `postgresql://user:pass@localhost/ids`).

## 3. Database Setup
The system uses SQLAlchemy. On first startup, the required tables (Alert, Statistics) will be automatically created.
- **Development**: Use SQLite (default config)
- **Production**: Update the `DB_PATH` variable to point to a managed PostgreSQL database instance.

## 4. ML Model Deployment
Ensure the pre-trained ML models are serialized as `.joblib` and `.pkl` files and placed in the correct directories:
- Random Forest Model: `models/rf_model.joblib`
- XGBoost Model: `models/xgb_model.joblib`
- Scaler: `data/final/scaler.pkl`
- Feature Names: `data/final/feature_names.txt`

## 5. Startup Instructions

### Local Development:
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

### Production Deployment (DigitalOcean):
1. **Provision Droplet**: Ubuntu 22.04 LTS.
2. **Clone Repo**: Clone the repository to `/var/www/aa-ids`.
3. **Set up Environment**: Create virtual environment, install requirements.
4. **Configure systemd**: Create a systemd service file to run Gunicorn.
```ini
[Unit]
Description=Gunicorn instance to serve AA-IDS Backend
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/aa-ids
Environment="PATH=/var/www/aa-ids/venv/bin"
ExecStart=/var/www/aa-ids/venv/bin/gunicorn -k eventlet -w 1 --bind 127.0.0.1:5000 "app:create_app()"

[Install]
WantedBy=multi-user.target
```
5. **Reverse Proxy (Nginx)**: Configure Nginx to forward requests to `127.0.0.1:5000` and handle WebSocket upgrades.
```nginx
location /socket.io {
    proxy_pass http://127.0.0.1:5000/socket.io;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "Upgrade";
}
```

## 6. Monitoring and Logging
The application uses structured logging. Logs are printed to `stdout` by default. Use `journalctl -u aa-ids` to view logs in production. Ensure that `ERROR` level events are monitored via your preferred logging solution (e.g., Datadog, ELK).
