# Prompt Firewall MVP

A serverless AI security solution that intercepts LLM prompts and responses to detect and mitigate security risks including PII/PHI exposure and prompt injection attacks.

## 🎯 Overview

The Prompt Firewall is designed to:
- **Detect** sensitive data (PII/PHI) in prompts and responses
- **Block** or **redact** prompt injection attempts
- **Log** all security events for audit and analysis
- **Provide** clear explanations for security decisions

## 🏗️ Architecture

- **Backend**: FastAPI (Python) - Serverless on GCP Cloud Run
- **Frontend**: Next.js (React) - Public demo UI and admin console
- **Database**: PostgreSQL (Cloud SQL or managed service)
- **SDK**: Python SDK for easy integration
- **Infrastructure**: Terraform for IaC

## 📁 Project Structure

```
.
├── backend/          # FastAPI backend application
│   ├── app/         # Application code
│   └── tests/       # Test suite
├── frontend/        # Next.js frontend application
├── sdk/             # Python SDK
├── infrastructure/  # Terraform/IaC configurations
└── docs/            # Documentation

```

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- PostgreSQL 14+
- GCP account (for deployment)

### Local Development

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd cloudmatos
   ```

2. **Set up backend**
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Run database migrations**
   ```bash
   alembic upgrade head
   ```

5. **Start backend server**
   ```bash
   uvicorn app.main:app --reload
   ```

6. **Set up frontend**
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

## 📚 Documentation

- [Requirements](memory-bank/features/feature-prompt-firewall/requirements.md)
- [Implementation Plan](memory-bank/features/feature-prompt-firewall/implementation_plan.md)
- [API Documentation](docs/api.md) (Coming soon)
- [Deployment Guide](docs/DEPLOY.md) (Coming soon)
- [Architecture Diagram](docs/architecture.png) (Coming soon)
- [Threat Model](docs/threat-model.md) (Coming soon)

## 🧪 Testing

```bash
# Backend tests
cd backend
pytest

# Frontend tests
cd frontend
npm test
```

## 📊 API Endpoints

- `POST /v1/query` - Process prompts and responses
- `GET /v1/policy` - Retrieve policy rules
- `PUT /v1/policy` - Update policy rules (admin)
- `GET /v1/logs` - Fetch logs with filtering
- `GET /v1/health` - Health check

## 🔒 Security Features

- PII/PHI Detection (emails, SSNs, phone numbers, medical data)
- Prompt Injection Detection
- Policy-based actions (Block, Redact, Warn)
- Secure authentication for admin endpoints
- Audit logging

## 💰 Cost Estimate

Estimated monthly cost: <$50 for simulated traffic
- Cloud Run: ~$10-20
- Cloud SQL: ~$20-30
- Storage/Logging: ~$5-10

## 📝 License

[To be determined]

## 🤝 Contributing

[To be determined]

