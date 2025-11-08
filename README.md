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

## 🛠️ Tech Stack

### Backend
- **Language**: Python 3.11+
- **Framework**: FastAPI 0.104+
- **Database**: PostgreSQL 15 (via SQLAlchemy 2.0)
- **ORM**: SQLAlchemy
- **Migrations**: Alembic
- **Authentication**: JWT (python-jose)
- **Password Hashing**: bcrypt (passlib)
- **Container**: Docker

### Frontend
- **Framework**: Next.js 16
- **Language**: TypeScript
- **UI Library**: React 19
- **Styling**: Tailwind CSS 4
- **Deployment**: Vercel

### Infrastructure
- **Compute**: Google Cloud Run (serverless containers)
- **Database**: Google Cloud SQL (PostgreSQL)
- **Secrets**: Google Secret Manager
- **Container Registry**: Google Container Registry
- **IaC**: Terraform
- **CI/CD**: Cloud Build (optional)

### SDK
- **Language**: Python 3.8+
- **HTTP Client**: httpx
- **Package Manager**: setuptools

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

#### Option 1: Using Docker Compose (Recommended)

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd cloudmatos
   ```

2. **Start services with Docker Compose**
   ```bash
   docker-compose up -d
   ```

3. **Initialize database**
   ```bash
   # Run migrations
   docker-compose exec backend alembic upgrade head
   
   # Initialize default data (creates admin users and policy rules)
   docker-compose exec backend python -m app.init_db
   ```

   This will create two admin users:
   - **Admin**: `admin` / `admin123`
   - **Test Admin**: `testadmin` / `test123`

4. **Access services**
   - Backend API: http://localhost:8000
   - API Docs: http://localhost:8000/docs
   - Database: localhost:5432

5. **Set up frontend** (in a separate terminal)
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

6. **Stop services**
   ```bash
   docker-compose down
   ```

#### Option 2: Manual Setup

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

3. **Set up PostgreSQL database**
   - Install PostgreSQL locally or use Docker:
     ```bash
     docker run -d --name postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=prompt_firewall -p 5432:5432 postgres:15-alpine
     ```

4. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   DATABASE_URL=postgresql://postgres:postgres@localhost:5432/prompt_firewall
   ```

5. **Run database migrations**
   ```bash
   alembic upgrade head
   ```

6. **Start backend server**
   ```bash
   uvicorn app.main:app --reload
   ```

7. **Set up frontend**
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

## 📚 Documentation

- [Requirements](memory-bank/features/feature-prompt-firewall/requirements.md)
- [Implementation Plan](memory-bank/features/feature-prompt-firewall/implementation_plan.md)
- [Deployment Guide](DEPLOY.md) - Complete deployment instructions
- [Architecture Diagram](docs/architecture.md) - System architecture and data flow
- [Threat Model](docs/threat-model.md) - Security threats, risks, and mitigations
- [SDK Documentation](sdk/README.md) - Python SDK usage and integration examples
- **API Documentation**: 
  - Swagger UI: Available at `/docs` endpoint (production: https://cloudmatos-ai-security-engineer-803270031211.europe-west1.run.app/docs)
  - OpenAPI JSON: Available at `/openapi.json` endpoint
  - ReDoc: Available at `/redoc` endpoint

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

### API Documentation

- **Swagger UI**: Available at `/docs` endpoint
- **ReDoc**: Available at `/redoc` endpoint
- **OpenAPI JSON**: Available at `/openapi.json` endpoint

**Production API Documentation:**
- Backend API Docs: https://cloudmatos-ai-security-engineer-803270031211.europe-west1.run.app/docs

## ☁️ Cloud Configuration

### Production Deployment

The application is deployed in a cloud-native architecture:

#### Backend Service
- **Platform**: Google Cloud Platform (GCP) Cloud Run
- **Deployment**: Docker container image
- **Region**: Europe-West1
- **Scaling**: Auto-scaling serverless containers (0-10 instances)
- **API URL**: https://cloudmatos-ai-security-engineer-803270031211.europe-west1.run.app
- **API Documentation**: https://cloudmatos-ai-security-engineer-803270031211.europe-west1.run.app/docs

#### Database
- **Service**: Google Cloud SQL
- **Database Engine**: PostgreSQL 15
- **Connection**: Private IP connection from Cloud Run
- **Backup**: Automated daily backups enabled

#### Frontend Service
- **Platform**: Vercel
- **Framework**: Next.js
- **URL**: https://cloud-matos-ai-security-engineer-xr.vercel.app/
- **Features**: Automatic deployments, CDN, SSL/TLS

#### Infrastructure Components
- **Secrets Management**: Google Secret Manager (database credentials, JWT secrets)
- **Container Registry**: Google Container Registry (Docker images)
- **Monitoring**: Cloud Logging and Cloud Monitoring


### Integration Example

**5-Line SDK Integration:**
```python
from prompt_firewall_sdk import PromptFirewallClient
client = PromptFirewallClient(base_url="http://localhost:8000")
result = client.query(prompt="My email is user@example.com")
if result['decision'] == 'block':
    raise ValueError("Request blocked by firewall")
print(result['explanation'])
```

See [SDK Documentation](sdk/README.md) for more examples.

## 🔒 Security Features

- PII/PHI Detection (emails, SSNs, phone numbers, medical data)
- Prompt Injection Detection
- Policy-based actions (Block, Redact, Warn)
- Secure authentication for admin endpoints
- Audit logging

## 💰 Cost Estimate

Estimated monthly cost: **$15-50/month** for MVP scale (< 10,000 requests/day)
- Cloud Run (Backend): ~$5-15
- Cloud SQL (PostgreSQL): ~$7-10
- Secret Manager: ~$0.06
- Frontend Hosting (Vercel): Free tier or ~$20/month
- Cloud Build (CI/CD): ~$1-5

See [DEPLOY.md](DEPLOY.md) for detailed cost breakdown and optimization tips.

## 📝 License

[To be determined]

## 🤝 Contributing

[To be determined]

