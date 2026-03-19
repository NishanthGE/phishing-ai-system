# Setup Guide

## System Requirements
- **OS**: Windows 10/11 (tested), Linux/macOS compatible
- **Node.js**: v16.0.0 or higher (v25 recommended)
- **npm**: v8+
- **Browser**: Chrome, Edge, Firefox (latest)
- **Ports**: 8080 (frontend), 8081 (backend) — must be free

---

## Installation

### Step 1 — Navigate to Project
```bash
cd d:\CapstoneNew\Capstone\phishing-ai-system
```

### Step 2 — Install Dependencies
```bash
npm install
```

Key packages installed:
| Package | Purpose |
|---------|---------|
| `express` | HTTP server framework |
| `helmet` | Security headers |
| `cors` | Cross-origin resource sharing |
| `express-rate-limit` | Rate limiting |
| `validator` | URL validation |
| `natural` | NLP / sentiment analysis (legacy) |
| `bcryptjs` | Password hashing |
| `jsonwebtoken` | JWT auth tokens |

---

## Running the System

### Terminal 1 — Backend API
```bash
node src/backend/server.js
```
Expected output:
```
🚀 AI-Based Phishing Detection System
🔧 Backend API running on: http://localhost:8081
✅ Naive Bayes v3.2 trained: 60 phishing, 100 legit
```

### Terminal 2 — Frontend
```bash
node src/backend/frontend-server.js
```
Expected: Frontend serving on http://localhost:8080

---

## Environment Notes

- No `.env` file needed — all config is hardcoded for local development
- User accounts are stored **in-memory** (reset on server restart)
- ML model trains **in-memory** on startup from hardcoded datasets in `aiEngine.js`
- The `datasets/` folder JSONs are used only by legacy featureExtractor — not the ML engine

---

## Verify Setup

```
http://localhost:8081/api/health   → should return { status: "ok" }
http://localhost:8080              → should show login page
```