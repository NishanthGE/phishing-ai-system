# Communication Guide — API & Frontend

## API Base URL

```
http://localhost:8081
```

## Authentication Flow

### 1. Sign Up
```http
POST /api/auth/signup
Content-Type: application/json

{ "username": "yourname", "password": "yourpass" }
```

### 2. Login → get JWT token
```http
POST /api/auth/login
Content-Type: application/json

{ "username": "yourname", "password": "yourpass" }
```
Response: `{ "token": "eyJ..." }`

### 3. Use token in all analysis requests
```http
Authorization: Bearer eyJ...
```

---

## Email Analysis Flow

```
Frontend (port 8080)
  │
  │ POST /api/analyze-email
  │ { emailContent: "..." }
  ▼
Backend (port 8081)
  │
  ├─ emailAnalyzer.js
  │     └─ aiEngine.classifyEmail()
  │           ├─ formalEmailScore() → dampening
  │           └─ NaiveBayesClassifier.predict()
  │
  └─ Response: { classification, threatScore, confidence, mlEngine, explanation }
```

## URL Analysis Flow

```
Frontend (port 8080)
  │
  │ POST /api/analyze-url
  │ { url: "https://..." }
  ▼
Backend (port 8081)
  │
  ├─ urlAnalyzer.js
  │     └─ aiEngine.classifyURL()
  │           └─ RandomForestURLClassifier.predict()
  │                 └─ 5 tree votes → weighted avg
  │
  └─ Response: { classification, threatScore, confidence, mlEngine, explanation }
```

---

## Response Structure

### Email
```json
{
  "success": true,
  "data": {
    "analysis": {
      "classification": "Phishing | Suspicious | Safe",
      "threatScore": 0,
      "confidence": { "level": "High", "value": 90 },
      "mlEngine": {
        "name": "Naive Bayes ML v3.2",
        "topPhishTokens": ["urgent", "suspended"],
        "topSafeTokens": ["attached", "report"]
      },
      "explanation": {
        "summary": "...",
        "riskFactors": [{ "title": "...", "severity": "high" }],
        "recommendation": "..."
      }
    }
  }
}
```

### URL
```json
{
  "success": true,
  "data": {
    "analysis": {
      "classification": "Malicious | Suspicious | Safe",
      "threatScore": 85,
      "mlEngine": {
        "name": "Random Forest ML v3.2",
        "treeVotes": [
          { "tree": 1, "vote": 100, "weight": 0.30 },
          { "tree": 2, "vote": 30, "weight": 0.20 }
        ]
      }
    }
  }
}
```
