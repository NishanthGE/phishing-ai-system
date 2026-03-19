# Test Signup Guide

## Step-by-Step

### 1. Start both servers
**Terminal 1:**
```bash
cd d:\CapstoneNew\Capstone\phishing-ai-system
node src/backend/server.js
```

**Terminal 2:**
```bash
cd d:\CapstoneNew\Capstone\phishing-ai-system
node src/backend/frontend-server.js
```

---

### 2. Open Browser
Go to: **http://localhost:8080**

---

### 3. Sign Up
1. Click **"Sign Up"** on the login page
2. Enter:
   - Username: `testuser`
   - Password: `test123`
   - Confirm password: `test123`
3. Click **"Create Account"**
4. ✅ Should show green success message and auto-switch to login

---

### 4. Login
1. Enter: `testuser` / `test123`
2. Click **"Login"**
3. ✅ Should enter the main dashboard

---

### Alternative — Use Demo Account

| Username | Password |
|----------|----------|
| `admin`  | `password123` |

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| "Failed to fetch" | Backend not running — start `node src/backend/server.js` |
| "Invalid credentials" | Use `admin` / `password123` or re-register |
| Blank page | Frontend not running — start `node src/backend/frontend-server.js` |
| "Username already taken" | Use a different username |

---

## Browser Console Debug

Open DevTools (F12) → Console and look for:
```
✅ Signup successful for: testuser
```
or
```
✅ Login successful, token stored
```
