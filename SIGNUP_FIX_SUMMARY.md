# Signup & Auth — Fix Summary

**Status:** ✅ Fixed and Working  
**Last Updated:** March 2026

---

## How Auth Works (Current)

Authentication is **JWT-based** with an **in-memory user store**.

### Flow
1. User submits signup form → `POST /api/auth/signup`
2. Password hashed with `bcryptjs`
3. User stored in `userStore.js` (in-memory Map)
4. Login → `POST /api/auth/login` → returns JWT token
5. Token stored in `localStorage` by frontend `script.js`
6. All analysis API calls include `Authorization: Bearer <token>`

---

## Demo Credentials

| Username | Password |
|----------|----------|
| `admin`  | `password123` |

---

## Files Involved

| File | Role |
|------|------|
| `src/backend/utils/userStore.js` | In-memory user Map (username → hashed password) |
| `src/backend/controllers/authController.js` | signup / login handlers |
| `src/backend/routes/authRoutes.js` | Routes at `/api/auth/signup` and `/api/auth/login` |
| `src/frontend/script.js` | handleLogin(), handleSignup(), localStorage token handling |

---

## Important Notes

- ⚠️ User accounts **reset on server restart** (in-memory only)
- JWT secret is hardcoded — must be moved to `.env` for production
- No email verification, no password strength validation (educational project)
- `admin` / `password123` is seeded on startup in `userStore.js`

---

## If Login Isn't Working

1. Confirm backend is running: http://localhost:8081/api/health
2. Try `admin` / `password123`
3. Open DevTools → Network tab → look at `/api/auth/login` response
4. If 401: credentials wrong
5. If failed to fetch: backend is not reachable
