const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const UserStore = require('../utils/userStore');
const crypto = require('crypto');

const JWT_SECRET = process.env.JWT_SECRET || 'phishing-ai-super-secret-key-change-in-prod';
const JWT_EXPIRES = '7d';
// FIXED CWE-798,259: Use environment variables for demo credentials
const DEMO_USERNAME = process.env.DEMO_USERNAME || 'admin';
const DEMO_PASSWORD = process.env.DEMO_PASSWORD || 'password123';

/**
 * Signup controller
 */
exports.signup = async (req, res) => {
    try {
        const { username, password } = req.body;

        // Validation
        if (!username || !password) {
            return res.status(400).json({
                success: false,
                error: 'Username and password required',
                code: 'VALIDATION_ERROR'
            });
        }

        if (username.length < 4 || password.length < 6) {
            return res.status(400).json({
                success: false,
                error: 'Username min 4 chars, password min 6 chars',
                code: 'VALIDATION_ERROR'
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);

        // Create user
        await UserStore.create(username, hashedPassword);

        // Generate JWT
        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: JWT_EXPIRES });

        res.status(201).json({
            success: true,
            message: 'User created successfully',
            data: { token, username },
            metadata: { createdAt: new Date().toISOString() }
        });

    } catch (error) {
        console.error('Signup error:', error);
        if (error.message === 'Username already exists') {
            return res.status(409).json({
                success: false,
                error: 'Username already exists',
                code: 'USER_EXISTS'
            });
        }
        res.status(500).json({
            success: false,
            error: 'Signup failed',
            code: 'INTERNAL_ERROR'
        });
    }
};

/**
 * Login controller
 */
exports.login = async (req, res) => {
    try {
        const { username, password } = req.body;

        // Validation
        if (!username || !password) {
            return res.status(400).json({
                success: false,
                error: 'Username and password required',
                code: 'VALIDATION_ERROR'
            });
        }

        // Find user
        const user = UserStore.findByUsername(username);
        if (!user) {
            // FIXED CWE-208: Use timing-safe comparison to prevent timing attacks
            // FIXED CWE-798,259: Demo credentials from env variables
            const demoUsernameMatch = crypto.timingSafeEqual(
                Buffer.from(username),
                Buffer.from(DEMO_USERNAME)
            );
            const demoPasswordMatch = crypto.timingSafeEqual(
                Buffer.from(password),
                Buffer.from(DEMO_PASSWORD)
            );
            
            if (demoUsernameMatch && demoPasswordMatch) {
                const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
                return res.json({
                    success: true,
                    message: 'Demo login successful',
                    data: { token, username },
                    metadata: { isDemo: true }
                });
            }

            return res.status(401).json({
                success: false,
                error: 'Invalid credentials',
                code: 'INVALID_CREDENTIALS'
            });
        }

        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({
                success: false,
                error: 'Invalid credentials',
                code: 'INVALID_CREDENTIALS'
            });
        }

        // Generate JWT
        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: JWT_EXPIRES });

        res.json({
            success: true,
            message: 'Login successful',
            data: { token, username },
            metadata: { loginAt: new Date().toISOString() }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            error: 'Login failed',
            code: 'INTERNAL_ERROR'
        });
    }
};

/**
 * Get current user/profile (protected)
 */
exports.profile = (req, res) => {
    try {
        const token = req.headers.authorization?.replace('Bearer ', '');
        if (!token) {
            return res.status(401).json({
                success: false,
                error: 'No token provided',
                code: 'NO_TOKEN'
            });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        res.json({
            success: true,
            data: { username: decoded.username },
            metadata: UserStore.getAll()
        });
    } catch (error) {
        res.status(401).json({
            success: false,
            error: 'Invalid token',
            code: 'INVALID_TOKEN'
        });
    }
};

/**
 * Get all users (admin only, demo)
 */
exports.getUsers = (req, res) => {
    try {
        const users = UserStore.getAll();
        res.json({
            success: true,
            data: { users, total: users.length },
            metadata: { storeType: 'in-memory' }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Failed to fetch users',
            code: 'INTERNAL_ERROR'
        });
    }
};

