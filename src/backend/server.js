/**
 * AI-Based Phishing Detection System Server
 * Professional Express.js server with security middleware and comprehensive API
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const path = require('path');

// Import routes
const emailRoutes = require('./routes/emailRoutes');
const urlRoutes = require('./routes/urlRoutes');
const authRoutes = require('./routes/authRoutes');
const dataRoutes = require('./routes/dataRoutes');
const downloadRoutes = require('./routes/downloadRoutes');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 8081;

// Serve static files
app.use(express.static(path.join(__dirname)));

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"]
        }
    }
}));

// CORS configuration
app.use(cors({
    origin: ['http://localhost:8080', 'http://127.0.0.1:8080', 'http://localhost:8081', 'http://127.0.0.1:8081'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    optionsSuccessStatus: 200,
    maxAge: 3600
}));

// Body parsing middleware (MUST be before rate limiter)
app.use(express.json({ 
    limit: '10mb',
    strict: true
}));

app.use(express.urlencoded({ 
    extended: true, 
    limit: '10mb' 
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: {
        error: 'Too many requests from this IP, please try again later.',
        code: 'RATE_LIMIT_EXCEEDED'
    },
    standardHeaders: true,
    legacyHeaders: false
});

app.use('/api/', limiter);

// Logging middleware
app.use(morgan('combined', {
    skip: (req, res) => res.statusCode < 400 // Only log errors in production
}));

// API Routes
app.use('/api', authRoutes);
app.use('/api', emailRoutes);
app.use('/api', urlRoutes);
app.use('/api', dataRoutes);
app.use('/api/download', downloadRoutes);

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: '2.0.0',
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// API documentation endpoint (JSON format)
app.get('/api/docs/json', (req, res) => {
    const apiDocs = {
        title: 'AI-Based Phishing Detection System API',
        version: '2.0.0',
        description: 'Advanced cybersecurity API for detecting phishing emails and malicious URLs',
        endpoints: {
            email: {
                'POST /api/analyze-email': 'Analyze single email for phishing indicators',
                'POST /api/analyze-emails-batch': 'Batch analyze multiple emails',
                'GET /api/email-stats': 'Get email analysis statistics',
                'POST /api/validate-email': 'Validate email content format',
                'GET /api/sample-email': 'Get sample phishing email for testing'
            },
            url: {
                'POST /api/analyze-url': 'Analyze single URL for malicious indicators',
                'POST /api/analyze-urls-batch': 'Batch analyze multiple URLs',
                'GET /api/url-stats': 'Get URL analysis statistics',
                'POST /api/validate-url': 'Validate URL format',
                'GET /api/sample-url': 'Get sample URLs for testing',
                'POST /api/extract-url-components': 'Extract and analyze URL components'
            },
            system: {
                'GET /api/health': 'System health check',
                'GET /api/docs': 'API documentation'
            }
        },
        examples: {
            analyzeEmail: {
                method: 'POST',
                url: '/api/analyze-email',
                body: {
                    emailContent: 'Your email content here...'
                }
            },
            analyzeUrl: {
                method: 'POST',
                url: '/api/analyze-url',
                body: {
                    url: 'https://example.com'
                }
            }
        }
    };

    res.json({
        success: true,
        data: apiDocs,
        metadata: {
            timestamp: new Date().toISOString()
        }
    });
});

// API documentation endpoint (HTML UI)
app.get('/api/docs', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/api-docs.html'));
});

// Handle 404 for API routes
app.use('/api/*', (req, res) => {
    res.status(404).json({
        success: false,
        error: 'API endpoint not found',
        code: 'ENDPOINT_NOT_FOUND',
        availableEndpoints: '/api/docs'
    });
});

// Handle all other routes (non-API)
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        error: 'Backend API does not serve frontend. Access frontend at http://localhost:8080',
        code: 'FRONTEND_NOT_AVAILABLE',
        note: 'Port 8081 is API-only. Frontend is on port 8080'
    });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('Global error handler:', err);

    // Handle JSON parsing errors
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        return res.status(400).json({
            success: false,
            error: 'Invalid JSON format',
            code: 'INVALID_JSON'
        });
    }

    // Handle payload too large errors
    if (err.type === 'entity.too.large') {
        return res.status(413).json({
            success: false,
            error: 'Request payload too large',
            code: 'PAYLOAD_TOO_LARGE'
        });
    }

    // Default error response
    res.status(err.status || 500).json({
        success: false,
        error: process.env.NODE_ENV === 'production' ? 
            'Internal server error' : 
            err.message,
        code: 'INTERNAL_ERROR',
        ...(process.env.NODE_ENV !== 'production' && { stack: err.stack })
    });
});

// Graceful shutdown handling
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully');
    server.close(() => {
        console.log('Process terminated');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('SIGINT received, shutting down gracefully');
    server.close(() => {
        console.log('Process terminated');
        process.exit(0);
    });
});

// Start server
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log('\n🚀 AI-Based Phishing Detection System');
    console.log('=====================================');
    console.log(`🔧 Backend API running on: http://localhost:${PORT}`);
    console.log(`📚 API Docs: http://localhost:${PORT}/api/docs`);
    console.log(`💚 Health Check: http://localhost:${PORT}/api/health`);
    console.log('\n📧 Email Analysis Endpoints:');
    console.log(`   POST /api/analyze-email`);
    console.log(`   POST /api/analyze-emails-batch`);
    console.log(`   GET  /api/email-stats`);
    console.log('\n🔗 URL Analysis Endpoints:');
    console.log(`   POST /api/analyze-url`);
    console.log(`   POST /api/analyze-urls-batch`);
    console.log(`   GET  /api/url-stats`);
    console.log('\n🛡️  Security Features:');
    console.log('   ✅ Helmet security headers');
    console.log('   ✅ CORS protection');
    console.log('   ✅ Rate limiting');
    console.log('   ✅ Request validation');
    console.log('\n🎯 Ready for cybersecurity analysis!');
    console.log('=====================================\n');
});

module.exports = app;