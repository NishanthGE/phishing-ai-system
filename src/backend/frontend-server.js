/**
 * Frontend Server
 * Serves the frontend application on port 8080
 */

const express = require('express');
const path = require('path');
const cors = require('cors');

// Initialize Express app
const app = express();
const PORT = process.env.FRONTEND_PORT || 8080;

// Enable CORS
app.use(cors());

// Serve static files from frontend
app.use(express.static(path.join(__dirname, '../frontend')));

// Serve index.html for all routes (SPA)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log('\n🌐 Frontend Server');
    console.log('═══════════════════════════════════════════');
    console.log(`📱 Frontend running on: http://localhost:${PORT}`);
    console.log(`🔌 Backend API on: http://localhost:8081`);
    console.log('═══════════════════════════════════════════\n');
});
