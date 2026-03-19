/**
 * Data Routes
 * Endpoints for retrieving stored analysis data
 */

const express = require('express');
const dataStore = require('../utils/dataStore');
const router = express.Router();

/**
 * GET /api/data/analyses
 * Get all stored analyses
 */
router.get('/data/analyses', (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 100;
        const data = dataStore.getAllAnalyses(limit);
        
        res.json({
            success: true,
            data: data,
            metadata: {
                endpoint: 'data/analyses',
                version: '1.0.0',
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Failed to retrieve analyses',
            details: error.message
        });
    }
});

/**
 * GET /api/data/emails
 * Get all email analyses
 */
router.get('/data/emails', (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const data = dataStore.getEmailAnalyses(limit);
        
        res.json({
            success: true,
            data: data,
            metadata: {
                endpoint: 'data/emails',
                version: '1.0.0',
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Failed to retrieve email analyses',
            details: error.message
        });
    }
});

/**
 * GET /api/data/urls
 * Get all URL analyses
 */
router.get('/data/urls', (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const data = dataStore.getURLAnalyses(limit);
        
        res.json({
            success: true,
            data: data,
            metadata: {
                endpoint: 'data/urls',
                version: '1.0.0',
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Failed to retrieve URL analyses',
            details: error.message
        });
    }
});

/**
 * GET /api/data/email/:id
 * Get specific email analysis
 */
router.get('/data/email/:id', (req, res) => {
    try {
        const analysis = dataStore.getEmailAnalysisById(req.params.id);
        
        if (!analysis) {
            return res.status(404).json({
                success: false,
                error: 'Email analysis not found',
                id: req.params.id
            });
        }
        
        res.json({
            success: true,
            data: analysis,
            metadata: {
                endpoint: 'data/email/:id',
                version: '1.0.0',
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Failed to retrieve email analysis',
            details: error.message
        });
    }
});

/**
 * GET /api/data/url/:id
 * Get specific URL analysis
 */
router.get('/data/url/:id', (req, res) => {
    try {
        const analysis = dataStore.getURLAnalysisById(req.params.id);
        
        if (!analysis) {
            return res.status(404).json({
                success: false,
                error: 'URL analysis not found',
                id: req.params.id
            });
        }
        
        res.json({
            success: true,
            data: analysis,
            metadata: {
                endpoint: 'data/url/:id',
                version: '1.0.0',
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Failed to retrieve URL analysis',
            details: error.message
        });
    }
});

/**
 * GET /api/data/stats
 * Get statistics of all analyses
 */
router.get('/data/stats', (req, res) => {
    try {
        const stats = dataStore.getStats();
        
        res.json({
            success: true,
            data: stats,
            metadata: {
                endpoint: 'data/stats',
                version: '1.0.0',
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Failed to retrieve statistics',
            details: error.message
        });
    }
});

/**
 * DELETE /api/data/clear
 * Clear all data
 */
router.delete('/data/clear', (req, res) => {
    try {
        dataStore.clearAll();
        
        res.json({
            success: true,
            message: 'All data cleared',
            metadata: {
                endpoint: 'data/clear',
                version: '1.0.0',
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Failed to clear data',
            details: error.message
        });
    }
});

module.exports = router;
