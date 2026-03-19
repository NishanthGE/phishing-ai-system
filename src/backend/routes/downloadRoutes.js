const express = require('express');
const router = express.Router();
const dataStore = require('../store/dataStore');

// Convert JSON to CSV
function jsonToCSV(data, type) {
    if (data.length === 0) return '';

    if (type === 'email') {
        const headers = ['ID', 'Timestamp', 'Subject', 'Threat Score', 'Classification', 'Is Phishing'];
        const rows = data.map(item => [
            item.id,
            item.timestamp,
            `"${item.subject ? item.subject.replace(/"/g, '""') : 'N/A'}"`,
            item.threatScore || 0,
            item.classification || 'Unknown',
            item.isPhishing || 'Unknown'
        ]);
        return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    } else if (type === 'url') {
        const headers = ['ID', 'Timestamp', 'URL', 'Threat Score', 'Classification', 'Is Malicious'];
        const rows = data.map(item => [
            item.id,
            item.timestamp,
            `"${item.url ? item.url.replace(/"/g, '""') : 'N/A'}"`,
            item.threatScore || 0,
            item.classification || 'Unknown',
            item.isMalicious || 'Unknown'
        ]);
        return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    }
    return '';
}

// Get all emails
router.get('/emails/json', (req, res) => {
    try {
        const emails = dataStore.getAllEmails();
        res.json({
            success: true,
            count: emails.length,
            data: emails,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Download emails as JSON
router.get('/emails/download-json', (req, res) => {
    try {
        const emails = dataStore.getAllEmails();
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="phishing_emails_${Date.now()}.json"`);
        res.send(JSON.stringify(emails, null, 2));
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Download emails as CSV
router.get('/emails/download-csv', (req, res) => {
    try {
        const emails = dataStore.getAllEmails();
        const csv = jsonToCSV(emails, 'email');
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="phishing_emails_${Date.now()}.csv"`);
        res.send(csv);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get all URLs
router.get('/urls/json', (req, res) => {
    try {
        const urls = dataStore.getAllURLs();
        res.json({
            success: true,
            count: urls.length,
            data: urls,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Download URLs as JSON
router.get('/urls/download-json', (req, res) => {
    try {
        const urls = dataStore.getAllURLs();
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="malicious_urls_${Date.now()}.json"`);
        res.send(JSON.stringify(urls, null, 2));
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Download URLs as CSV
router.get('/urls/download-csv', (req, res) => {
    try {
        const urls = dataStore.getAllURLs();
        const csv = jsonToCSV(urls, 'url');
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="malicious_urls_${Date.now()}.csv"`);
        res.send(csv);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Delete all data
router.delete('/clear', (req, res) => {
    try {
        const success = dataStore.clearAll();
        res.json({
            success: success,
            message: success ? 'All data cleared successfully' : 'Failed to clear data'
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

module.exports = router;
