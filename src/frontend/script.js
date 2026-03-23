/**
 * AI-Based Phishing Detection System - Frontend JavaScript
 * Professional cybersecurity dashboard with improved backend communication
 */

// Global variables and state management
const AppState = {
    currentTab: 'email',
    currentAnalysis: null,
    threatChart: null,
    totalAnalyses: 0,
    threatsDetected: 0,
    isAnalyzing: false,
    isLoggedIn: false,
    username: '',
    token: null
};

// API Configuration
const API_BASE_URL = 'http://localhost:8081';
const API_ENDPOINTS = {
    analyzeEmail: '/api/analyze-email',
    analyzeURL: '/api/analyze-url',
    batchEmails: '/api/analyze-emails-batch',
    batchURLs: '/api/analyze-urls-batch',
    sampleEmail: '/api/sample-email',
    sampleURL: '/api/sample-url',
    health: '/api/health',
    login: '/api/auth/login',
    signup: '/api/auth/signup'
};

// Utility to get auth headers
function getAuthHeaders() {
    return {
        'Content-Type': 'application/json',
        ...(AppState.token && { 'Authorization': `Bearer ${AppState.token}` })
    };
}

// Initialize application
document.addEventListener('DOMContentLoaded', function() {
    setupLoginForm();
    checkAuthenticationStatus();
});

/**
 * Setup login/signup forms
 */
function setupLoginForm() {
    const loginForm = document.getElementById('login-form');
    const signupForm = document.getElementById('signup-form');
    
    if (loginForm) loginForm.addEventListener('submit', handleLogin);
    if (signupForm) signupForm.addEventListener('submit', handleSignup);
}

/**
 * Check authentication status
 */
async function checkAuthenticationStatus() {
    const token = localStorage.getItem('authToken') || sessionStorage.getItem('authToken');
    const username = localStorage.getItem('username') || sessionStorage.getItem('username');
    
    console.log('🔍 Checking authentication...', { hasToken: !!token, hasUsername: !!username });
    
    if (token && username) {
        AppState.token = token;
        AppState.isLoggedIn = true;
        AppState.username = username;
        showDashboard();
        initializeApp();
        return;
    }
    
    console.log('🔐 Showing login modal');
    showLoginModal();
}

/**
 * Handle login
 */
async function handleLogin(event) {
    event.preventDefault();
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const remember = document.getElementById('remember').checked;
    const errorDiv = document.getElementById('login-error');

    try {
        const response = await fetch(`${API_BASE_URL}${API_ENDPOINTS.login}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            AppState.isLoggedIn = true;
            AppState.username = username;
            AppState.token = data.data.token || ('token-' + Date.now());

            const storage = remember ? localStorage : sessionStorage;
            storage.setItem('authToken', AppState.token);
            storage.setItem('username', username);

            errorDiv.style.display = 'none';
            showToast('Login successful!', 'success');
            showDashboard();
            initializeApp();
        } else {
            errorDiv.textContent = data.error || 'Invalid credentials. Please try again.';
            errorDiv.style.display = 'block';
            document.getElementById('password').value = '';
        }
    } catch (error) {
        errorDiv.textContent = 'Cannot connect to server. Please try again.';
        errorDiv.style.display = 'block';
    }
}

/**
 * Handle signup
 */
async function handleSignup(event) {
    event.preventDefault();
    const username = document.getElementById('signup-username').value.trim();
    const password = document.getElementById('signup-password').value;
    const confirmPassword = document.getElementById('signup-confirm').value;
    const errorDiv = document.getElementById('login-error');

    if (username.length < 4) { errorDiv.textContent = 'Username must be at least 4 characters'; errorDiv.style.display = 'block'; return; }
    if (password.length < 6) { errorDiv.textContent = 'Password must be at least 6 characters'; errorDiv.style.display = 'block'; return; }
    if (password !== confirmPassword) { errorDiv.textContent = 'Passwords do not match'; errorDiv.style.display = 'block'; return; }

    try {
        const response = await fetch(`${API_BASE_URL}${API_ENDPOINTS.signup}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await response.json();
        if (response.ok && data.success) {
            errorDiv.textContent = 'Account created! Please sign in.';
            errorDiv.classList.add('success');
            errorDiv.style.display = 'block';
            setTimeout(() => {
                toggleAuthForm('login');
                document.getElementById('signup-form').reset();
                errorDiv.style.display = 'none';
                errorDiv.classList.remove('success');
            }, 1500);
        } else {
            errorDiv.textContent = data.error || 'Signup failed. Please try again.';
            errorDiv.style.display = 'block';
        }
    } catch (error) {
        errorDiv.textContent = 'Cannot connect to server. Please try again.';
        errorDiv.style.display = 'block';
    }
}

/**
 * Toggle auth forms
 */
function toggleAuthForm(formType) {
    const loginForm = document.getElementById('login-form');
    const signupForm = document.getElementById('signup-form');
    const loginToggle = document.getElementById('login-toggle-text');
    const signupToggle = document.getElementById('signup-toggle-text');
    const subtitle = document.getElementById('modal-subtitle');
    const errorDiv = document.getElementById('login-error');
    
    if (formType === 'signup') {
        loginForm.style.display = 'none';
        signupForm.style.display = 'block';
        loginToggle.style.display = 'none';
        signupToggle.style.display = 'block';
        subtitle.textContent = 'Create Account';
    } else {
        signupForm.style.display = 'none';
        loginForm.style.display = 'block';
        signupToggle.style.display = 'none';
        loginToggle.style.display = 'block';
        subtitle.textContent = 'Secure Login';
    }
    errorDiv.style.display = 'none';
}

/**
 * Show/hide modals
 */
function showLoginModal() {
    document.getElementById('login-modal').style.display = 'flex';
    document.getElementById('dashboard').style.display = 'none';
}

function showDashboard() {
    document.getElementById('login-modal').style.display = 'none';
    document.getElementById('dashboard').style.display = 'flex';
    document.getElementById('current-user').textContent = AppState.username;
}

/**
 * Logout
 */
window.logout = function() {
    localStorage.removeItem('authToken');
    localStorage.removeItem('username');
    sessionStorage.removeItem('authToken');
    sessionStorage.removeItem('username');
    AppState.isLoggedIn = false;
    AppState.username = '';
    AppState.token = null;
    showLoginModal();
    showToast('Logged out successfully', 'success');
};

/**
 * Initialize app after login
 */
async function initializeApp() {
    console.log('🚀 Initializing app...');
    switchTab('email');
    setupCharacterCounters();
    await checkBackendConnection();
    setupEventListeners();
    loadSystemStats();
}

/**
 * Check backend connection status
 */
async function checkBackendConnection() {
    try {
        console.log('🔌 Checking backend connection...');
        const statusEl = document.getElementById('connection-status');
        if (statusEl) {
            statusEl.classList.remove('connected', 'disconnected');
            statusEl.classList.add('checking');
            const textEl = document.getElementById('connection-text');
            if (textEl) textEl.textContent = 'Checking...';
        }
        
        const response = await fetch(`${API_BASE_URL}${API_ENDPOINTS.health}`, {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' }
        });
        
        if (response.ok) {
            console.log('✅ Backend connected!');
            if (statusEl) {
                statusEl.classList.remove('checking', 'disconnected');
                statusEl.classList.add('connected');
                const textEl = document.getElementById('connection-text');
                if (textEl) textEl.textContent = 'Connected';
            }
            showToast('Backend connected successfully', 'success');
        } else {
            throw new Error(`HTTP ${response.status}`);
        }
    } catch (error) {
        console.error('❌ Backend connection failed:', error);
        const statusEl = document.getElementById('connection-status');
        if (statusEl) {
            statusEl.classList.remove('checking', 'connected');
            statusEl.classList.add('disconnected');
            const textEl = document.getElementById('connection-text');
            if (textEl) textEl.textContent = 'Offline';
        }
        showToast('Cannot connect to backend. Make sure server is running on port 8081', 'error');
    }
}

/**
 * Analyze email
 */
async function analyzeEmail() {
    const emailContent = document.getElementById('email-input').value.trim();
    console.log('📧 Analyze email called, content length:', emailContent.length);
    
    if (!emailContent) {
        showToast('Please enter email content to analyze', 'warning');
        return;
    }
    
    try {
        showLoading();
        const url = `${API_BASE_URL}${API_ENDPOINTS.analyzeEmail}`;
        const body = JSON.stringify({ emailContent });
        
        console.log('📤 Request details:');
        console.log('  URL:', url);
        console.log('  Content-Length:', body.length);
        console.log('  Preview:', emailContent.substring(0, 100) + '...');
        
        const response = await fetch(url, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: body
        });
        
        console.log('📥 Response status:', response.status, 'OK:', response.ok);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const data = await response.json();
        console.log('📦 Response data received:', data.success);
        
        if (data.success) {
            console.log('✅ Analysis successful!');
            AppState.currentAnalysis = data.data.analysis;
            displayEmailResults(data.data.analysis, data.data.processingTime);
            updateStats();
            showResults();
            showToast('Email analysis completed successfully!', 'success');
        } else {
            throw new Error(data.error || 'Analysis failed');
        }
    } catch (error) {
        console.error('❌ Email Analysis error:', error.message);
        showToast(`Analysis failed: ${error.message}`, 'error');
    } finally {
        hideLoading();
    }
}

/**
 * Analyze URL
 */
async function analyzeURL() {
    const urlContent = document.getElementById('url-input').value.trim();
    console.log('🔗 Analyze URL called:', urlContent);
    
    if (!urlContent) {
        showToast('Please enter a URL to analyze', 'warning');
        return;
    }
    
    try {
        showLoading();
        const response = await fetch(`${API_BASE_URL}${API_ENDPOINTS.analyzeURL}`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ url: urlContent })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.success) {
            AppState.currentAnalysis = data.data.analysis;
            displayURLResults(data.data.analysis, data.data.processingTime);
            updateStats();
            showResults();
            showToast('URL analysis completed successfully!', 'success');
        } else {
            throw new Error(data.error || 'Analysis failed');
        }
    } catch (error) {
        console.error('❌ URL Analysis error:', error.message);
        showToast(`Analysis failed: ${error.message}`, 'error');
    } finally {
        hideLoading();
    }
}

/**
 * Batch analysis
 */
async function batchAnalyze() {
    const batchType = document.querySelector('input[name="batch-type"]:checked').value;
    const content = document.getElementById('batch-input').value.trim();
    const items = content.split('\n').filter(item => item.trim());

    if (!items.length) {
        showToast('Please enter content for batch analysis', 'warning');
        return;
    }

    showLoading();

    try {
        const endpoint = batchType === 'emails' ? API_ENDPOINTS.batchEmails : API_ENDPOINTS.batchURLs;
        const body = batchType === 'emails' ? { emails: items } : { urls: items };

        const response = await fetch(`${API_BASE_URL}${endpoint}`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify(body)
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        if (data.success) {
            showToast(`Batch analysis completed! Processed ${items.length} items.`, 'success');
        } else {
            throw new Error(data.error);
        }
    } catch (error) {
        showToast(`Batch analysis failed: ${error.message}`, 'error');
    } finally {
        hideLoading();
    }
}

/**
 * Load sample email
 * @param {'phishing'|'legitimate'|'suspicious'} type - type of sample to load
 */
async function loadSampleEmail(type = 'phishing') {
    try {
        const response = await fetch(`${API_BASE_URL}${API_ENDPOINTS.sampleEmail}?type=${type}`, {
            headers: getAuthHeaders()
        });
        const data = await response.json();
        if (data.success) {
            document.getElementById('email-input').value = data.data.sample.content;
            document.getElementById('email-char-count').textContent = data.data.sample.content.length;
            const label = type === 'legitimate' ? 'Safe (non-threat) email sample loaded' : 'Threat email sample loaded';
            showToast(label, type === 'legitimate' ? 'success' : 'warning');
        }
    } catch (error) {
        showToast('Failed to load sample', 'error');
    }
}

/**
 * Load sample URL
 * @param {'malicious'|'legitimate'|'suspicious'} type - type of URL sample to load
 */
async function loadSampleURL(type = 'malicious') {
    try {
        const response = await fetch(`${API_BASE_URL}${API_ENDPOINTS.sampleURL}?type=${type}`, {
            headers: getAuthHeaders()
        });
        const data = await response.json();
        if (data.success) {
            document.getElementById('url-input').value = data.data.sample.url;
            document.getElementById('url-char-count').textContent = data.data.sample.url.length;
            const label = type === 'legitimate' ? 'Safe (non-threat) URL sample loaded' : 'Threat URL sample loaded';
            showToast(label, type === 'legitimate' ? 'success' : 'warning');
        }
    } catch (error) {
        showToast('Failed to load sample', 'error');
    }
}

/**
 * Clear inputs and data
 */
function clearEmailInput() {
    document.getElementById('email-input').value = '';
    document.getElementById('email-char-count').textContent = '0';
    showToast('Email input cleared', 'info');
}

function clearUrlInput() {
    document.getElementById('url-input').value = '';
    document.getElementById('url-char-count').textContent = '0';
    showToast('URL input cleared', 'info');
}

function clearBatchInput() {
    document.getElementById('batch-input').value = '';
    showToast('Batch input cleared', 'info');
}

/**
 * Clear all - Clear all inputs and results
 */
function clearAllData() {
    // Clear email input
    const emailInput = document.getElementById('email-input');
    if (emailInput) {
        emailInput.value = '';
        const emailCount = document.getElementById('email-char-count');
        if (emailCount) emailCount.textContent = '0';
    }

    // Clear URL input
    const urlInput = document.getElementById('url-input');
    if (urlInput) {
        urlInput.value = '';
        const urlCount = document.getElementById('url-char-count');
        if (urlCount) urlCount.textContent = '0';
    }

    // Clear batch input if exists
    const batchInput = document.getElementById('batch-input');
    if (batchInput) {
        batchInput.value = '';
    }

    // Clear results section
    const resultsSection = document.getElementById('results-section');
    if (resultsSection) {
        resultsSection.style.display = 'none';
    }

    // Clear loading indicator
    const loadingIndicator = document.getElementById('loading-indicator');
    if (loadingIndicator) {
        loadingIndicator.style.display = 'none';
    }

    // Reset analysis state
    AppState.currentAnalysis = null;

    // Clear chart if exists
    if (AppState.threatChart) {
        AppState.threatChart.destroy();
        AppState.threatChart = null;
    }

    showToast('All data cleared successfully', 'success');
}

/**
 * Display email analysis results
 */
function displayEmailResults(analysis, processingTime) {
    if (!analysis) {
        showToast('No analysis data to display', 'error');
        return;
    }

    const resultsSection = document.getElementById('results-section');
    if (resultsSection) resultsSection.style.display = 'block';

    const title = document.getElementById('results-title');
    if (title) title.textContent = 'Email Analysis Results';

    const badge = document.getElementById('classification-badge');
    if (badge) {
        badge.textContent = analysis.classification || 'Unknown';
        badge.style.background = analysis.classification === 'Phishing' ? '#ef4444' : 
                                 analysis.classification === 'Suspicious' ? '#f59e0b' : '#10b981';
    }

    const threatScore = document.getElementById('threat-score-value');
    if (threatScore) threatScore.textContent = analysis.threatScore || 0;

    const threatLevel = document.getElementById('threat-level');
    if (threatLevel) threatLevel.textContent = analysis.threatScore > 70 ? 'Critical' : 
                                                 analysis.threatScore > 50 ? 'High' : 
                                                 analysis.threatScore > 30 ? 'Medium' : 'Low';

    const confidence = document.getElementById('confidence-level');
    if (confidence && analysis.confidence) {
        confidence.textContent = analysis.confidence.level || 'Unknown';
    }

    const time = document.getElementById('processing-time');
    if (time) time.textContent = processingTime + 'ms';

    const riskFactors = document.querySelector('.risk-factors-container');
    if (riskFactors && analysis.features) {
        // FIXED CWE-94: Clear innerHTML safely
        riskFactors.textContent = '';
        const allRiskFactors = [
            ...(analysis.features.suspiciousKeywords || []),
            ...(analysis.features.phishingPhrases || [])
        ];
        
        if (allRiskFactors.length > 0) {
            allRiskFactors.forEach(factor => {
                const chip = document.createElement('span');
                chip.className = 'risk-factor';
                // FIXED CWE-94: Use textContent instead of innerHTML to prevent XSS
                chip.textContent = factor;
                riskFactors.appendChild(chip);
            });
        } else {
            // FIXED CWE-94: Create element instead of using innerHTML
            const noRisk = document.createElement('div');
            noRisk.className = 'no-risk-factors';
            noRisk.textContent = 'No risk factors detected';
            riskFactors.appendChild(noRisk);
        }
    }

    resultsSection?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/**
 * Display URL analysis results
 */
function displayURLResults(analysis, processingTime) {
    displayEmailResults(analysis, processingTime);
}

/**
 * Show/hide functions
 */
function showLoading() {
    document.getElementById('loading-indicator').style.display = 'block';
}

function hideLoading() {
    document.getElementById('loading-indicator').style.display = 'none';
}

function showResults() {
    document.getElementById('results-section').style.display = 'block';
    document.getElementById('results-section').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function hideResults() {
    document.getElementById('results-section').style.display = 'none';
}

/**
 * Toast notifications
 */
function showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    // Icon per type
    const icons = { success: 'fa-circle-check', error: 'fa-circle-xmark', warning: 'fa-triangle-exclamation', info: 'fa-circle-info' };

    // Left group: icon + message text
    const leftGroup = document.createElement('div');
    leftGroup.className = 'toast-left';

    const icon = document.createElement('i');
    icon.className = `fas ${icons[type] || icons.info} toast-icon`;
    leftGroup.appendChild(icon);

    const msgSpan = document.createElement('span');
    msgSpan.className = 'toast-msg';
    msgSpan.textContent = message;
    leftGroup.appendChild(msgSpan);

    // Close button
    const closeBtn = document.createElement('button');
    closeBtn.className = 'toast-close';
    closeBtn.innerHTML = '&times;';
    closeBtn.setAttribute('aria-label', 'Dismiss');
    closeBtn.addEventListener('click', () => toast.remove());

    toast.appendChild(leftGroup);
    toast.appendChild(closeBtn);
    toastContainer.appendChild(toast);

    // Auto-dismiss after 5s
    setTimeout(() => toast.remove(), 5000);
}

/**
 * Switch tabs
 */
function switchTab(tabName) {
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
    document.getElementById(`${tabName}-tab`).classList.add('active');
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
    document.addEventListener('keydown', (e) => {
        if (e.ctrlKey && e.key === 'Enter') {
            if (AppState.currentTab === 'email') analyzeEmail();
            else if (AppState.currentTab === 'url') analyzeURL();
        }
    });
}

/**
 * Character counters
 */
function setupCharacterCounters() {
    ['email-input', 'url-input'].forEach(id => {
        const input = document.getElementById(id);
        const counter = document.getElementById(id.replace('input', 'char-count'));
        if (input && counter) {
            input.addEventListener('input', () => counter.textContent = input.value.length);
        }
    });
}

/**
 * Load system stats
 */
function loadSystemStats() {
    document.getElementById('total-analyses').textContent = AppState.totalAnalyses;
    document.getElementById('threats-detected').textContent = AppState.threatsDetected;
}

/**
 * Update statistics
 */
function updateStats() {
    AppState.totalAnalyses++;
    if (AppState.currentAnalysis && 
        (AppState.currentAnalysis.classification === 'Phishing' || 
         AppState.currentAnalysis.classification === 'Malicious')) {
        AppState.threatsDetected++;
    }
    document.getElementById('total-analyses').textContent = AppState.totalAnalyses;
    document.getElementById('threats-detected').textContent = AppState.threatsDetected;
}

console.log('🎯 Frontend Ready!');

function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    const eye = document.getElementById(inputId + '-eye');
    if (!input || !eye) return;
    const isHidden = input.type === 'password';
    input.type = isHidden ? 'text' : 'password';
    eye.className = isHidden ? 'fas fa-eye-slash' : 'fas fa-eye';
}
