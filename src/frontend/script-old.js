/**
 * AI-Based Phishing Detection System - Frontend JavaScript (Backend Auth Integrated)
 * Professional cybersecurity dashboard with backend authentication
 */

// Demo credentials
const DEMO_CREDENTIALS = {
    username: 'admin',
    password: 'password123'
};

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
    authSignup: '/api/auth/signup',
    authLogin: '/api/auth/login',
    authProfile: '/api/auth/profile',
    analyzeEmail: '/api/analyze-email',
    analyzeURL: '/api/analyze-url',
    batchEmails: '/api/analyze-emails-batch',
    batchURLs: '/api/analyze-urls-batch',
    sampleEmail: '/api/sample-email',
    sampleURL: '/api/sample-url',
    health: '/api/health'
};

// Utility to get auth headers
function getAuthHeaders() {
    return {
        'Content-Type': 'application/json',
        ...(AppState.token && { 'Authorization': `Bearer ${AppState.token}` })
    };
}

// Clear auth storage
function clearAuthStorage() {
    localStorage.removeItem('authToken');
    localStorage.removeItem('username');
    sessionStorage.removeItem('authToken');
    sessionStorage.removeItem('username');
    AppState.isLoggedIn = false;
    AppState.username = '';
    AppState.token = null;
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
 * Check authentication status (validate token with backend)
 */
async function checkAuthenticationStatus() {
    const token = localStorage.getItem('authToken') || sessionStorage.getItem('authToken');
    const username = localStorage.getItem('username') || sessionStorage.getItem('username');
    
    console.log('🔍 Checking authentication...', { hasToken: !!token, hasUsername: !!username });
    
    if (token && username) {
        try {
            console.log('📡 Validating token with backend...');
            AppState.token = token;
            const response = await fetch(`${API_BASE_URL}${API_ENDPOINTS.authProfile}`, {
                method: 'GET',
                headers: getAuthHeaders()
            });
            
            console.log('📥 Profile response:', response.status);
            
            if (response.ok) {
                const data = await response.json();
                console.log('✅ Token valid, logging in user:', username);
                AppState.isLoggedIn = true;
                AppState.username = username;
                AppState.token = token;
                showDashboard();
                initializeApp();
                return;
            }
        } catch (error) {
            console.error('❌ Token validation failed:', error.message);
        }
        clearAuthStorage();
    }
    console.log('🔐 Showing login modal');
    showLoginModal();
}

/**
 * Backend login
 */
async function handleLogin(event) {
    event.preventDefault();
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const remember = document.getElementById('remember').checked;
    const errorDiv = document.getElementById('login-error');
    
    console.log('🔐 Login attempt:', username);
    errorDiv.textContent = 'Logging in...';
    errorDiv.style.display = 'block';
    
    try {
        console.log('📡 Sending login request to:', `${API_BASE_URL}${API_ENDPOINTS.authLogin}`);
        const response = await fetch(`${API_BASE_URL}${API_ENDPOINTS.authLogin}`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ username, password })
        });
        
        console.log('📥 Login response status:', response.status);
        const data = await response.json();
        console.log('📦 Login response:', data);
        
        if (data.success) {
            console.log('✅ Login successful!');
            AppState.isLoggedIn = true;
            AppState.username = data.data.username;
            AppState.token = data.data.token;
            
            if (remember) {
                localStorage.setItem('authToken', data.data.token);
                localStorage.setItem('username', data.data.username);
            } else {
                sessionStorage.setItem('authToken', data.data.token);
                sessionStorage.setItem('username', data.data.username);
            }
            
            showToast('Login successful!', 'success');
            console.log('🎯 Showing dashboard...');
            showDashboard();
            initializeApp();
        } else {
            throw new Error(data.error);
        }
    } catch (error) {
        console.error('❌ Login error:', error);
        errorDiv.textContent = `Login failed: ${error.message}. Try demo: admin/password123`;
        document.getElementById('password').value = '';
    }
}

/**
 * Backend signup
 */
async function handleSignup(event) {
    event.preventDefault();
    const username = document.getElementById('signup-username').value.trim();
    const password = document.getElementById('signup-password').value;
    const confirmPassword = document.getElementById('signup-confirm').value;
    const errorDiv = document.getElementById('login-error');
    
    // Validation
    if (username.length < 4 || password.length < 6 || password !== confirmPassword) {
        errorDiv.textContent = 'Validation error: Check username/password length/match';
        errorDiv.style.display = 'block';
        return;
    }
    
    errorDiv.textContent = 'Creating account...';
    errorDiv.style.display = 'block';
    
    try {
        const response = await fetch(`${API_BASE_URL}${API_ENDPOINTS.authSignup}`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast('Account created! Logging in...', 'success');
            document.getElementById('signup-form').reset();
            toggleAuthForm('login');
            document.getElementById('username').value = username;
            // Auto login
            setTimeout(() => document.getElementById('login-form').dispatchEvent(new Event('submit')), 1000);
        } else {
            throw new Error(data.error);
        }
    } catch (error) {
        errorDiv.textContent = `Signup failed: ${error.message}`;
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
    clearAuthStorage();
    showLoginModal();
    showToast('Logged out successfully', 'success');
};

/**
 * Initialize app after login
 */
async function initializeApp() {
    switchTab('email');
    setupCharacterCounters();
    await testBackendConnection();
    setupEventListeners();
    loadSystemStats();
}

/**
 * Test backend
 */
async function testBackendConnection() {
    try {
        const response = await fetch(`${API_BASE_URL}${API_ENDPOINTS.health}`, {
            headers: getAuthHeaders()
        });
        if (response.ok) {
            showToast('✅ Backend connected', 'success');
        }
    } catch (error) {
        showToast('Backend connection failed', 'error');
    }
}

/**
 * Analysis functions (with auth)
 */
async function analyzeEmail() {
    const emailContent = document.getElementById('email-input').value.trim();
    console.log('📧 Analyze email called, content length:', emailContent.length);
    if (!emailContent) return showToast('Enter email content', 'warning');
    
    try {
        showLoading();
        const url = `${API_BASE_URL}${API_ENDPOINTS.analyzeEmail}`;
        const body = JSON.stringify({ emailContent });
        console.log('📡 Sending request to:', url);
        
        const response = await fetch(url, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: body
        });
        
        console.log('📥 Response status:', response.status);
        const data = await response.json();
        console.log('✅ Got response:', data.success);
        
        if (data.success) {
            console.log('✅ Analysis successful!');
            AppState.currentAnalysis = data.data.analysis;
            displayEmailResults(data.data.analysis, data.data.processingTime);
            updateStats();
            showResults();
            showToast('Analysis complete!', 'success');
        } else {
            showToast(data.error || 'Analysis failed', 'error');
        }
    } catch (error) {
        console.error('❌ Email Analysis error:', error);
        showToast(`Analysis failed: ${error.message}`, 'error');
    } finally {
        hideLoading();
    }
}

/**
 * URL Analysis
 */
async function analyzeURL() {
    const urlContent = document.getElementById('url-input').value.trim();
    if (!urlContent) return showToast('Enter a URL', 'warning');
    
    try {
        showLoading();
        const response = await fetch(`${API_BASE_URL}${API_ENDPOINTS.analyzeURL}`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ url: urlContent })
        });
        const data = await response.json();
        if (data.success) {
            displayURLResults(data.data.analysis, data.data.processingTime);
        } else {
            showToast(data.error || 'Analysis failed', 'error');
        }
    } catch (error) {
        console.error('URL Analysis error:', error);
        showToast(`Analysis failed: ${error.message}`, 'error');
    } finally {
        hideLoading();
    }
}

/**
 * Batch analysis
 */
/**
 * Load sample email
 */
async function loadSampleEmail() {
    try {
        const response = await fetch(`${API_BASE_URL}${API_ENDPOINTS.sampleEmail}?type=phishing`, {
            headers: getAuthHeaders()
        });
        const data = await response.json();
        if (data.success) {
            document.getElementById('email-input').value = data.data.content;
            showToast('Sample email loaded', 'success');
        }
    } catch (error) {
        showToast('Failed to load sample', 'error');
    }
}

/**
 * Load sample URL
 */
async function loadSampleURL() {
    try {
        const response = await fetch(`${API_BASE_URL}${API_ENDPOINTS.sampleURL}?type=malicious`, {
            headers: getAuthHeaders()
        });
        const data = await response.json();
        if (data.success) {
            document.getElementById('url-input').value = data.data.url;
            showToast('Sample URL loaded', 'success');
        }
    } catch (error) {
        showToast('Failed to load sample', 'error');
    }
}

/**
 * Clear inputs
 */
function clearEmailInput() {
    document.getElementById('email-input').value = '';
    showToast('Cleared', 'info');
}

function clearUrlInput() {
    document.getElementById('url-input').value = '';
    showToast('Cleared', 'info');
}

function clearBatchInput() {
    document.getElementById('batch-input').value = '';
    showToast('Cleared', 'info');
}

/**
 * Display email analysis results
 */
function displayEmailResults(analysis, processingTime) {
    if (!analysis) {
        showToast('No analysis data to display', 'error');
        return;
    }

    // Show results section
    const resultsSection = document.getElementById('results-section');
    if (resultsSection) resultsSection.style.display = 'block';

    // Update title
    const title = document.getElementById('results-title');
    if (title) title.textContent = 'Email Analysis Results';

    // Update classification badge
    const badge = document.getElementById('classification-badge');
    if (badge) {
        badge.textContent = analysis.classification || 'Unknown';
        badge.style.background = analysis.classification === 'Phishing' ? '#e74c3c' : 
                                 analysis.classification === 'Suspicious' ? '#f39c12' : '#27ae60';
    }

    // Update threat score
    const threatScore = document.getElementById('threat-score-value');
    if (threatScore) threatScore.textContent = analysis.threatScore || 0;

    // Update threat level
    const threatLevel = document.getElementById('threat-level');
    if (threatLevel) threatLevel.textContent = analysis.threatScore > 70 ? 'Critical' : 
                                                 analysis.threatScore > 50 ? 'High' : 
                                                 analysis.threatScore > 30 ? 'Medium' : 'Low';

    // Update confidence
    const confidence = document.getElementById('confidence-level');
    if (confidence && analysis.confidence) {
        confidence.textContent = analysis.confidence.level || 'Unknown';
    }

    // Update processing time
    const time = document.getElementById('processing-time');
    if (time) time.textContent = processingTime + 'ms';

    // Update risk factors
    const riskFactors = document.querySelector('.risk-factors-container');
    if (riskFactors && analysis.features) {
        riskFactors.innerHTML = '';
        const allRiskFactors = [
            ...(analysis.features.suspiciousKeywords || []),
            ...(analysis.features.phishingPhrases || [])
        ];
        
        if (allRiskFactors.length > 0) {
            allRiskFactors.forEach(factor => {
                const chip = document.createElement('span');
                chip.className = 'risk-factor';
                chip.textContent = factor;
                riskFactors.appendChild(chip);
            });
        } else {
            riskFactors.innerHTML = '<div class="no-risk-factors">No risk factors detected</div>';
        }
    }

    // Update explanations
    const explanationsContainer = document.querySelector('.explanations-container');
    if (explanationsContainer && analysis.explanation) {
        explanationsContainer.innerHTML = '';
        (analysis.explanation.explanations || []).forEach(exp => {
            const item = document.createElement('div');
            item.className = `explanation-item ${exp.severity || 'low'}`;
            item.innerHTML = `
                <div class="explanation-header">
                    <span class="explanation-category">${exp.category || 'Finding'}</span>
                    <span class="explanation-impact">${exp.severity || 'info'}</span>
                </div>
                <div class="explanation-description">${exp.description || ''}</div>
                <div class="explanation-details">${exp.details || ''}</div>
            `;
            explanationsContainer.appendChild(item);
        });
    }

    // Update highlighted content
    const highlightSection = document.getElementById('highlighted-content-section');
    if (highlightSection && analysis.highlightedContent) {
        highlightSection.style.display = 'block';
        const contentDiv = document.querySelector('.highlighted-content');
        if (contentDiv) {
            contentDiv.innerHTML = analysis.highlightedContent;
        }
    }

    // Scroll to results
    resultsSection?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    
    updateStats();
}

/**
 * Display URL analysis results
 */
function displayURLResults(analysis, processingTime) {
    displayEmailResults(analysis, processingTime);
}

/**
 * Update threat chart
 */
function updateThreatChart(threatScore) {
    const canvas = document.getElementById('threat-chart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const radius = 80;

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Draw background circle
    ctx.fillStyle = '#e9ecef';
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, 0, 2 * Math.PI);
    ctx.fill();

    // Draw threat score circle
    const threat = Math.min(threatScore, 100) / 100;
    const color = threatScore > 70 ? '#e74c3c' : threatScore > 50 ? '#f39c12' : '#27ae60';
    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, -Math.PI / 2, -Math.PI / 2 + 2 * Math.PI * threat);
    ctx.lineTo(centerX, centerY);
    ctx.fill();

    // Draw text
    ctx.fillStyle = '#2c3e50';
    ctx.font = 'bold 32px Arial';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(threatScore, centerX, centerY);
}

function showLoading() {
    document.getElementById('loading-indicator').style.display = 'block';
}

function hideLoading() {
    document.getElementById('loading-indicator').style.display = 'none';
}

function showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span>${message}</span>`;
    toastContainer.appendChild(toast);
    setTimeout(() => toast.remove(), 5000);
}

function switchTab(tabName) {
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
    document.getElementById(`${tabName}-tab`).classList.add('active');
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
}

// Copy all other original functions (setupCharacterCounters, updateStats, display functions, etc.)

// Event listeners
function setupEventListeners() {
    document.addEventListener('keydown', (e) => {
        if (e.ctrlKey && e.key === 'Enter') {
            if (AppState.currentTab === 'email') analyzeEmail();
        }
    });
}

// Character counters
function setupCharacterCounters() {
    ['email-input', 'url-input'].forEach(id => {
        const input = document.getElementById(id);
        const counter = document.getElementById(id.replace('input', 'char-count'));
        if (input && counter) {
            input.addEventListener('input', () => counter.textContent = input.value.length);
        }
    });
}

function loadSystemStats() {
    document.getElementById('total-analyses').textContent = AppState.totalAnalyses;
    document.getElementById('threats-detected').textContent = AppState.threatsDetected;
}

/**
 * Update application statistics
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

/**
 * Initialize application
 */
function initializeApp() {
    console.log('🚀 Initializing app...');
    setupEventListeners();
    setupCharacterCounters();
    loadSystemStats();
    checkBackendConnection(); // Add connection check
}

/**
 * Check backend connection status
 */
async function checkBackendConnection() {
    try {
        console.log('🔍 Checking backend connection...');
        const response = await fetch(`${API_BASE_URL}/api/health`, {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' }
        });
        
        if (response.ok) {
            console.log('✅ Backend connected!');
            const statusEl = document.getElementById('connection-status');
            if (statusEl) {
                statusEl.classList.remove('checking', 'disconnected');
                statusEl.classList.add('connected');
                const textEl = document.getElementById('connection-text');
                if (textEl) textEl.textContent = 'Connected';
            }
            showToast('✅ Backend connected successfully', 'success');
        } else {
            console.warn('⚠️ Backend responded with:', response.status);
            updateConnectionStatus('Error', '#e74c3c');
        }
    } catch (error) {
        console.error('❌ Backend connection failed:', error);
        updateConnectionStatus('Offline', '#e74c3c');
        showToast('❌ Cannot connect to backend. Make sure server is running on port 8081', 'error');
    }
}

/**
 * Update connection status display
 */
function updateConnectionStatus(status, color = '#27ae60') {
    const statusEl = document.getElementById('connection-status');
    if (statusEl) {
        if (status === 'Connected') {
            statusEl.classList.remove('checking', 'disconnected');
            statusEl.classList.add('connected');
        } else {
            statusEl.classList.remove('checking', 'connected');
            statusEl.classList.add('disconnected');
        }
        const textEl = document.getElementById('connection-text');
        if (textEl) {
            textEl.textContent = status;
            textEl.style.color = color;
        }
        console.log('📊 Connection status updated to:', status);
    }
}

/**
 * Show/hide results section
 */
function showResults() {
    document.getElementById('results-section').style.display = 'block';
    document.getElementById('results-section').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function hideResults() {
    document.getElementById('results-section').style.display = 'none';
}

/**
 * Sample data loading
 */
function loadSampleEmail() {
    const sampleEmails = [
        "From: support@paypa1-secure.com\nSubject: Urgent: Verify Your Account\n\nDear Valued Customer,\n\nWe have detected suspicious activity on your PayPal account. Click here to verify your identity immediately.",
        "From: admin@amazon-confirm.net\nSubject: Confirm Your Password\n\nYour Amazon account requires immediate action. Update your password to secure your account.",
        "From: security@bankofamerica-alert.com\nSubject: Action Required: Unusual Activity\n\nWe detected unusual sign-in attempts. Please verify your credentials within 24 hours."
    ];
    const email = sampleEmails[Math.floor(Math.random() * sampleEmails.length)];
    document.getElementById('email-input').value = email;
    document.getElementById('email-char-count').textContent = email.length;
}

function loadSampleURL() {
    const sampleURLs = [
        "https://paypa1.com/verify-account",
        "http://amazon-login-check.online/verify",
        "https://bankofamerica-security-check.net/update"
    ];
    const url = sampleURLs[Math.floor(Math.random() * sampleURLs.length)];
    document.getElementById('url-input').value = url;
    document.getElementById('url-char-count').textContent = url.length;
}

/**
 * Batch analysis
 */
async function batchAnalyze() {
    const batchType = document.querySelector('input[name="batch-type"]:checked').value;
    const content = document.getElementById('batch-input').value.trim();
    const items = content.split('\n').filter(item => item.trim());

    if (!items.length) {
        showToast('Please enter content for batch analysis.', 'warning');
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

function clearBatchInput() {
    document.getElementById('batch-input').value = '';
}

/**
 * Download data from backend
 */
async function downloadEmails(format = 'json') {
    try {
        const url = `${API_BASE_URL}/api/download/emails/download-${format}`;
        console.log(`📥 Downloading emails as ${format.toUpperCase()}...`);
        
        // Create a temporary link and trigger download
        const link = document.createElement('a');
        link.href = url;
        link.download = `phishing_emails_${Date.now()}.${format === 'json' ? 'json' : 'csv'}`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        console.log('✅ Emails downloaded successfully!');
        showNotification(`✅ Emails downloaded as ${format.toUpperCase()}`);
    } catch (error) {
        console.error('❌ Download failed:', error);
        showNotification('❌ Failed to download emails', true);
    }
}

async function downloadURLs(format = 'json') {
    try {
        const url = `${API_BASE_URL}/api/download/urls/download-${format}`;
        console.log(`📥 Downloading URLs as ${format.toUpperCase()}...`);
        
        // Create a temporary link and trigger download
        const link = document.createElement('a');
        link.href = url;
        link.download = `malicious_urls_${Date.now()}.${format === 'json' ? 'json' : 'csv'}`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        console.log('✅ URLs downloaded successfully!');
        showNotification(`✅ URLs downloaded as ${format.toUpperCase()}`);
    } catch (error) {
        console.error('❌ Download failed:', error);
        showNotification('❌ Failed to download URLs', true);
    }
}

/**
 * View backend data in formatted viewer
 */
async function viewEmails() {
    try {
        console.log('📊 Fetching emails data from backend...');
        const response = await fetch(`${API_BASE_URL}/api/download/emails/json`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        
        const result = await response.json();
        displayDataViewer(result.data || [], 'Emails', 'email');
    } catch (error) {
        console.error('❌ Failed to fetch emails:', error);
        showNotification('❌ Failed to fetch emails', true);
    }
}

async function viewURLs() {
    try {
        console.log('📊 Fetching URLs data from backend...');
        const response = await fetch(`${API_BASE_URL}/api/download/urls/json`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        
        const result = await response.json();
        displayDataViewer(result.data || [], 'URLs', 'url');
    } catch (error) {
        console.error('❌ Failed to fetch URLs:', error);
        showNotification('❌ Failed to fetch URLs', true);
    }
}

function displayDataViewer(data, title, type) {
    const modal = document.getElementById('data-viewer-modal');
    const titleEl = document.getElementById('data-viewer-title');
    const listEl = document.getElementById('data-viewer-list');
    const countEl = document.getElementById('data-count');
    
    titleEl.textContent = `${title} (${data.length} records)`;
    listEl.innerHTML = '';
    
    if (data.length === 0) {
        listEl.innerHTML = '<p class="empty-data">No data available</p>';
        countEl.textContent = '0 records found';
        modal.style.display = 'flex';
        return;
    }
    
    data.forEach(item => {
        const card = createDataCard(item, type);
        listEl.appendChild(card);
    });
    
    countEl.textContent = `${data.length} record(s) found`;
    modal.style.display = 'flex';
}

function createDataCard(item, type) {
    const card = document.createElement('div');
    card.className = 'data-card';
    
    let threatColor = '#28a745'; // green
    if (item.classification === 'Suspicious') threatColor = '#ffc107'; // yellow
    if (item.classification === 'Phishing' || item.classification === 'Malicious') threatColor = '#dc3545'; // red
    
    const threatIcon = item.classification === 'Safe' ? '✓' : '⚠️';
    
    if (type === 'email') {
        card.innerHTML = `
            <div class="data-card-header" style="border-left: 4px solid ${threatColor}">
                <div class="data-card-title">
                    <i class="fas fa-envelope"></i>
                    <span>${item.subject || 'No Subject'}</span>
                    <span class="threat-badge" style="background: ${threatColor}">${item.classification}</span>
                </div>
                <div class="data-card-meta">
                    <span class="timestamp"><i class="fas fa-clock"></i> ${new Date(item.timestamp).toLocaleString()}</span>
                </div>
            </div>
            <div class="data-card-body">
                <div class="data-row">
                    <span class="label">Threat Score:</span>
                    <span class="value threat-score">${item.threatScore || 0}</span>
                </div>
                <div class="data-row">
                    <span class="label">From:</span>
                    <span class="value" style="font-size: 12px; word-break: break-all;">${item.content.match(/From: (.*?)\\n/)?.[1] || 'Unknown'}</span>
                </div>
                <div class="data-row">
                    <span class="label">Risk Level:</span>
                    <span class="value">${item.analysis?.confidence?.level || 'Unknown'}</span>
                </div>
                <div class="data-row">
                    <span class="label">Phishing Probability:</span>
                    <span class="value">${item.isPhishing ? '🔴 Yes' : '🟢 No'}</span>
                </div>
            </div>
        `;
    } else {
        card.innerHTML = `
            <div class="data-card-header" style="border-left: 4px solid ${threatColor}">
                <div class="data-card-title">
                    <i class="fas fa-link"></i>
                    <span>${item.url || 'No URL'}</span>
                    <span class="threat-badge" style="background: ${threatColor}">${item.classification}</span>
                </div>
                <div class="data-card-meta">
                    <span class="timestamp"><i class="fas fa-clock"></i> ${new Date(item.timestamp).toLocaleString()}</span>
                </div>
            </div>
            <div class="data-card-body">
                <div class="data-row">
                    <span class="label">Threat Score:</span>
                    <span class="value threat-score">${item.threatScore || 0}</span>
                </div>
                <div class="data-row">
                    <span class="label">Risk Level:</span>
                    <span class="value">${item.analysis?.confidence?.level || 'Unknown'}</span>
                </div>
                <div class="data-row">
                    <span class="label">Malicious Probability:</span>
                    <span class="value">${item.isMalicious ? '🔴 Yes' : '🟢 No'}</span>
                </div>
                <div class="data-row">
                    <span class="label">Domain:</span>
                    <span class="value" style="font-size: 12px; word-break: break-all;">${item.analysis?.urlComponents?.domain || 'Unknown'}</span>
                </div>
            </div>
        `;
    }
    
    return card;
}

function closeDataViewer() {
    document.getElementById('data-viewer-modal').style.display = 'none';
}

// Export
window.AppFunctions = {
    switchTab,
    analyzeEmail,
    analyzeURL,
    batchAnalyze,
    loadSampleEmail,
    loadSampleURL,
    clearEmailInput,
    clearUrlInput,
    clearBatchInput,
    downloadEmails,
    downloadURLs,
    viewEmails,
    viewURLs,
    closeDataViewer,
    logout
};

console.log('🎯 Backend Auth Ready!');

