/**
 * Feature Extraction Utility
 * Extracts features from emails and URLs for AI-based threat detection
 */

const natural = require('natural');
const path = require('path');

// Load datasets from project root
const phishingData = require(path.join(__dirname, '../../../datasets/phishing_keywords.json'));
const urlData = require(path.join(__dirname, '../../../datasets/malicious_url_patterns.json'));

class FeatureExtractor {
    /**
     * Extract comprehensive features from email content
     * @param {string} emailContent - The email content to analyze
     * @returns {Object} Extracted features object
     */
    static extractEmailFeatures(emailContent) {
        const features = {
            // Basic metrics
            length: emailContent.length,
            wordCount: emailContent.split(/\s+/).length,
            
            // Suspicious content detection
            suspiciousKeywords: [],
            phishingPhrases: [],
            urgencyIndicators: [],
            personalInfoRequests: [],
            
            // Advanced AI detection
            hasHtmlContent: false,
            hasHiddenText: false,
            hasFormFields: false,
            hasClickablLinks: false,
            brandMismatch: false,
            senderRedFlags: 0,
            
            // URL analysis
            urlCount: 0,
            suspiciousUrls: [],
            suspiciousDomains: [],
            urlMismatches: [],
            
            // Language analysis
            hasUrgentLanguage: false,
            hasPersonalInfoRequest: false,
            hasMultipleExclamations: false,
            hasAllCaps: false,
            urgencyScore: 0,
            
            // Sentiment and structure
            sentimentScore: 0,
            exclamationCount: 0,
            questionCount: 0,
            capsRatio: 0,
            
            // Advanced behavioral patterns
            requestsImmedediateAction: false,
            urgencyProximityScore: 0,
            contextualSuspicionScore: 0
        };

        const lowerContent = emailContent.toLowerCase();
        
        // Advanced keyword matching with fuzzy logic
        phishingData.suspicious_keywords.forEach(keyword => {
            const keywordLower = keyword.toLowerCase();
            // Check exact match and partial matches
            if (lowerContent.includes(keywordLower)) {
                features.suspiciousKeywords.push(keyword);
            }
        });

        // Extract phishing phrases with context analysis
        phishingData.phishing_phrases.forEach(phrase => {
            const phraseLower = phrase.toLowerCase();
            if (lowerContent.includes(phraseLower)) {
                features.phishingPhrases.push(phrase);
                // Check for ACTION + URGENCY combination (strong indicator)
                if ((phraseLower.includes('click') || phraseLower.includes('confirm') || phraseLower.includes('verify')) &&
                    (phraseLower.includes('now') || phraseLower.includes('immediately') || phraseLower.includes('urgent'))) {
                    features.contextualSuspicionScore += 15;
                }
            }
        });

        // Extract urgency indicators with proximity analysis
        let urgencyCount = 0;
        phishingData.urgency_indicators.forEach(indicator => {
            const indicatorLower = indicator.toLowerCase();
            if (lowerContent.includes(indicatorLower)) {
                features.urgencyIndicators.push(indicator);
                features.hasUrgentLanguage = true;
                urgencyCount++;
            }
        });
        
        // Multiple urgency indicators = higher suspicion
        if (urgencyCount >= 3) {
            features.urgencyScore = Math.min(urgencyCount * 8, 40);
            features.requestsImmedediateAction = true;
        }

        // Extract personal info requests with context
        phishingData.personal_info_requests.forEach(request => {
            const requestLower = request.toLowerCase();
            if (lowerContent.includes(requestLower)) {
                features.personalInfoRequests.push(request);
                features.hasPersonalInfoRequest = true;
                // Combination of info request + urgency = highly suspicious
                if (features.hasUrgentLanguage) {
                    features.contextualSuspicionScore += 20;
                }
            }
        });

        // Analyze URLs in email with advanced detection
        const urlRegex = /https?:\/\/[^\s"'<>)]+/gi;
        const urlMatches = emailContent.match(urlRegex) || [];
        features.urlCount = urlMatches.length;

        // Extract links with display text for mismatch detection
        const linkRegex = /\[([^\]]+)\]\(([^)]+)\)|<a[^>]*href=["']([^"']+)["'][^>]*>([^<]+)<\/a>/gi;
        let linkMatch;
        while ((linkMatch = linkRegex.exec(emailContent)) !== null) {
            const displayText = linkMatch[1] || linkMatch[4] || '';
            const actualUrl = linkMatch[2] || linkMatch[3] || '';
            
            // Check for URL spoofing (display text doesn't match actual URL)
            if (displayText && actualUrl && !actualUrl.includes(displayText)) {
                features.urlMismatches.push({
                    displayed: displayText,
                    actual: actualUrl
                });
                features.contextualSuspicionScore += 25; // Very high suspicion
            }
        }

        urlMatches.forEach(url => {
            // Check for suspicious domains
            let isSuspicious = false;
            phishingData.suspicious_domains.forEach(domain => {
                if (url.toLowerCase().includes(domain.toLowerCase())) {
                    features.suspiciousDomains.push(domain);
                    features.suspiciousUrls.push(url);
                    isSuspicious = true;
                }
            });

            // Advanced URL analysis
            if (!isSuspicious) {
                // Check for IP addresses (common phishing tactic)
                if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
                    features.contextualSuspicionScore += 30;
                    features.suspiciousUrls.push(url);
                }
                
                // Check for URL shorteners
                const shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'short.link'];
                if (shorteners.some(s => url.includes(s))) {
                    features.contextualSuspicionScore += 15;
                    features.suspiciousUrls.push(url);
                }
                
                // Check for suspicious path patterns (e.g., admin, login, account)
                const suspiciousPaths = ['admin', 'login', 'account', 'confirm', 'verify', 'secure', 'update'];
                if (suspiciousPaths.some(path => url.toLowerCase().includes('/' + path))) {
                    features.contextualSuspicionScore += 10;
                }
            }
        });

        // Detect brand impersonation - check for legitimate brand names with suspicious domains
        const legitmiateBrands = ['paypal', 'amazon', 'microsoft', 'google', 'apple', 'facebook', 'netflix'];
        legitmiateBrands.forEach(brand => {
            if (lowerContent.includes(brand)) {
                // Check if mention is paired with suspicious domain
                features.suspiciousUrls.forEach(url => {
                    if (!url.includes(brand)) {
                        features.brandMismatch = true;
                        features.contextualSuspicionScore += 20;
                    }
                });
            }
        });

        // HTML/Email structure analysis
        features.hasHtmlContent = /(<html|<body|<div|<span|<style)/i.test(emailContent);
        features.hasFormFields = /(<form|<input|<textarea|<button)/i.test(emailContent);
        features.hasClickablLinks = /(<a\s+href|<button)/i.test(emailContent);
        
        // Hidden text detection (common in phishing)
        features.hasHiddenText = /(style=.*display\s*:\s*none|color.*:#?fff|opacity\s*:\s*0|display\s*:\s*none)/i.test(emailContent);
        if (features.hasHiddenText) {
            features.contextualSuspicionScore += 20;
        }

        // Sender analysis (basic - check for generic greetings)
        const genericGreetings = ['dear user', 'dear customer', 'dear sir', 'dear madam', 'valued customer'];
        if (genericGreetings.some(greeting => lowerContent.includes(greeting))) {
            features.senderRedFlags++;
            features.contextualSuspicionScore += 8;
        }

        // Language pattern analysis
        features.exclamationCount = (emailContent.match(/!/g) || []).length;
        features.questionCount = (emailContent.match(/\?/g) || []).length;
        features.hasMultipleExclamations = features.exclamationCount > 2;
        
        // Multiple exclamations is suspicious
        if (features.hasMultipleExclamations) {
            features.contextualSuspicionScore += 8;
        }

        // Calculate caps ratio
        const capsCount = (emailContent.match(/[A-Z]/g) || []).length;
        const letterCount = (emailContent.match(/[a-zA-Z]/g) || []).length;
        features.capsRatio = letterCount > 0 ? capsCount / letterCount : 0;
        features.hasAllCaps = features.capsRatio > 0.3;
        
        if (features.hasAllCaps) {
            features.contextualSuspicionScore += 5;
        }

        // Sentiment analysis using Natural library
        try {
            const analyzer = new natural.SentimentAnalyzer('English', 
                natural.PorterStemmer, ['negation']);
            const tokenizer = new natural.WordTokenizer();
            const tokens = tokenizer.tokenize(emailContent);
            
            if (tokens && tokens.length > 0) {
                const stemmedTokens = tokens.map(token => 
                    natural.PorterStemmer.stem(token.toLowerCase())
                );
                features.sentimentScore = analyzer.getSentiment(stemmedTokens);
                
                // Negative sentiment in phishing context
                if (features.sentimentScore < -0.3 && features.hasUrgentLanguage) {
                    features.contextualSuspicionScore += 12;
                }
            }
        } catch (error) {
            console.warn('Sentiment analysis failed:', error.message);
            features.sentimentScore = 0;
        }

        return features;
    }

    /**
     * Extract comprehensive features from URL
     * @param {string} url - The URL to analyze
     * @returns {Object} Extracted features object
     */
    static extractUrlFeatures(url) {
        const features = {
            // Basic metrics
            originalUrl: url,
            length: url.length,
            
            // Structure analysis
            protocol: '',
            domain: '',
            path: '',
            hasIP: false,
            subdomainCount: 0,
            pathDepth: 0,
            
            // Security indicators
            httpsUsed: false,
            hasPort: false,
            suspiciousPort: false,
            
            // Content analysis
            suspiciousKeywords: [],
            maliciousPatterns: [],
            specialCharCount: 0,
            
            // Classification flags
            isShortener: false,
            hasSuspiciousTLD: false,
            hasPhishingIndicators: false,
            
            // Risk factors
            riskFactors: []
        };

        try {
            // Parse URL components
            const urlObj = new URL(url);
            features.protocol = urlObj.protocol;
            features.domain = urlObj.hostname;
            features.path = urlObj.pathname;
            features.httpsUsed = urlObj.protocol === 'https:';
            features.hasPort = urlObj.port !== '';
            
            // Check for suspicious ports
            if (features.hasPort) {
                features.suspiciousPort = urlData.suspicious_patterns.suspicious_ports
                    .includes(urlObj.port);
            }

        } catch (error) {
            // Invalid URL format
            features.riskFactors.push('Invalid URL format');
            return features;
        }

        // Check for IP address instead of domain
        const ipRegex = new RegExp(urlData.suspicious_patterns.ip_address_regex);
        features.hasIP = ipRegex.test(features.domain);

        // Count subdomains
        const domainParts = features.domain.split('.');
        features.subdomainCount = Math.max(0, domainParts.length - 2);

        // Calculate path depth
        features.pathDepth = features.path.split('/').filter(part => part.length > 0).length;

        // Check for suspicious keywords
        urlData.malicious_keywords.forEach(keyword => {
            if (url.toLowerCase().includes(keyword)) {
                features.suspiciousKeywords.push(keyword);
            }
        });

        // Check for phishing indicators
        urlData.phishing_indicators.forEach(indicator => {
            if (url.toLowerCase().includes(indicator)) {
                features.maliciousPatterns.push(indicator);
                features.hasPhishingIndicators = true;
            }
        });

        // Count special characters
        urlData.suspicious_patterns.suspicious_chars.forEach(char => {
            const count = (url.match(new RegExp(`\\${char}`, 'g')) || []).length;
            features.specialCharCount += count;
        });

        // Check if URL shortener
        features.isShortener = urlData.url_shorteners.some(shortener => 
            url.includes(shortener)
        );

        // Check for suspicious TLD
        features.hasSuspiciousTLD = urlData.suspicious_tlds.some(tld => 
            url.toLowerCase().includes(tld)
        );

        // Compile risk factors
        if (features.hasIP) features.riskFactors.push('Uses IP address');
        if (features.length > urlData.suspicious_patterns.max_safe_length) {
            features.riskFactors.push('Unusually long URL');
        }
        if (features.subdomainCount > urlData.suspicious_patterns.max_safe_subdomains) {
            features.riskFactors.push('Too many subdomains');
        }
        if (features.isShortener) features.riskFactors.push('URL shortener');
        if (!features.httpsUsed) features.riskFactors.push('No HTTPS');
        if (features.hasSuspiciousTLD) features.riskFactors.push('Suspicious TLD');
        if (features.suspiciousPort) features.riskFactors.push('Suspicious port');

        return features;
    }

    /**
     * Calculate feature importance weights
     * @param {Object} features - Extracted features
     * @param {string} type - 'email' or 'url'
     * @returns {Object} Weighted feature scores
     */
    static calculateFeatureWeights(features, type) {
        const weights = {};

        if (type === 'email') {
            // Enhanced weight calculations with boost for combinations
            weights.suspiciousKeywords = Math.min(features.suspiciousKeywords.length * 10, 40);
            weights.phishingPhrases = Math.min(features.phishingPhrases.length * 18, 50);
            weights.urgencyIndicators = Math.min(features.urgencyIndicators.length * 15, 35);
            weights.personalInfoRequests = Math.min(features.personalInfoRequests.length * 25, 40);
            
            // URL-based threats
            weights.suspiciousDomains = Math.min(features.suspiciousDomains.length * 30, 45);
            weights.suspiciousUrls = Math.min(features.suspiciousUrls.length * 20, 35);
            weights.urlMismatches = Math.min(features.urlMismatches.length * 40, 50); // Very high
            
            // Structural threats
            weights.multipleUrls = features.urlCount > 3 ? 15 : (features.urlCount > 1 ? 8 : 0);
            weights.urgentLanguage = features.hasUrgentLanguage ? 18 : 0;
            weights.allCaps = features.hasAllCaps ? 12 : 0;
            weights.multipleExclamations = features.hasMultipleExclamations ? 12 : 0;
            
            // Advanced detection
            weights.htmlContent = features.hasHtmlContent ? 8 : 0;
            weights.formFields = features.hasFormFields ? 20 : 0;
            weights.clickableLinks = features.hasClickablLinks ? 12 : 0;
            weights.hiddenText = features.hasHiddenText ? 30 : 0; // Very suspicious
            weights.brandMismatch = features.brandMismatch ? 25 : 0;
            weights.genericGreeting = features.senderRedFlags > 0 ? 10 : 0;
            
            // Sentiment and context
            weights.negativeSentiment = features.sentimentScore < -0.3 ? 15 : 0;
            weights.contextualSuspicion = Math.min(features.contextualSuspicionScore, 50);
            
            // Boost for immediate action requests
            weights.immediateActionRequest = features.requestsImmedediateAction ? 20 : 0;
        } else if (type === 'url') {
            weights.ipAddress = features.hasIP ? 50 : 0;
            weights.longUrl = features.length > 100 ? Math.min((features.length - 100) / 5, 30) : 0;
            weights.manySubdomains = features.subdomainCount > 3 ? Math.min(features.subdomainCount * 10, 35) : 0;
            weights.suspiciousKeywords = Math.min(features.suspiciousKeywords.length * 15, 35);
            weights.phishingIndicators = features.hasPhishingIndicators ? 30 : 0;
            weights.urlShortener = features.isShortener ? 25 : 0;
            weights.suspiciousTLD = features.hasSuspiciousTLD ? 20 : 0;
            weights.noHttps = !features.httpsUsed ? 15 : 0;
            weights.specialChars = features.specialCharCount > 8 ? 15 : 0;
            weights.suspiciousPort = features.suspiciousPort ? 20 : 0;
            weights.maliciousPatterns = Math.min(features.maliciousPatterns.length * 12, 40);
        }

        return weights;
    }
}

module.exports = FeatureExtractor;