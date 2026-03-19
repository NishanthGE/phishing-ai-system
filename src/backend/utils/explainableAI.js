/**
 * Explainable AI Utility
 * Generates human-readable explanations for threat detection decisions
 */

class ExplainableAI {
    /**
     * Generate comprehensive explanation for email analysis
     * @param {Object} features - Extracted email features
     * @param {Object} weights - Feature weights
     * @param {number} threatScore - Calculated threat score
     * @returns {Object} Detailed explanation object
     */
    static generateEmailExplanation(features, weights, threatScore) {
        const explanations = [];
        const riskFactors = [];
        const detailedBreakdown = {};

        // Analyze suspicious keywords
        if (features.suspiciousKeywords.length > 0) {
            const impact = weights.suspiciousKeywords;
            explanations.push({
                category: 'Suspicious Keywords',
                severity: this.getSeverityLevel(impact),
                impact: impact,
                description: `Found ${features.suspiciousKeywords.length} suspicious keywords commonly used in phishing emails`,
                details: `Keywords detected: ${features.suspiciousKeywords.slice(0, 5).join(', ')}${features.suspiciousKeywords.length > 5 ? '...' : ''}`,
                recommendation: 'Be cautious of emails containing urgent or suspicious language'
            });
            riskFactors.push(...features.suspiciousKeywords.slice(0, 3));
            detailedBreakdown.suspiciousKeywords = impact;
        }

        // Analyze phishing phrases
        if (features.phishingPhrases.length > 0) {
            const impact = weights.phishingPhrases;
            explanations.push({
                category: 'Phishing Phrases',
                severity: 'high',
                impact: impact,
                description: `Contains ${features.phishingPhrases.length} known phishing phrases`,
                details: `Phrases: ${features.phishingPhrases.join(', ')}`,
                recommendation: 'These phrases are commonly used to trick users into revealing personal information'
            });
            riskFactors.push(...features.phishingPhrases);
            detailedBreakdown.phishingPhrases = impact;
        }

        // Analyze urgency indicators
        if (features.urgencyIndicators.length > 0) {
            const impact = weights.urgencyIndicators;
            explanations.push({
                category: 'Urgency Tactics',
                severity: this.getSeverityLevel(impact),
                impact: impact,
                description: `Uses ${features.urgencyIndicators.length} urgency indicators to pressure immediate action`,
                details: `Urgency phrases: ${features.urgencyIndicators.join(', ')}`,
                recommendation: 'Legitimate organizations rarely require immediate action under threat'
            });
            detailedBreakdown.urgencyTactics = impact;
        }

        // Analyze personal information requests
        if (features.personalInfoRequests.length > 0) {
            const impact = weights.personalInfoRequests;
            explanations.push({
                category: 'Personal Information Request',
                severity: 'high',
                impact: impact,
                description: `Requests ${features.personalInfoRequests.length} types of sensitive personal information`,
                details: `Information requested: ${features.personalInfoRequests.join(', ')}`,
                recommendation: 'Never provide sensitive information via email, even if it appears legitimate'
            });
            detailedBreakdown.personalInfoRequests = impact;
        }

        // Analyze suspicious domains
        if (features.suspiciousDomains.length > 0) {
            const impact = weights.suspiciousDomains;
            explanations.push({
                category: 'Suspicious Domains',
                severity: 'high',
                impact: impact,
                description: `Links to ${features.suspiciousDomains.length} suspicious or known malicious domains`,
                details: `Domains: ${features.suspiciousDomains.join(', ')}`,
                recommendation: 'Verify domain authenticity before clicking any links'
            });
            detailedBreakdown.suspiciousDomains = impact;
        }

        // Analyze URL count
        if (weights.multipleUrls > 0) {
            explanations.push({
                category: 'Multiple URLs',
                severity: 'medium',
                impact: weights.multipleUrls,
                description: `Contains ${features.urlCount} URLs, which is unusual for legitimate emails`,
                details: 'Legitimate emails typically contain fewer links',
                recommendation: 'Be cautious of emails with many links'
            });
            detailedBreakdown.multipleUrls = weights.multipleUrls;
        }

        // Analyze language patterns
        if (weights.allCaps > 0) {
            explanations.push({
                category: 'Aggressive Language',
                severity: 'medium',
                impact: weights.allCaps,
                description: `Uses excessive capital letters (${(features.capsRatio * 100).toFixed(1)}% of text)`,
                details: 'Excessive capitalization is often used to create urgency or grab attention',
                recommendation: 'Professional communications typically use proper capitalization'
            });
            detailedBreakdown.aggressiveLanguage = weights.allCaps;
        }

        // Analyze sentiment
        if (weights.negativeSentiment > 0) {
            explanations.push({
                category: 'Negative Sentiment',
                severity: 'medium',
                impact: weights.negativeSentiment,
                description: `Email has negative sentiment score (${features.sentimentScore.toFixed(2)})`,
                details: 'Phishing emails often use fear, urgency, or negative emotions',
                recommendation: 'Be wary of emails that create anxiety or pressure'
            });
            detailedBreakdown.negativeSentiment = weights.negativeSentiment;
        }

        return {
            explanations,
            riskFactors,
            detailedBreakdown,
            recommendation: this.getOverallRecommendation(threatScore),
            confidence: this.calculateConfidence(explanations.length, threatScore),
            summary: this.generateSummary(threatScore, explanations.length)
        };
    }

    /**
     * Generate comprehensive explanation for URL analysis
     * @param {Object} features - Extracted URL features
     * @param {Object} weights - Feature weights
     * @param {number} threatScore - Calculated threat score
     * @returns {Object} Detailed explanation object
     */
    static generateUrlExplanation(features, weights, threatScore) {
        const explanations = [];
        const riskFactors = [];
        const detailedBreakdown = {};

        // Analyze IP address usage
        if (weights.ipAddress > 0) {
            explanations.push({
                category: 'IP Address Usage',
                severity: 'high',
                impact: weights.ipAddress,
                description: 'Uses IP address instead of domain name',
                details: `IP address: ${features.domain}`,
                recommendation: 'Legitimate websites use domain names, not IP addresses'
            });
            riskFactors.push('IP Address');
            detailedBreakdown.ipAddress = weights.ipAddress;
        }

        // Analyze URL length
        if (weights.longUrl > 0) {
            explanations.push({
                category: 'Suspicious URL Length',
                severity: this.getSeverityLevel(weights.longUrl),
                impact: weights.longUrl,
                description: `URL is ${features.length} characters long, which is unusually long`,
                details: 'Long URLs are often used to hide malicious content or confuse users',
                recommendation: 'Be cautious of extremely long URLs'
            });
            detailedBreakdown.longUrl = weights.longUrl;
        }

        // Analyze subdomain count
        if (weights.manySubdomains > 0) {
            explanations.push({
                category: 'Multiple Subdomains',
                severity: this.getSeverityLevel(weights.manySubdomains),
                impact: weights.manySubdomains,
                description: `Has ${features.subdomainCount} subdomains, which may indicate obfuscation`,
                details: 'Excessive subdomains can be used to make malicious URLs appear legitimate',
                recommendation: 'Verify the main domain is legitimate'
            });
            detailedBreakdown.manySubdomains = weights.manySubdomains;
        }

        // Analyze suspicious keywords
        if (weights.suspiciousKeywords > 0) {
            explanations.push({
                category: 'Suspicious Keywords',
                severity: this.getSeverityLevel(weights.suspiciousKeywords),
                impact: weights.suspiciousKeywords,
                description: `Contains ${features.suspiciousKeywords.length} suspicious keywords`,
                details: `Keywords: ${features.suspiciousKeywords.join(', ')}`,
                recommendation: 'Be wary of URLs containing security-related keywords'
            });
            riskFactors.push(...features.suspiciousKeywords.slice(0, 3));
            detailedBreakdown.suspiciousKeywords = weights.suspiciousKeywords;
        }

        // Analyze phishing indicators
        if (weights.phishingIndicators > 0) {
            explanations.push({
                category: 'Phishing Indicators',
                severity: 'high',
                impact: weights.phishingIndicators,
                description: 'Contains patterns commonly used in phishing URLs',
                details: `Patterns: ${features.maliciousPatterns.join(', ')}`,
                recommendation: 'These patterns are frequently used to impersonate legitimate services'
            });
            riskFactors.push(...features.maliciousPatterns);
            detailedBreakdown.phishingIndicators = weights.phishingIndicators;
        }

        // Analyze URL shortener
        if (weights.urlShortener > 0) {
            explanations.push({
                category: 'URL Shortener',
                severity: 'high',
                impact: weights.urlShortener,
                description: 'Uses URL shortening service, hiding the actual destination',
                details: 'URL shorteners can be used to hide malicious destinations',
                recommendation: 'Use URL expander tools to see the real destination before clicking'
            });
            riskFactors.push('URL Shortener');
            detailedBreakdown.urlShortener = weights.urlShortener;
        }

        // Analyze suspicious TLD
        if (weights.suspiciousTLD > 0) {
            explanations.push({
                category: 'Suspicious Top-Level Domain',
                severity: 'medium',
                impact: weights.suspiciousTLD,
                description: 'Uses a TLD commonly associated with malicious websites',
                details: 'Some TLDs are frequently used for malicious purposes',
                recommendation: 'Exercise extra caution with uncommon TLDs'
            });
            detailedBreakdown.suspiciousTLD = weights.suspiciousTLD;
        }

        // Analyze HTTPS usage
        if (weights.noHttps > 0) {
            explanations.push({
                category: 'No HTTPS Encryption',
                severity: 'medium',
                impact: weights.noHttps,
                description: 'Does not use secure HTTPS protocol',
                details: 'HTTPS provides encryption and authentication',
                recommendation: 'Avoid entering sensitive information on non-HTTPS sites'
            });
            detailedBreakdown.noHttps = weights.noHttps;
        }

        // Analyze special characters
        if (weights.specialChars > 0) {
            explanations.push({
                category: 'Excessive Special Characters',
                severity: 'medium',
                impact: weights.specialChars,
                description: `Contains ${features.specialCharCount} special characters, potentially for obfuscation`,
                details: 'Excessive special characters may indicate URL manipulation',
                recommendation: 'Be cautious of URLs with many special characters'
            });
            detailedBreakdown.specialChars = weights.specialChars;
        }

        // Analyze suspicious port
        if (weights.suspiciousPort > 0) {
            explanations.push({
                category: 'Suspicious Port',
                severity: 'medium',
                impact: weights.suspiciousPort,
                description: 'Uses a port commonly associated with development or testing',
                details: 'Legitimate websites typically use standard ports (80, 443)',
                recommendation: 'Be cautious of URLs using non-standard ports'
            });
            detailedBreakdown.suspiciousPort = weights.suspiciousPort;
        }

        return {
            explanations,
            riskFactors,
            detailedBreakdown,
            recommendation: this.getOverallRecommendation(threatScore),
            confidence: this.calculateConfidence(explanations.length, threatScore),
            summary: this.generateSummary(threatScore, explanations.length)
        };
    }

    /**
     * Get severity level based on impact score
     * @param {number} impact - Impact score
     * @returns {string} Severity level
     */
    static getSeverityLevel(impact) {
        if (impact >= 25) return 'high';
        if (impact >= 15) return 'medium';
        return 'low';
    }

    /**
     * Get overall recommendation based on threat score
     * @param {number} threatScore - Threat score (0-100)
     * @returns {Object} Recommendation object
     */
    static getOverallRecommendation(threatScore) {
        if (threatScore >= 71) {
            return {
                level: 'HIGH RISK',
                action: 'DO NOT INTERACT',
                message: 'This content appears to be malicious. Do not click links, download attachments, or provide any information.',
                color: '#dc3545'
            };
        } else if (threatScore >= 31) {
            return {
                level: 'MEDIUM RISK',
                action: 'PROCEED WITH EXTREME CAUTION',
                message: 'This content shows suspicious characteristics. Verify the sender through alternative means before taking any action.',
                color: '#ffc107'
            };
        } else {
            return {
                level: 'LOW RISK',
                action: 'LIKELY SAFE',
                message: 'This content appears to be legitimate, but always remain vigilant when sharing personal information.',
                color: '#28a745'
            };
        }
    }

    /**
     * Calculate confidence level of the analysis
     * @param {number} factorCount - Number of risk factors found
     * @param {number} threatScore - Threat score
     * @returns {Object} Confidence object
     */
    static calculateConfidence(factorCount, threatScore) {
        let confidence;
        let description;

        if (factorCount >= 5 && threatScore >= 70) {
            confidence = 'Very High';
            description = 'Multiple strong indicators detected';
        } else if (factorCount >= 3 && threatScore >= 50) {
            confidence = 'High';
            description = 'Several indicators detected';
        } else if (factorCount >= 2 && threatScore >= 30) {
            confidence = 'Medium';
            description = 'Some indicators detected';
        } else {
            confidence = 'Low';
            description = 'Few or no indicators detected';
        }

        return { level: confidence, description };
    }

    /**
     * Generate summary of the analysis
     * @param {number} threatScore - Threat score
     * @param {number} factorCount - Number of risk factors
     * @returns {string} Summary text
     */
    static generateSummary(threatScore, factorCount) {
        if (threatScore >= 71) {
            return `High threat detected with ${factorCount} risk factors. This content is likely malicious.`;
        } else if (threatScore >= 31) {
            return `Moderate threat detected with ${factorCount} risk factors. Exercise caution.`;
        } else {
            return `Low threat detected with ${factorCount} risk factors. Content appears safe.`;
        }
    }

    /**
     * Highlight suspicious content in text
     * @param {string} content - Original content
     * @param {Array} riskFactors - Array of risk factors to highlight
     * @returns {string} Content with highlighted risk factors
     */
    static highlightSuspiciousContent(content, riskFactors) {
        let highlightedContent = content;
        
        // Sort risk factors by length (longest first) to avoid partial replacements
        const sortedFactors = riskFactors.sort((a, b) => b.length - a.length);
        
        sortedFactors.forEach(factor => {
            const regex = new RegExp(`(${this.escapeRegExp(factor)})`, 'gi');
            highlightedContent = highlightedContent.replace(regex, 
                '<mark class="suspicious-highlight" title="Suspicious content detected">$1</mark>'
            );
        });

        return highlightedContent;
    }

    /**
     * Escape special characters for regex
     * @param {string} string - String to escape
     * @returns {string} Escaped string
     */
    static escapeRegExp(string) {
        return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
}

module.exports = ExplainableAI;