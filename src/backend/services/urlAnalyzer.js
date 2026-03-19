/**
 * URL Analyzer Service
 * Now powered by Random Forest ML engine (aiEngine.js)
 */

'use strict';

const { classifyURL }  = require('../utils/aiEngine');
const FeatureExtractor = require('../utils/featureExtractor');
const validator        = require('validator');

class URLAnalyzer {
    /**
     * Analyze URL for malicious indicators
     * @param {string} url
     * @returns {Object} Analysis results
     */
    static async analyzeURL(url) {
        // Validate first
        const validation = this.validateURL(url);
        if (!validation.isValid) throw new Error(validation.errors.join(', '));

        const normalizedUrl = this.normalizeURL(url);
        const startTime     = Date.now();

        try {
            // ── ML Classification ──────────────────────────────────────────
            const mlResult = classifyURL(normalizedUrl);

            // ── Legacy feature extraction (kept for rich display) ──────────
            const features = FeatureExtractor.extractUrlFeatures(normalizedUrl);
            const securityChecks = await this.performSecurityChecks(normalizedUrl, features);

            const processingTime = Date.now() - startTime;

            const result = {
                // Core
                originalUrl:     url,
                normalizedUrl,
                classification:  mlResult.label,
                threatScore:     mlResult.threatScore,
                confidence:      mlResult.confidence,

                // URL components
                urlComponents: {
                    protocol:  features.protocol,
                    domain:    features.domain,
                    path:      features.path,
                    hasPort:   features.hasPort,
                    httpsUsed: features.httpsUsed
                },

                // Features (ML-augmented)
                features: {
                    length:              features.length,
                    subdomainCount:      features.subdomainCount,
                    pathDepth:           features.pathDepth,
                    specialCharCount:    features.specialCharCount,
                    suspiciousKeywords:  mlResult.features.suspiciousKeywords,
                    maliciousPatterns:   mlResult.features.maliciousPatterns,
                    hasIP:               features.hasIP,
                    isShortener:         features.isShortener,
                    hasSuspiciousTLD:    features.hasSuspiciousTLD,
                    hasPhishingIndicators: features.hasPhishingIndicators,
                    riskFactors:         mlResult.explanation.riskFactors.map(r => r.title)
                },

                // Security checks
                securityChecks,

                // ML engine details
                mlEngine: {
                    name:      mlResult.engine,
                    rawScore:  mlResult.threatScore,
                    confidence: mlResult.confidence,
                    treeVotes: mlResult.explanation.treeVotes,
                },

                // Explanation
                explanation: {
                    summary:           mlResult.explanation.summary,
                    riskFactors:       mlResult.explanation.riskFactors,
                    explanations:      mlResult.explanation.riskFactors.map(r => r.description),
                    recommendation:    mlResult.explanation.recommendation,
                    detailedBreakdown: mlResult.explanation.riskFactors
                },

                // Metadata
                metadata: {
                    analysisTimestamp: new Date().toISOString(),
                    processingTime,
                    version: '3.0.0-ML'
                }
            };

            console.log(`🔗 [ML] URL → ${result.classification} (score: ${result.threatScore}) — ${features.domain} in ${processingTime}ms`);
            return result;

        } catch (err) {
            console.error('URL ML analysis error:', err.message);
            throw new Error(`URL analysis failed: ${err.message}`);
        }
    }

    /** Perform extra security checks (SSL, reputation, redirect) */
    static async performSecurityChecks(url, features) {
        const checks = { sslCertificate: null, reputation: null, redirectChain: null };
        try {
            checks.sslCertificate = {
                hasSSL:         features.httpsUsed,
                status:         features.httpsUsed ? 'valid' : 'missing',
                recommendation: features.httpsUsed
                    ? 'SSL certificate present'
                    : 'No SSL certificate — avoid entering sensitive data'
            };
            checks.reputation   = this.analyzeDomainReputation(features.domain);
            checks.redirectChain = this.analyzeRedirectPatterns(url);
        } catch (e) {
            console.warn('Security checks failed:', e.message);
        }
        return checks;
    }

    static analyzeDomainReputation(domain) {
        const knownGood = ['google.com','microsoft.com','amazon.com','paypal.com',
                           'facebook.com','apple.com','netflix.com','github.com'];
        const knownBad  = ['paypal-security','amazon-update','microsoft-support',
                           'google-verification','facebook-security','apple-id-verify'];
        if (knownGood.some(g => domain.endsWith(g)))
            return { score: 'good',    confidence: 'high',   description: 'Domain appears to be legitimate' };
        if (knownBad.some(b => domain.includes(b)))
            return { score: 'bad',     confidence: 'high',   description: 'Domain appears to impersonate a legitimate service' };
        return     { score: 'unknown', confidence: 'medium', description: 'Domain reputation unknown — exercise caution' };
    }

    static analyzeRedirectPatterns(url) {
        const redirectParams      = ['redirect=','url=','goto=','link=','target='];
        const hasSuspiciousRedirect = redirectParams.some(p => url.toLowerCase().includes(p));
        return {
            hasSuspiciousRedirect,
            riskLevel:   hasSuspiciousRedirect ? 'medium' : 'low',
            description: hasSuspiciousRedirect
                ? 'URL contains redirect parameters'
                : 'No suspicious redirect patterns detected'
        };
    }

    /** Batch analyze */
    static async batchAnalyzeURLs(urls) {
        if (!Array.isArray(urls))  throw new Error('URLs must be an array');
        if (urls.length > 20)      throw new Error('Maximum 20 URLs per batch');
        const results = [];
        for (let i = 0; i < urls.length; i++) {
            try {
                const result = await this.analyzeURL(urls[i]);
                results.push({ index: i, success: true, result });
            } catch (err) {
                results.push({ index: i, success: false, error: err.message, url: urls[i] });
            }
        }
        return results;
    }

    static validateURL(url) {
        const v = { isValid: true, errors: [], warnings: [] };
        if (!url)                                { v.isValid = false; v.errors.push('URL is required'); return v; }
        if (typeof url !== 'string')             { v.isValid = false; v.errors.push('URL must be a string'); return v; }
        const t = url.trim();
        if (t.length === 0)                      { v.isValid = false; v.errors.push('URL cannot be empty'); return v; }
        if (t.length > 2000)                     { v.isValid = false; v.errors.push('URL too long (max 2000 chars)'); return v; }
        if (!validator.isURL(t, { protocols: ['http','https'], require_protocol: true }))
                                                 { v.isValid = false; v.errors.push('Invalid URL format'); return v; }
        if (t.length > 100)        v.warnings.push('URL is unusually long');
        if (!t.startsWith('https://')) v.warnings.push('URL does not use HTTPS');
        return v;
    }

    static normalizeURL(url) {
        try {
            const u = new URL(url.trim());
            if (u.pathname.endsWith('/') && u.pathname.length > 1)
                u.pathname = u.pathname.slice(0, -1);
            u.hostname = u.hostname.toLowerCase();
            return u.toString();
        } catch { return url.trim(); }
    }

    static getAnalysisStats() {
        return {
            engine: 'Random Forest ML (v3.0)',
            totalAnalyses:   0,
            maliciousUrls:   0,
            suspiciousUrls:  0,
            safeUrls:        0,
            averageThreatScore: 0,
            lastAnalysis: null,
        };
    }
}

module.exports = URLAnalyzer;