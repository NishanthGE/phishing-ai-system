/**
 * Email Analyzer Service
 * Now powered by Naive Bayes ML engine (aiEngine.js)
 * Falls back to legacy keyword scoring if ML fails
 */

'use strict';

const { classifyEmail } = require('../utils/aiEngine');
const FeatureExtractor  = require('../utils/featureExtractor');

class EmailAnalyzer {
    /**
     * Analyze email content for phishing indicators
     * @param {string} emailContent
     * @returns {Object} Analysis results
     */
    static async analyzeEmail(emailContent) {
        if (!emailContent || typeof emailContent !== 'string') {
            throw new Error('Invalid email content provided');
        }
        if (emailContent.trim().length === 0) {
            throw new Error('Email content cannot be empty');
        }
        if (emailContent.length > 100000) {
            throw new Error('Email content too large (max 100KB)');
        }

        const startTime = Date.now();

        try {
            // ── ML Classification ──────────────────────────────────────────
            const mlResult = classifyEmail(emailContent);

            // ── Legacy feature extraction (kept for rich feature display) ──
            const features = FeatureExtractor.extractEmailFeatures(emailContent);

            const processingTime = Date.now() - startTime;

            const result = {
                // Core
                classification:  mlResult.label,
                threatScore:     mlResult.threatScore,
                confidence:      mlResult.confidence,

                // Features (ML-augmented)
                features: {
                    suspiciousKeywords:   mlResult.features.suspiciousKeywords,
                    phishingPhrases:      mlResult.features.phishingPhrases,
                    safeIndicators:       mlResult.features.safeIndicators || [],
                    urgencyIndicators:    features.urgencyIndicators,
                    personalInfoRequests: features.personalInfoRequests,
                    suspiciousDomains:    features.suspiciousDomains,
                    urlCount:             features.urlCount,
                    hasUrgentLanguage:    features.hasUrgentLanguage,
                    hasPersonalInfoRequest: features.hasPersonalInfoRequest,
                    sentimentScore:       features.sentimentScore
                },

                // ML engine details
                mlEngine: {
                    name:          mlResult.engine,
                    rawScore:      mlResult.threatScore,
                    confidence:    mlResult.confidence,
                    topPhishTokens: mlResult.explanation.topPhishingTokens,
                    topSafeTokens:  mlResult.explanation.topSafeTokens,
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
                    emailLength:       emailContent.length,
                    wordCount:         features.wordCount,
                    processingTime,
                    version: '3.0.0-ML'
                }
            };

            console.log(`📧 [ML] Email → ${result.classification} (score: ${result.threatScore}) in ${processingTime}ms`);
            return result;

        } catch (err) {
            console.error('Email ML analysis error:', err.message);
            throw new Error(`Email analysis failed: ${err.message}`);
        }
    }

    /** Batch analyze multiple emails */
    static async batchAnalyzeEmails(emails) {
        if (!Array.isArray(emails)) throw new Error('Emails must be an array');
        if (emails.length > 10)    throw new Error('Maximum 10 emails per batch');

        const results = [];
        for (let i = 0; i < emails.length; i++) {
            try {
                const result = await this.analyzeEmail(emails[i]);
                results.push({ index: i, success: true, result });
            } catch (err) {
                results.push({ index: i, success: false, error: err.message });
            }
        }
        return results;
    }

    /** Validate email content */
    static validateEmailContent(emailContent) {
        const v = { isValid: true, errors: [], warnings: [] };
        if (!emailContent)                       { v.isValid = false; v.errors.push('Email content is required'); return v; }
        if (typeof emailContent !== 'string')    { v.isValid = false; v.errors.push('Email content must be a string'); return v; }
        if (emailContent.trim().length === 0)    { v.isValid = false; v.errors.push('Email content cannot be empty'); return v; }
        if (emailContent.length < 10)            v.warnings.push('Email content is very short');
        if (emailContent.length > 50000)         v.warnings.push('Email content is very long');
        return v;
    }

    static getAnalysisStats() {
        return {
            engine: 'Naive Bayes ML (v3.0)',
            totalAnalyses:    0,
            phishingDetected: 0,
            suspiciousEmails: 0,
            safeEmails:       0,
            averageThreatScore: 0,
            lastAnalysis: null,
        };
    }
}

module.exports = EmailAnalyzer;