/**
 * Email Controller
 * Handles HTTP requests for email phishing analysis
 */

const EmailAnalyzer = require('../services/emailAnalyzer');
const dataStore = require('../utils/dataStore');
const fileStore = require('../store/dataStore');

class EmailController {
    /**
     * Analyze single email for phishing indicators
     * POST /api/analyze-email
     */
    static async analyzeEmail(req, res) {
        try {
            const { emailContent } = req.body;

            // Log incoming data
            console.log('\n📧 EMAIL ANALYSIS REQUEST RECEIVED');
            console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
            console.log('⏰ Timestamp:', new Date().toISOString());
            console.log('📝 Email Content Length:', emailContent ? emailContent.length : 0, 'characters');
            if (emailContent) {
                console.log('📄 Preview:', emailContent.substring(0, 100) + (emailContent.length > 100 ? '...' : ''));
            }

            // Validate request body
            if (!emailContent) {
                console.log('❌ Error: Email content is required');
                return res.status(400).json({
                    success: false,
                    error: 'Email content is required',
                    code: 'MISSING_EMAIL_CONTENT'
                });
            }

            // Validate email content
            const validation = EmailAnalyzer.validateEmailContent(emailContent);
            if (!validation.isValid) {
                return res.status(400).json({
                    success: false,
                    error: 'Invalid email content',
                    details: validation.errors,
                    code: 'INVALID_EMAIL_CONTENT'
                });
            }

            // Perform analysis
            const startTime = Date.now();
            const analysis = await EmailAnalyzer.analyzeEmail(emailContent);
            const processingTime = Date.now() - startTime;

            // Save to backend data stores (both in-memory and file-based)
            const savedRecord = dataStore.saveEmailAnalysis(emailContent, analysis);
            fileStore.saveEmail({
                subject: emailContent.match(/Subject: (.*)/)?.[1] || 'No Subject',
                content: emailContent,
                threatScore: analysis.threatScore,
                classification: analysis.classification,
                isPhishing: analysis.classification === 'phishing',
                analysis: analysis
            });

            // Log analysis results
            console.log('✅ Analysis Completed');
            console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
            console.log('🎯 Classification:', analysis.classification);
            console.log('⚠️  Threat Score:', analysis.threatScore);
            console.log('💯 Confidence:', analysis.confidence.level);
            console.log('⏱️  Processing Time:', processingTime, 'ms');
            console.log('📊 Features Found:');
            console.log('   • Suspicious Keywords:', analysis.features.suspiciousKeywords.length);
            console.log('   • Phishing Phrases:', analysis.features.phishingPhrases.length);
            console.log('   • URLs Found:', analysis.features.urlCount);
            console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

            // Return successful response
            res.json({
                success: true,
                recordId: savedRecord.id,
                data: {
                    analysis: analysis,
                    processingTime: processingTime,
                    warnings: validation.warnings
                },
                metadata: {
                    endpoint: 'analyze-email',
                    version: '2.0.0',
                    timestamp: new Date().toISOString()
                }
            });

        } catch (error) {
            console.error('Email analysis controller error:', error);
            
            res.status(500).json({
                success: false,
                error: 'Email analysis failed',
                details: error.message,
                code: 'ANALYSIS_ERROR'
            });
        }
    }

    /**
     * Batch analyze multiple emails
     * POST /api/analyze-emails-batch
     */
    static async batchAnalyzeEmails(req, res) {
        try {
            const { emails } = req.body;

            // Validate request body
            if (!emails || !Array.isArray(emails)) {
                return res.status(400).json({
                    success: false,
                    error: 'Emails array is required',
                    code: 'MISSING_EMAILS_ARRAY'
                });
            }

            if (emails.length === 0) {
                return res.status(400).json({
                    success: false,
                    error: 'At least one email is required',
                    code: 'EMPTY_EMAILS_ARRAY'
                });
            }

            if (emails.length > 10) {
                return res.status(400).json({
                    success: false,
                    error: 'Maximum 10 emails allowed per batch',
                    code: 'BATCH_SIZE_EXCEEDED'
                });
            }

            // Perform batch analysis
            const startTime = Date.now();
            const results = await EmailAnalyzer.batchAnalyzeEmails(emails);
            const processingTime = Date.now() - startTime;

            // Calculate batch statistics
            const stats = {
                total: results.length,
                successful: results.filter(r => r.success).length,
                failed: results.filter(r => !r.success).length,
                phishing: results.filter(r => r.success && r.result.classification === 'Phishing').length,
                suspicious: results.filter(r => r.success && r.result.classification === 'Suspicious').length,
                safe: results.filter(r => r.success && r.result.classification === 'Safe').length
            };

            // Return successful response
            res.json({
                success: true,
                data: {
                    results: results,
                    statistics: stats,
                    processingTime: processingTime
                },
                metadata: {
                    endpoint: 'analyze-emails-batch',
                    version: '2.0.0',
                    timestamp: new Date().toISOString()
                }
            });

        } catch (error) {
            console.error('Batch email analysis controller error:', error);
            
            res.status(500).json({
                success: false,
                error: 'Batch email analysis failed',
                details: error.message,
                code: 'BATCH_ANALYSIS_ERROR'
            });
        }
    }

    /**
     * Get email analysis statistics
     * GET /api/email-stats
     */
    static async getEmailStats(req, res) {
        try {
            const stats = EmailAnalyzer.getAnalysisStats();
            
            res.json({
                success: true,
                data: stats,
                metadata: {
                    endpoint: 'email-stats',
                    version: '2.0.0',
                    timestamp: new Date().toISOString()
                }
            });

        } catch (error) {
            console.error('Email stats controller error:', error);
            
            res.status(500).json({
                success: false,
                error: 'Failed to retrieve email statistics',
                details: error.message,
                code: 'STATS_ERROR'
            });
        }
    }

    /**
     * Validate email content format
     * POST /api/validate-email
     */
    static async validateEmail(req, res) {
        try {
            const { emailContent } = req.body;

            if (!emailContent) {
                return res.status(400).json({
                    success: false,
                    error: 'Email content is required for validation',
                    code: 'MISSING_EMAIL_CONTENT'
                });
            }

            const validation = EmailAnalyzer.validateEmailContent(emailContent);
            
            res.json({
                success: true,
                data: {
                    validation: validation,
                    contentLength: emailContent.length,
                    wordCount: emailContent.split(/\s+/).length
                },
                metadata: {
                    endpoint: 'validate-email',
                    version: '2.0.0',
                    timestamp: new Date().toISOString()
                }
            });

        } catch (error) {
            console.error('Email validation controller error:', error);
            
            res.status(500).json({
                success: false,
                error: 'Email validation failed',
                details: error.message,
                code: 'VALIDATION_ERROR'
            });
        }
    }

    /**
     * Get sample phishing email for testing
     * GET /api/sample-email
     */
    static async getSampleEmail(req, res) {
        try {
            const sampleEmails = [
                {
                    id: 1,
                    type: 'phishing',
                    subject: 'URGENT: Your Account Will Be Suspended',
                    content: `Subject: URGENT: Your Account Will Be Suspended

Dear Valued Customer,

We have detected suspicious activity on your account. Your account will be suspended within 24 hours unless you verify your information immediately.

Click here to verify your account: http://paypal-security.com/verify-account

Please provide the following information:
- Your full name
- Social Security Number  
- Credit card details
- Bank account information

This is urgent! Act now to prevent account suspension.

Best regards,
PayPal Security Team`
                },
                {
                    id: 2,
                    type: 'legitimate',
                    subject: 'Welcome to Our Service',
                    content: `Subject: Welcome to Our Service

Hello,

Thank you for signing up for our newsletter. We're excited to have you as part of our community.

You can manage your subscription preferences at any time by visiting your account settings.

If you have any questions, please don't hesitate to contact our support team.

Best regards,
The Team`
                },
                {
                    id: 3,
                    type: 'suspicious',
                    subject: 'Congratulations! You\'ve Won!',
                    content: `Subject: Congratulations! You've Won!

Dear Winner,

Congratulations! You have been selected as the winner of our monthly lottery drawing.

To claim your prize of $10,000, please click the link below and provide your banking details for the transfer.

Claim your prize: http://lottery-winner.tk/claim

This offer expires in 48 hours, so act quickly!

Best regards,
Lottery Commission`
                }
            ];

            const { type } = req.query;
            let selectedSample;

            if (type && ['phishing', 'legitimate', 'suspicious'].includes(type)) {
                selectedSample = sampleEmails.find(email => email.type === type);
            } else {
                // Return random sample
                selectedSample = sampleEmails[Math.floor(Math.random() * sampleEmails.length)];
            }

            res.json({
                success: true,
                data: {
                    sample: selectedSample,
                    availableTypes: ['phishing', 'legitimate', 'suspicious']
                },
                metadata: {
                    endpoint: 'sample-email',
                    version: '2.0.0',
                    timestamp: new Date().toISOString()
                }
            });

        } catch (error) {
            console.error('Sample email controller error:', error);
            
            res.status(500).json({
                success: false,
                error: 'Failed to retrieve sample email',
                details: error.message,
                code: 'SAMPLE_ERROR'
            });
        }
    }
}

module.exports = EmailController;