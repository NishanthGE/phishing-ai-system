/**
 * URL Controller
 * Handles HTTP requests for malicious URL analysis
 */

const URLAnalyzer = require('../services/urlAnalyzer');
const dataStore = require('../utils/dataStore');
const fileStore = require('../store/dataStore');

class URLController {
    /**
     * Analyze single URL for malicious indicators
     * POST /api/analyze-url
     */
    static async analyzeURL(req, res) {
        try {
            const { url } = req.body;

            // Log incoming data
            console.log('\n🔗 URL ANALYSIS REQUEST RECEIVED');
            console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
            console.log('⏰ Timestamp:', new Date().toISOString());
            console.log('🌐 URL:', url);

            // Validate request body
            if (!url) {
                console.log('❌ Error: URL is required');
                return res.status(400).json({
                    success: false,
                    error: 'URL is required',
                    code: 'MISSING_URL'
                });
            }

            // Validate URL format
            const validation = URLAnalyzer.validateURL(url);
            if (!validation.isValid) {
                return res.status(400).json({
                    success: false,
                    error: 'Invalid URL format',
                    details: validation.errors,
                    code: 'INVALID_URL'
                });
            }

            // Perform analysis
            const startTime = Date.now();
            const analysis = await URLAnalyzer.analyzeURL(url);
            const processingTime = Date.now() - startTime;

            // Save to backend data stores (both in-memory and file-based)
            const savedRecord = dataStore.saveURLAnalysis(url, analysis);
            fileStore.saveURL({
                url: url,
                threatScore: analysis.threatScore,
                classification: analysis.classification,
                isMalicious: analysis.classification === 'malicious',
                analysis: analysis
            });

            // Log analysis results
            console.log('✅ Analysis Completed');
            console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
            console.log('🎯 Classification:', analysis.classification);
            console.log('⚠️  Threat Score:', analysis.threatScore);
            console.log('💯 Confidence:', analysis.confidence.level);
            console.log('⏱️  Processing Time:', processingTime, 'ms');
            console.log('🔍 URL Features:');
            console.log('   • Domain:', analysis.urlComponents.domain);
            console.log('   • Protocol:', analysis.urlComponents.protocol);
            console.log('   • Suspicious Keywords:', analysis.features.suspiciousKeywords.length);
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
                    endpoint: 'analyze-url',
                    version: '2.0.0',
                    timestamp: new Date().toISOString()
                }
            });

        } catch (error) {
            console.error('URL analysis controller error:', error);
            
            res.status(500).json({
                success: false,
                error: 'URL analysis failed',
                details: error.message,
                code: 'ANALYSIS_ERROR'
            });
        }
    }

    /**
     * Batch analyze multiple URLs
     * POST /api/analyze-urls-batch
     */
    static async batchAnalyzeURLs(req, res) {
        try {
            const { urls } = req.body;

            // Validate request body
            if (!urls || !Array.isArray(urls)) {
                return res.status(400).json({
                    success: false,
                    error: 'URLs array is required',
                    code: 'MISSING_URLS_ARRAY'
                });
            }

            if (urls.length === 0) {
                return res.status(400).json({
                    success: false,
                    error: 'At least one URL is required',
                    code: 'EMPTY_URLS_ARRAY'
                });
            }

            if (urls.length > 20) {
                return res.status(400).json({
                    success: false,
                    error: 'Maximum 20 URLs allowed per batch',
                    code: 'BATCH_SIZE_EXCEEDED'
                });
            }

            // Perform batch analysis
            const startTime = Date.now();
            const results = await URLAnalyzer.batchAnalyzeURLs(urls);
            const processingTime = Date.now() - startTime;

            // Calculate batch statistics
            const stats = {
                total: results.length,
                successful: results.filter(r => r.success).length,
                failed: results.filter(r => !r.success).length,
                malicious: results.filter(r => r.success && r.result.classification === 'Malicious').length,
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
                    endpoint: 'analyze-urls-batch',
                    version: '2.0.0',
                    timestamp: new Date().toISOString()
                }
            });

        } catch (error) {
            console.error('Batch URL analysis controller error:', error);
            
            res.status(500).json({
                success: false,
                error: 'Batch URL analysis failed',
                details: error.message,
                code: 'BATCH_ANALYSIS_ERROR'
            });
        }
    }

    /**
     * Get URL analysis statistics
     * GET /api/url-stats
     */
    static async getURLStats(req, res) {
        try {
            const stats = URLAnalyzer.getAnalysisStats();
            
            res.json({
                success: true,
                data: stats,
                metadata: {
                    endpoint: 'url-stats',
                    version: '2.0.0',
                    timestamp: new Date().toISOString()
                }
            });

        } catch (error) {
            console.error('URL stats controller error:', error);
            
            res.status(500).json({
                success: false,
                error: 'Failed to retrieve URL statistics',
                details: error.message,
                code: 'STATS_ERROR'
            });
        }
    }

    /**
     * Validate URL format
     * POST /api/validate-url
     */
    static async validateURL(req, res) {
        try {
            const { url } = req.body;

            if (!url) {
                return res.status(400).json({
                    success: false,
                    error: 'URL is required for validation',
                    code: 'MISSING_URL'
                });
            }

            const validation = URLAnalyzer.validateURL(url);
            const normalizedUrl = validation.isValid ? URLAnalyzer.normalizeURL(url) : null;
            
            res.json({
                success: true,
                data: {
                    validation: validation,
                    originalUrl: url,
                    normalizedUrl: normalizedUrl,
                    urlLength: url.length
                },
                metadata: {
                    endpoint: 'validate-url',
                    version: '2.0.0',
                    timestamp: new Date().toISOString()
                }
            });

        } catch (error) {
            console.error('URL validation controller error:', error);
            
            res.status(500).json({
                success: false,
                error: 'URL validation failed',
                details: error.message,
                code: 'VALIDATION_ERROR'
            });
        }
    }

    /**
     * Get sample URLs for testing
     * GET /api/sample-url
     */
    static async getSampleURL(req, res) {
        try {
            const sampleUrls = [
                {
                    id: 1,
                    type: 'malicious',
                    description: 'Phishing URL impersonating PayPal',
                    url: 'http://paypal-security.com/verify-account-login-update-secure'
                },
                {
                    id: 2,
                    type: 'suspicious',
                    description: 'URL shortener hiding destination',
                    url: 'https://bit.ly/urgent-verify-account'
                },
                {
                    id: 3,
                    type: 'malicious',
                    description: 'URL using IP address instead of domain',
                    url: 'http://192.168.1.100:8080/login/verify'
                },
                {
                    id: 4,
                    type: 'legitimate',
                    description: 'Legitimate PayPal URL',
                    url: 'https://www.paypal.com/signin'
                },
                {
                    id: 5,
                    type: 'suspicious',
                    description: 'Long URL with many parameters',
                    url: 'https://amazon-update.tk/verify?user=12345&token=abc123&redirect=secure-login&verify=account&update=billing'
                },
                {
                    id: 6,
                    type: 'malicious',
                    description: 'Suspicious TLD with phishing keywords',
                    url: 'https://microsoft-support.ml/urgent-security-update'
                }
            ];

            const { type } = req.query;
            let selectedSample;

            if (type && ['malicious', 'suspicious', 'legitimate'].includes(type)) {
                const filteredSamples = sampleUrls.filter(url => url.type === type);
                selectedSample = filteredSamples[Math.floor(Math.random() * filteredSamples.length)];
            } else {
                // Return random sample
                selectedSample = sampleUrls[Math.floor(Math.random() * sampleUrls.length)];
            }

            res.json({
                success: true,
                data: {
                    sample: selectedSample,
                    availableTypes: ['malicious', 'suspicious', 'legitimate'],
                    allSamples: sampleUrls
                },
                metadata: {
                    endpoint: 'sample-url',
                    version: '2.0.0',
                    timestamp: new Date().toISOString()
                }
            });

        } catch (error) {
            console.error('Sample URL controller error:', error);
            
            res.status(500).json({
                success: false,
                error: 'Failed to retrieve sample URL',
                details: error.message,
                code: 'SAMPLE_ERROR'
            });
        }
    }

    /**
     * Extract URL components for analysis
     * POST /api/extract-url-components
     */
    static async extractURLComponents(req, res) {
        try {
            const { url } = req.body;

            if (!url) {
                return res.status(400).json({
                    success: false,
                    error: 'URL is required',
                    code: 'MISSING_URL'
                });
            }

            const validation = URLAnalyzer.validateURL(url);
            if (!validation.isValid) {
                return res.status(400).json({
                    success: false,
                    error: 'Invalid URL format',
                    details: validation.errors,
                    code: 'INVALID_URL'
                });
            }

            try {
                const urlObj = new URL(url);
                const components = {
                    protocol: urlObj.protocol,
                    hostname: urlObj.hostname,
                    port: urlObj.port || (urlObj.protocol === 'https:' ? '443' : '80'),
                    pathname: urlObj.pathname,
                    search: urlObj.search,
                    hash: urlObj.hash,
                    origin: urlObj.origin,
                    href: urlObj.href
                };

                const analysis = {
                    isSecure: urlObj.protocol === 'https:',
                    hasPort: urlObj.port !== '',
                    hasQuery: urlObj.search !== '',
                    hasFragment: urlObj.hash !== '',
                    pathDepth: urlObj.pathname.split('/').filter(p => p.length > 0).length,
                    subdomainCount: urlObj.hostname.split('.').length - 2
                };

                res.json({
                    success: true,
                    data: {
                        originalUrl: url,
                        components: components,
                        analysis: analysis
                    },
                    metadata: {
                        endpoint: 'extract-url-components',
                        version: '2.0.0',
                        timestamp: new Date().toISOString()
                    }
                });

            } catch (parseError) {
                res.status(400).json({
                    success: false,
                    error: 'Failed to parse URL',
                    details: parseError.message,
                    code: 'URL_PARSE_ERROR'
                });
            }

        } catch (error) {
            console.error('URL component extraction error:', error);
            
            res.status(500).json({
                success: false,
                error: 'URL component extraction failed',
                details: error.message,
                code: 'EXTRACTION_ERROR'
            });
        }
    }
}

module.exports = URLController;