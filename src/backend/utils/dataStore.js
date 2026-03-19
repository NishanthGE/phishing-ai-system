/**
 * Data Store - In-Memory Data Storage for Analysis Results
 * Stores all email and URL analyses for backend viewing
 */

class DataStore {
    constructor() {
        this.emailAnalyses = [];
        this.urlAnalyses = [];
        this.analysisId = 1;
    }

    /**
     * Save email analysis result
     */
    saveEmailAnalysis(emailContent, analysis) {
        const record = {
            id: this.analysisId++,
            type: 'email',
            timestamp: new Date().toISOString(),
            content: emailContent.substring(0, 200), // Store preview
            fullContent: emailContent,
            threatLevel: analysis.classification,
            threatScore: analysis.threatScore,
            confidence: analysis.confidence,
            indicators: analysis.indicators,
            recommendations: analysis.recommendations,
            features: analysis.features,
            fullAnalysis: analysis
        };
        
        this.emailAnalyses.unshift(record); // Add to front
        
        // Keep only last 100 records
        if (this.emailAnalyses.length > 100) {
            this.emailAnalyses.pop();
        }
        
        return record;
    }

    /**
     * Save URL analysis result
     */
    saveURLAnalysis(url, analysis) {
        const record = {
            id: this.analysisId++,
            type: 'url',
            timestamp: new Date().toISOString(),
            url: url,
            threatLevel: analysis.classification,
            threatScore: analysis.threatScore,
            confidence: analysis.confidence,
            indicators: analysis.indicators,
            recommendations: analysis.recommendations,
            features: analysis.features,
            fullAnalysis: analysis
        };
        
        this.urlAnalyses.unshift(record); // Add to front
        
        // Keep only last 100 records
        if (this.urlAnalyses.length > 100) {
            this.urlAnalyses.pop();
        }
        
        return record;
    }

    /**
     * Get all email analyses
     */
    getEmailAnalyses(limit = 50) {
        return {
            total: this.emailAnalyses.length,
            items: this.emailAnalyses.slice(0, limit),
            limit,
            hasMore: this.emailAnalyses.length > limit
        };
    }

    /**
     * Get all URL analyses
     */
    getURLAnalyses(limit = 50) {
        return {
            total: this.urlAnalyses.length,
            items: this.urlAnalyses.slice(0, limit),
            limit,
            hasMore: this.urlAnalyses.length > limit
        };
    }

    /**
     * Get all analyses (combined)
     */
    getAllAnalyses(limit = 100) {
        const all = [
            ...this.emailAnalyses.map(e => ({ ...e, category: 'email' })),
            ...this.urlAnalyses.map(u => ({ ...u, category: 'url' }))
        ].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        return {
            emailCount: this.emailAnalyses.length,
            urlCount: this.urlAnalyses.length,
            totalCount: all.length,
            items: all.slice(0, limit),
            limit,
            hasMore: all.length > limit
        };
    }

    /**
     * Get single email analysis by ID
     */
    getEmailAnalysisById(id) {
        return this.emailAnalyses.find(e => e.id === parseInt(id));
    }

    /**
     * Get single URL analysis by ID
     */
    getURLAnalysisById(id) {
        return this.urlAnalyses.find(u => u.id === parseInt(id));
    }

    /**
     * Get statistics
     */
    getStats() {
        const stats = {
            emailAnalyses: this.emailAnalyses.length,
            urlAnalyses: this.urlAnalyses.length,
            totalAnalyses: this.emailAnalyses.length + this.urlAnalyses.length,
            threatDistribution: {
                emails: this._getThreatDistribution(this.emailAnalyses),
                urls: this._getThreatDistribution(this.urlAnalyses)
            }
        };
        return stats;
    }

    /**
     * Get threat distribution
     */
    _getThreatDistribution(analyses) {
        const dist = { phishing: 0, malicious: 0, suspicious: 0, legitimate: 0 };
        analyses.forEach(a => {
            const threat = (a.threatLevel || 'legitimate').toLowerCase();
            if (dist.hasOwnProperty(threat)) {
                dist[threat]++;
            }
        });
        return dist;
    }

    /**
     * Clear all data
     */
    clearAll() {
        this.emailAnalyses = [];
        this.urlAnalyses = [];
    }

    /**
     * Clear email data
     */
    clearEmails() {
        this.emailAnalyses = [];
    }

    /**
     * Clear URL data
     */
    clearURLs() {
        this.urlAnalyses = [];
    }
}

// Export singleton instance
module.exports = new DataStore();
