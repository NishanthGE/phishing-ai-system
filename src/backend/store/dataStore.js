const fs = require('fs');
const path = require('path');

const storeDir = path.join(__dirname);

// Initialize storage files
const emailsFile = path.join(storeDir, 'emails.json');
const urlsFile = path.join(storeDir, 'urls.json');

// Ensure files exist
if (!fs.existsSync(emailsFile)) {
    fs.writeFileSync(emailsFile, JSON.stringify([], null, 2));
}
if (!fs.existsSync(urlsFile)) {
    fs.writeFileSync(urlsFile, JSON.stringify([], null, 2));
}

class DataStore {
    // Save analyzed email
    saveEmail(emailData) {
        try {
            const emails = this.getAllEmails();
            const entry = {
                id: Date.now(),
                timestamp: new Date().toISOString(),
                ...emailData
            };
            emails.push(entry);
            fs.writeFileSync(emailsFile, JSON.stringify(emails, null, 2));
            return entry;
        } catch (error) {
            console.error('Error saving email:', error);
            return null;
        }
    }

    // Save analyzed URL
    saveURL(urlData) {
        try {
            const urls = this.getAllURLs();
            const entry = {
                id: Date.now(),
                timestamp: new Date().toISOString(),
                ...urlData
            };
            urls.push(entry);
            fs.writeFileSync(urlsFile, JSON.stringify(urls, null, 2));
            return entry;
        } catch (error) {
            console.error('Error saving URL:', error);
            return null;
        }
    }

    // Get all emails
    getAllEmails() {
        try {
            const data = fs.readFileSync(emailsFile, 'utf-8');
            return JSON.parse(data);
        } catch (error) {
            console.error('Error reading emails:', error);
            return [];
        }
    }

    // Get all URLs
    getAllURLs() {
        try {
            const data = fs.readFileSync(urlsFile, 'utf-8');
            return JSON.parse(data);
        } catch (error) {
            console.error('Error reading URLs:', error);
            return [];
        }
    }

    // Delete email
    deleteEmail(id) {
        try {
            const emails = this.getAllEmails();
            const filtered = emails.filter(e => e.id !== parseInt(id));
            fs.writeFileSync(emailsFile, JSON.stringify(filtered, null, 2));
            return true;
        } catch (error) {
            console.error('Error deleting email:', error);
            return false;
        }
    }

    // Delete URL
    deleteURL(id) {
        try {
            const urls = this.getAllURLs();
            const filtered = urls.filter(u => u.id !== parseInt(id));
            fs.writeFileSync(urlsFile, JSON.stringify(filtered, null, 2));
            return true;
        } catch (error) {
            console.error('Error deleting URL:', error);
            return false;
        }
    }

    // Clear all data
    clearAll() {
        try {
            fs.writeFileSync(emailsFile, JSON.stringify([], null, 2));
            fs.writeFileSync(urlsFile, JSON.stringify([], null, 2));
            return true;
        } catch (error) {
            console.error('Error clearing data:', error);
            return false;
        }
    }
}

module.exports = new DataStore();
