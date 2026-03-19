/**
 * Simple In-Memory User Store for Demo
 * Production: Replace with database (MongoDB/PostgreSQL)
 */

const users = new Map(); // username -> {password: hashed, createdAt: Date}

class UserStore {
    /**
     * Find user by username
     */
    findByUsername(username) {
        return users.get(username);
    }

    /**
     * Create new user
     */
    async create(username, hashedPassword) {
        if (users.has(username)) {
            throw new Error('Username already exists');
        }
        const user = {
            password: hashedPassword,
            createdAt: new Date().toISOString()
        };
        users.set(username, user);
        console.log(`✅ New user created: ${username}`);
        return user;
    }

    /**
     * Get all users (for demo/stats)
     */
    getAll() {
        return Array.from(users.entries()).map(([username, user]) => ({
            username,
            createdAt: user.createdAt
        }));
    }

    /**
     * Clear all users (demo reset)
     */
    clearAll() {
        users.clear();
        console.log('🗑️ All users cleared');
    }
}

module.exports = new UserStore();

