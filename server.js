require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();

// ===================
// SECURITY CONFIGURATION
// ===================
const CONFIG = {
    port: process.env.PORT || 3000,
    nodeEnv: process.env.NODE_ENV || 'development',
    whatsappNumber: process.env.WHATSAPP_NUMBER || '2349049845763',
    jwtSecret: process.env.JWT_SECRET,
    jwtRefreshSecret: process.env.JWT_REFRESH_SECRET,
    sessionExpiry: parseInt(process.env.SESSION_EXPIRY_HOURS) || 8,
    bcryptRounds: 12,
    tiers: {
        bronze: 3,
        silver: 5,
        gold: 10,
        platinum: 20
    },
    // Security settings
    maxReferralsPerHour: 10, // Max referrals that can be logged per hour per referrer
    maxCodeGenerationsPerIP: 20, // Max codes per IP per day
    minTimeBetweenReferrals: 60 * 1000, // 1 minute minimum between referrals for same referrer
    suspiciousActivityThreshold: 50, // Flag accounts with more than this per day
};

// Validate required environment variables
function validateEnv() {
    const required = ['JWT_SECRET', 'JWT_REFRESH_SECRET'];
    const missing = required.filter(key => !process.env[key]);
    
    if (missing.length > 0) {
        console.error(`❌ Missing required environment variables: ${missing.join(', ')}`);
        console.error('Please copy .env.example to .env and fill in all values');
        process.exit(1);
    }
    
    if (process.env.JWT_SECRET.length < 32) {
        console.error('❌ JWT_SECRET must be at least 32 characters');
        process.exit(1);
    }
}

validateEnv();

// ===================
// DATABASE SETUP
// ===================
const db = new Database('./reflink.db');

// Enable WAL mode for better performance and reliability
db.pragma('journal_mode = WAL');

// Initialize tables with security-focused schema
db.exec(`
    -- Admin users table (supports multiple admins)
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'admin',
        is_active INTEGER DEFAULT 1,
        failed_login_attempts INTEGER DEFAULT 0,
        locked_until DATETIME,
        last_login DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        created_by INTEGER
    );

    -- Referrers table with security tracking
    CREATE TABLE IF NOT EXISTS referrers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE NOT NULL,
        referral_count INTEGER DEFAULT 0,
        is_flagged INTEGER DEFAULT 0,
        flag_reason TEXT,
        ip_address TEXT,
        user_agent_hash TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_referral_at DATETIME
    );

    -- Referrals table with audit trail
    CREATE TABLE IF NOT EXISTS referrals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        referrer_code TEXT NOT NULL,
        referred_name TEXT,
        referred_phone TEXT,
        notes TEXT,
        logged_by INTEGER,
        ip_address TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (referrer_code) REFERENCES referrers(code),
        FOREIGN KEY (logged_by) REFERENCES admins(id)
    );

    -- Security audit log
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        user_id INTEGER,
        username TEXT,
        ip_address TEXT,
        user_agent TEXT,
        details TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    -- Rate limiting tracking
    CREATE TABLE IF NOT EXISTS rate_limits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        identifier TEXT NOT NULL,
        action_type TEXT NOT NULL,
        count INTEGER DEFAULT 1,
        window_start DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(identifier, action_type)
    );

    -- Active sessions (for logout-all functionality)
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER NOT NULL,
        token_hash TEXT UNIQUE NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (admin_id) REFERENCES admins(id)
    );

    CREATE INDEX IF NOT EXISTS idx_referrer_code ON referrals(referrer_code);
    CREATE INDEX IF NOT EXISTS idx_referrals_created ON referrals(created_at);
    CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
    CREATE INDEX IF NOT EXISTS idx_rate_limits ON rate_limits(identifier, action_type, window_start);
    CREATE INDEX IF NOT EXISTS idx_sessions_admin ON sessions(admin_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);
`);

// Create default admin if none exists
async function initializeAdmin() {
    const adminExists = db.prepare('SELECT COUNT(*) as count FROM admins').get();
    
    if (adminExists.count === 0) {
        const defaultUsername = process.env.ADMIN_USERNAME || 'admin';
        const defaultPassword = process.env.ADMIN_PASSWORD;
        
        if (!defaultPassword || defaultPassword.length < 12) {
            console.error('❌ ADMIN_PASSWORD must be at least 12 characters');
            process.exit(1);
        }
        
        const hash = await bcrypt.hash(defaultPassword, CONFIG.bcryptRounds);
        db.prepare('INSERT INTO admins (username, password_hash, role) VALUES (?, ?, ?)').run(
            defaultUsername, hash, 'superadmin'
        );
        console.log(`✅ Created admin user: ${defaultUsername}`);
    }
}

// ===================
// SECURITY HELPERS
// ===================

// Hash sensitive data for storage (one-way)
function hashData(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

// Generate secure random token
function generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
}

// Get client IP (handles proxies)
function getClientIP(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
        return forwarded.split(',')[0].trim();
    }
    return req.socket?.remoteAddress || req.ip || 'unknown';
}

// Sanitize input - strip dangerous characters
function sanitize(str, maxLength = 500) {
    if (typeof str !== 'string') return '';
    return str
        .slice(0, maxLength)
        .replace(/[<>&"'`]/g, (char) => {
            const entities = { '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;', '`': '&#96;' };
            return entities[char];
        })
        .trim();
}

// Validate referral code format
function isValidCode(code) {
    if (typeof code !== 'string') return false;
    // Alphanumeric and underscores, 2-20 chars, no leading/trailing underscores
    return /^[a-zA-Z0-9][a-zA-Z0-9_]{0,18}[a-zA-Z0-9]$|^[a-zA-Z0-9]{1,2}$/.test(code);
}

// Validate phone format
function isValidPhone(phone) {
    if (!phone) return true;
    return /^[0-9+\-\s()]{7,20}$/.test(phone);
}

// Audit logging
function logAudit(eventType, req, details = {}, userId = null, username = null) {
    try {
        db.prepare(`
            INSERT INTO audit_log (event_type, user_id, username, ip_address, user_agent, details)
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(
            eventType,
            userId,
            username,
            getClientIP(req),
            req.headers['user-agent']?.slice(0, 500) || 'unknown',
            JSON.stringify(details)
        );
    } catch (err) {
        console.error('Audit log error:', err);
    }
}

// Rate limiting check (database-backed for persistence)
function checkRateLimit(identifier, actionType, maxCount, windowMs) {
    const windowStart = new Date(Date.now() - windowMs).toISOString();
    
    // Clean old entries
    db.prepare(`DELETE FROM rate_limits WHERE window_start < ?`).run(windowStart);
    
    // Get current count
    const record = db.prepare(`
        SELECT count FROM rate_limits 
        WHERE identifier = ? AND action_type = ? AND window_start >= ?
    `).get(identifier, actionType, windowStart);
    
    if (record && record.count >= maxCount) {
        return false; // Rate limited
    }
    
    // Increment or insert
    db.prepare(`
        INSERT INTO rate_limits (identifier, action_type, count, window_start)
        VALUES (?, ?, 1, CURRENT_TIMESTAMP)
        ON CONFLICT(identifier, action_type) DO UPDATE SET count = count + 1
    `).run(identifier, actionType);
    
    return true; // Allowed
}

// ===================
// MIDDLEWARE
// ===================

// Security headers with strict CSP
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    noSniff: true,
    xssFilter: true,
}));

// Additional security headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    next();
});

app.use(express.json({ limit: '10kb' })); // Limit body size
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// Trust proxy for accurate IP (only in production behind reverse proxy)
if (CONFIG.nodeEnv === 'production') {
    app.set('trust proxy', 1);
}

// Global rate limiting
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', globalLimiter);

// Strict rate limit for auth endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Too many login attempts. Please try again in 15 minutes.' },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: false,
});

// Rate limit for code generation
const codeGenLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10,
    message: { error: 'Too many codes generated. Please try again later.' },
    keyGenerator: (req) => getClientIP(req),
});

// ===================
// AUTH MIDDLEWARE
// ===================
async function authenticateToken(req, res, next) {
    const token = req.cookies.auth_token;
    
    if (!token) {
        logAudit('AUTH_FAILED_NO_TOKEN', req);
        return res.status(401).json({ error: 'Authentication required' });
    }

    try {
        const decoded = jwt.verify(token, CONFIG.jwtSecret);
        
        // Verify session exists in database
        const tokenHash = hashData(token);
        const session = db.prepare(`
            SELECT s.*, a.is_active, a.username, a.role 
            FROM sessions s
            JOIN admins a ON s.admin_id = a.id
            WHERE s.token_hash = ? AND s.expires_at > datetime('now')
        `).get(tokenHash);
        
        if (!session) {
            res.clearCookie('auth_token');
            logAudit('AUTH_FAILED_INVALID_SESSION', req);
            return res.status(403).json({ error: 'Session expired or invalid' });
        }
        
        if (!session.is_active) {
            res.clearCookie('auth_token');
            logAudit('AUTH_FAILED_INACTIVE_USER', req, { username: session.username });
            return res.status(403).json({ error: 'Account is disabled' });
        }
        
        req.user = {
            id: session.admin_id,
            username: session.username,
            role: session.role,
            sessionId: session.id
        };
        next();
    } catch (err) {
        res.clearCookie('auth_token');
        
        if (err.name === 'TokenExpiredError') {
            logAudit('AUTH_FAILED_EXPIRED', req);
            return res.status(403).json({ error: 'Session expired, please login again' });
        }
        
        logAudit('AUTH_FAILED_INVALID_TOKEN', req, { error: err.message });
        return res.status(403).json({ error: 'Invalid authentication' });
    }
}

// CSRF protection for state-changing operations
function csrfProtection(req, res, next) {
    // For API requests, verify origin
    const origin = req.headers.origin;
    const host = req.headers.host;
    
    if (CONFIG.nodeEnv === 'production' && origin) {
        const originHost = new URL(origin).host;
        if (originHost !== host) {
            logAudit('CSRF_BLOCKED', req, { origin, host });
            return res.status(403).json({ error: 'Invalid request origin' });
        }
    }
    
    next();
}

// Apply CSRF to state-changing routes
app.use('/api/admin', csrfProtection);

// ===================
// PUBLIC API ROUTES
// ===================

// Get config (public - only non-sensitive data)
app.get('/api/config', (req, res) => {
    res.json({
        whatsappNumber: CONFIG.whatsappNumber,
        tiers: CONFIG.tiers
    });
});

// Generate/register referral code (public with rate limiting)
app.post('/api/referrers', codeGenLimiter, (req, res) => {
    const { code } = req.body;
    const clientIP = getClientIP(req);
    
    if (!code || !isValidCode(code)) {
        return res.status(400).json({ 
            error: 'Invalid code. Use 2-20 characters: letters, numbers, underscores only.' 
        });
    }

    const upperCode = code.toUpperCase();
    
    // Check for banned words/patterns
    const bannedPatterns = ['ADMIN', 'ROOT', 'SYSTEM', 'NULL', 'UNDEFINED', 'DROP', 'DELETE', 'INSERT', 'SELECT'];
    if (bannedPatterns.some(p => upperCode.includes(p))) {
        logAudit('CODE_GEN_BANNED_WORD', req, { code: upperCode });
        return res.status(400).json({ error: 'This code is not allowed' });
    }

    try {
        const existing = db.prepare('SELECT code, is_flagged FROM referrers WHERE code = ?').get(upperCode);
        
        if (existing) {
            if (existing.is_flagged) {
                return res.status(400).json({ error: 'This code is unavailable' });
            }
            
            return res.json({ 
                code: existing.code, 
                isNew: false,
                link: `https://wa.me/${CONFIG.whatsappNumber}?text=${encodeURIComponent(`Hi! I was referred by ${existing.code}`)}`
            });
        }

        // Additional rate limit check per IP per day
        if (!checkRateLimit(clientIP, 'code_gen', CONFIG.maxCodeGenerationsPerIP, 24 * 60 * 60 * 1000)) {
            logAudit('CODE_GEN_RATE_LIMITED', req, { code: upperCode });
            return res.status(429).json({ error: 'Daily limit reached. Try again tomorrow.' });
        }

        // Create new referrer
        const userAgentHash = hashData(req.headers['user-agent'] || 'unknown');
        db.prepare('INSERT INTO referrers (code, ip_address, user_agent_hash) VALUES (?, ?, ?)').run(
            upperCode, clientIP, userAgentHash
        );
        
        logAudit('CODE_CREATED', req, { code: upperCode });
        
        res.status(201).json({ 
            code: upperCode, 
            isNew: true,
            link: `https://wa.me/${CONFIG.whatsappNumber}?text=${encodeURIComponent(`Hi! I was referred by ${upperCode}`)}`
        });
    } catch (err) {
        console.error('Error creating referrer:', err);
        res.status(500).json({ error: 'Failed to create referral code' });
    }
});

// Get leaderboard (public - limited data)
app.get('/api/leaderboard', (req, res) => {
    try {
        const leaderboard = db.prepare(`
            SELECT code, referral_count
            FROM referrers 
            WHERE referral_count > 0 AND is_flagged = 0
            ORDER BY referral_count DESC 
            LIMIT 20
        `).all();

        // Only return code and count - no sensitive data
        res.json(leaderboard.map(r => ({
            code: r.code,
            referral_count: r.referral_count
        })));
    } catch (err) {
        console.error('Error fetching leaderboard:', err);
        res.status(500).json({ error: 'Failed to fetch leaderboard' });
    }
});

// ===================
// ADMIN AUTH ROUTES
// ===================

// Admin login with security measures
app.post('/api/admin/login', authLimiter, async (req, res) => {
    const { username, password } = req.body;
    const clientIP = getClientIP(req);

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }

    // Normalize username
    const normalizedUsername = username.toLowerCase().trim();

    try {
        const admin = db.prepare('SELECT * FROM admins WHERE LOWER(username) = ?').get(normalizedUsername);
        
        // Check if account is locked
        if (admin && admin.locked_until) {
            const lockTime = new Date(admin.locked_until);
            if (lockTime > new Date()) {
                const minutesLeft = Math.ceil((lockTime - new Date()) / 60000);
                logAudit('LOGIN_BLOCKED_LOCKED', req, { username: normalizedUsername });
                return res.status(423).json({ 
                    error: `Account locked. Try again in ${minutesLeft} minutes.` 
                });
            }
        }

        // Verify password (constant time comparison via bcrypt)
        const isValid = admin && await bcrypt.compare(password, admin.password_hash);
        
        if (!isValid) {
            // Increment failed attempts
            if (admin) {
                const newAttempts = (admin.failed_login_attempts || 0) + 1;
                let lockUntil = null;
                
                // Lock after 5 failed attempts
                if (newAttempts >= 5) {
                    lockUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 min lock
                }
                
                db.prepare(`
                    UPDATE admins 
                    SET failed_login_attempts = ?, locked_until = ?
                    WHERE id = ?
                `).run(newAttempts, lockUntil, admin.id);
            }
            
            logAudit('LOGIN_FAILED', req, { username: normalizedUsername });
            
            // Generic error to prevent username enumeration
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        if (!admin.is_active) {
            logAudit('LOGIN_FAILED_INACTIVE', req, { username: normalizedUsername });
            return res.status(401).json({ error: 'Account is disabled' });
        }

        // Reset failed attempts
        db.prepare(`
            UPDATE admins 
            SET failed_login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP
            WHERE id = ?
        `).run(admin.id);

        // Generate tokens
        const tokenId = generateSecureToken(16);
        const token = jwt.sign(
            { 
                sub: admin.id, 
                username: admin.username, 
                role: admin.role,
                jti: tokenId 
            },
            CONFIG.jwtSecret,
            { expiresIn: `${CONFIG.sessionExpiry}h` }
        );

        // Store session in database
        const expiresAt = new Date(Date.now() + CONFIG.sessionExpiry * 60 * 60 * 1000).toISOString();
        db.prepare(`
            INSERT INTO sessions (admin_id, token_hash, ip_address, user_agent, expires_at)
            VALUES (?, ?, ?, ?, ?)
        `).run(
            admin.id,
            hashData(token),
            clientIP,
            req.headers['user-agent']?.slice(0, 500) || 'unknown',
            expiresAt
        );

        // Set secure cookie
        res.cookie('auth_token', token, {
            httpOnly: true,
            secure: CONFIG.nodeEnv === 'production',
            sameSite: 'strict',
            maxAge: CONFIG.sessionExpiry * 60 * 60 * 1000,
            path: '/'
        });

        logAudit('LOGIN_SUCCESS', req, {}, admin.id, admin.username);

        res.json({ 
            message: 'Login successful',
            user: { username: admin.username, role: admin.role }
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Admin logout
app.post('/api/admin/logout', authenticateToken, (req, res) => {
    const token = req.cookies.auth_token;
    
    // Remove session from database
    if (token) {
        db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashData(token));
    }
    
    res.clearCookie('auth_token', { path: '/' });
    logAudit('LOGOUT', req, {}, req.user.id, req.user.username);
    
    res.json({ message: 'Logged out' });
});

// Logout all sessions
app.post('/api/admin/logout-all', authenticateToken, (req, res) => {
    db.prepare('DELETE FROM sessions WHERE admin_id = ?').run(req.user.id);
    res.clearCookie('auth_token', { path: '/' });
    logAudit('LOGOUT_ALL', req, {}, req.user.id, req.user.username);
    
    res.json({ message: 'All sessions terminated' });
});

// Check auth status
app.get('/api/admin/me', authenticateToken, (req, res) => {
    res.json({ 
        username: req.user.username, 
        role: req.user.role 
    });
});

// Change password
app.post('/api/admin/change-password', authenticateToken, async (req, res) => {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
        return res.status(400).json({ error: 'Current and new password required' });
    }

    if (newPassword.length < 12) {
        return res.status(400).json({ error: 'Password must be at least 12 characters' });
    }

    // Check password strength
    const hasUpper = /[A-Z]/.test(newPassword);
    const hasLower = /[a-z]/.test(newPassword);
    const hasNumber = /[0-9]/.test(newPassword);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(newPassword);
    
    if (!(hasUpper && hasLower && hasNumber && hasSpecial)) {
        return res.status(400).json({ 
            error: 'Password must contain uppercase, lowercase, number, and special character' 
        });
    }

    try {
        const admin = db.prepare('SELECT * FROM admins WHERE id = ?').get(req.user.id);
        const isValid = await bcrypt.compare(currentPassword, admin.password_hash);
        
        if (!isValid) {
            logAudit('PASSWORD_CHANGE_FAILED', req, { reason: 'wrong_current' }, req.user.id, req.user.username);
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        const newHash = await bcrypt.hash(newPassword, CONFIG.bcryptRounds);
        db.prepare('UPDATE admins SET password_hash = ? WHERE id = ?').run(newHash, req.user.id);
        
        // Invalidate all other sessions
        db.prepare('DELETE FROM sessions WHERE admin_id = ? AND id != ?').run(req.user.id, req.user.sessionId);
        
        logAudit('PASSWORD_CHANGED', req, {}, req.user.id, req.user.username);
        
        res.json({ message: 'Password changed successfully' });
    } catch (err) {
        console.error('Password change error:', err);
        res.status(500).json({ error: 'Failed to change password' });
    }
});

// ===================
// ADMIN DASHBOARD ROUTES
// ===================

// Get dashboard stats
app.get('/api/admin/stats', authenticateToken, (req, res) => {
    try {
        const totalReferrals = db.prepare('SELECT COUNT(*) as count FROM referrals').get().count;
        const totalReferrers = db.prepare('SELECT COUNT(*) as count FROM referrers').get().count;
        const activeReferrers = db.prepare('SELECT COUNT(*) as count FROM referrers WHERE referral_count > 0').get().count;
        const flaggedReferrers = db.prepare('SELECT COUNT(*) as count FROM referrers WHERE is_flagged = 1').get().count;
        
        const today = new Date().toISOString().split('T')[0];
        const todayReferrals = db.prepare(`
            SELECT COUNT(*) as count FROM referrals 
            WHERE date(created_at) = date(?)
        `).get(today).count;

        const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
        const weekReferrals = db.prepare(`
            SELECT COUNT(*) as count FROM referrals 
            WHERE created_at >= ?
        `).get(weekAgo).count;

        res.json({
            totalReferrals,
            totalReferrers,
            activeReferrers,
            flaggedReferrers,
            todayReferrals,
            weekReferrals
        });
    } catch (err) {
        console.error('Error fetching stats:', err);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// Get all referrers (admin)
app.get('/api/admin/referrers', authenticateToken, (req, res) => {
    const { search, sort = 'referral_count', order = 'desc', flagged } = req.query;

    const allowedSorts = ['code', 'referral_count', 'created_at', 'last_referral_at'];
    const sortCol = allowedSorts.includes(sort) ? sort : 'referral_count';
    const sortOrder = order === 'asc' ? 'ASC' : 'DESC';

    try {
        let query = `SELECT * FROM referrers WHERE 1=1`;
        let params = [];

        if (search) {
            query += ` AND code LIKE ?`;
            params.push(`%${search.toUpperCase()}%`);
        }

        if (flagged === 'true') {
            query += ` AND is_flagged = 1`;
        } else if (flagged === 'false') {
            query += ` AND is_flagged = 0`;
        }

        query += ` ORDER BY ${sortCol} ${sortOrder} LIMIT 500`;

        const referrers = db.prepare(query).all(...params);
        res.json(referrers);
    } catch (err) {
        console.error('Error fetching referrers:', err);
        res.status(500).json({ error: 'Failed to fetch referrers' });
    }
});

// Get referrals for a specific referrer
app.get('/api/admin/referrers/:code/referrals', authenticateToken, (req, res) => {
    const { code } = req.params;

    if (!isValidCode(code)) {
        return res.status(400).json({ error: 'Invalid code' });
    }

    try {
        const referrals = db.prepare(`
            SELECT r.*, a.username as logged_by_name
            FROM referrals r
            LEFT JOIN admins a ON r.logged_by = a.id
            WHERE r.referrer_code = ? 
            ORDER BY r.created_at DESC
            LIMIT 100
        `).all(code.toUpperCase());

        res.json(referrals);
    } catch (err) {
        console.error('Error fetching referrals:', err);
        res.status(500).json({ error: 'Failed to fetch referrals' });
    }
});

// Log a new referral (admin only)
app.post('/api/admin/referrals', authenticateToken, (req, res) => {
    const { referrerCode, referredName, referredPhone, notes } = req.body;

    if (!referrerCode || !isValidCode(referrerCode)) {
        return res.status(400).json({ error: 'Valid referrer code required' });
    }

    if (referredPhone && !isValidPhone(referredPhone)) {
        return res.status(400).json({ error: 'Invalid phone number format' });
    }

    const upperCode = referrerCode.toUpperCase();

    try {
        // Check referrer exists and isn't flagged
        let referrer = db.prepare('SELECT * FROM referrers WHERE code = ?').get(upperCode);
        
        if (referrer && referrer.is_flagged) {
            return res.status(400).json({ error: 'This referrer is flagged and cannot receive referrals' });
        }

        // Rate limiting: max referrals per hour for this referrer
        const hourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
        const recentCount = db.prepare(`
            SELECT COUNT(*) as count FROM referrals 
            WHERE referrer_code = ? AND created_at >= ?
        `).get(upperCode, hourAgo).count;

        if (recentCount >= CONFIG.maxReferralsPerHour) {
            logAudit('REFERRAL_RATE_LIMITED', req, { code: upperCode, count: recentCount }, req.user.id, req.user.username);
            return res.status(429).json({ 
                error: `Rate limit: Max ${CONFIG.maxReferralsPerHour} referrals per hour for each referrer` 
            });
        }

        // Check minimum time between referrals
        if (referrer && referrer.last_referral_at) {
            const lastReferral = new Date(referrer.last_referral_at).getTime();
            if (Date.now() - lastReferral < CONFIG.minTimeBetweenReferrals) {
                return res.status(429).json({ error: 'Please wait before logging another referral for this code' });
            }
        }

        // Create referrer if doesn't exist
        if (!referrer) {
            db.prepare('INSERT INTO referrers (code, ip_address) VALUES (?, ?)').run(
                upperCode, getClientIP(req)
            );
        }

        // Add referral with audit trail
        const result = db.prepare(`
            INSERT INTO referrals (referrer_code, referred_name, referred_phone, notes, logged_by, ip_address)
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(
            upperCode,
            sanitize(referredName, 100) || null,
            sanitize(referredPhone, 20) || null,
            sanitize(notes, 500) || null,
            req.user.id,
            getClientIP(req)
        );

        // Update referrer count
        db.prepare(`
            UPDATE referrers 
            SET referral_count = referral_count + 1, last_referral_at = CURRENT_TIMESTAMP
            WHERE code = ?
        `).run(upperCode);

        // Check for suspicious activity
        const todayCount = db.prepare(`
            SELECT COUNT(*) as count FROM referrals 
            WHERE referrer_code = ? AND date(created_at) = date('now')
        `).get(upperCode).count;

        if (todayCount >= CONFIG.suspiciousActivityThreshold) {
            db.prepare(`
                UPDATE referrers SET is_flagged = 1, flag_reason = 'Suspicious activity: high volume'
                WHERE code = ?
            `).run(upperCode);
            logAudit('REFERRER_AUTO_FLAGGED', req, { code: upperCode, todayCount }, req.user.id, req.user.username);
        }

        logAudit('REFERRAL_LOGGED', req, { 
            code: upperCode, 
            referredName: sanitize(referredName, 100),
            referralId: result.lastInsertRowid 
        }, req.user.id, req.user.username);

        res.status(201).json({ 
            id: result.lastInsertRowid,
            message: 'Referral logged successfully' 
        });
    } catch (err) {
        console.error('Error logging referral:', err);
        res.status(500).json({ error: 'Failed to log referral' });
    }
});

// Delete a referral
app.delete('/api/admin/referrals/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const referralId = parseInt(id, 10);

    if (isNaN(referralId)) {
        return res.status(400).json({ error: 'Invalid referral ID' });
    }

    try {
        const referral = db.prepare('SELECT * FROM referrals WHERE id = ?').get(referralId);
        
        if (!referral) {
            return res.status(404).json({ error: 'Referral not found' });
        }

        db.prepare('DELETE FROM referrals WHERE id = ?').run(referralId);
        
        // Decrement referrer count
        db.prepare(`
            UPDATE referrers 
            SET referral_count = MAX(0, referral_count - 1)
            WHERE code = ?
        `).run(referral.referrer_code);

        logAudit('REFERRAL_DELETED', req, { 
            referralId, 
            code: referral.referrer_code 
        }, req.user.id, req.user.username);

        res.json({ message: 'Referral deleted' });
    } catch (err) {
        console.error('Error deleting referral:', err);
        res.status(500).json({ error: 'Failed to delete referral' });
    }
});

// Flag/unflag a referrer
app.patch('/api/admin/referrers/:code/flag', authenticateToken, (req, res) => {
    const { code } = req.params;
    const { flagged, reason } = req.body;

    if (!isValidCode(code)) {
        return res.status(400).json({ error: 'Invalid code' });
    }

    const upperCode = code.toUpperCase();

    try {
        const referrer = db.prepare('SELECT * FROM referrers WHERE code = ?').get(upperCode);
        
        if (!referrer) {
            return res.status(404).json({ error: 'Referrer not found' });
        }

        db.prepare(`
            UPDATE referrers SET is_flagged = ?, flag_reason = ?
            WHERE code = ?
        `).run(flagged ? 1 : 0, flagged ? sanitize(reason, 200) : null, upperCode);

        logAudit(flagged ? 'REFERRER_FLAGGED' : 'REFERRER_UNFLAGGED', req, { 
            code: upperCode, 
            reason 
        }, req.user.id, req.user.username);

        res.json({ message: flagged ? 'Referrer flagged' : 'Referrer unflagged' });
    } catch (err) {
        console.error('Error flagging referrer:', err);
        res.status(500).json({ error: 'Failed to update referrer' });
    }
});

// Delete a referrer and all their referrals
app.delete('/api/admin/referrers/:code', authenticateToken, (req, res) => {
    const { code } = req.params;

    if (!isValidCode(code)) {
        return res.status(400).json({ error: 'Invalid code' });
    }

    const upperCode = code.toUpperCase();

    try {
        const referrer = db.prepare('SELECT * FROM referrers WHERE code = ?').get(upperCode);
        
        if (!referrer) {
            return res.status(404).json({ error: 'Referrer not found' });
        }

        db.prepare('DELETE FROM referrals WHERE referrer_code = ?').run(upperCode);
        db.prepare('DELETE FROM referrers WHERE code = ?').run(upperCode);

        logAudit('REFERRER_DELETED', req, { 
            code: upperCode, 
            referralCount: referrer.referral_count 
        }, req.user.id, req.user.username);

        res.json({ message: 'Referrer deleted' });
    } catch (err) {
        console.error('Error deleting referrer:', err);
        res.status(500).json({ error: 'Failed to delete referrer' });
    }
});

// Get audit log
app.get('/api/admin/audit-log', authenticateToken, (req, res) => {
    // Only superadmin can view audit log
    if (req.user.role !== 'superadmin') {
        return res.status(403).json({ error: 'Insufficient permissions' });
    }

    const { limit = 100, offset = 0, eventType } = req.query;

    try {
        let query = `SELECT * FROM audit_log WHERE 1=1`;
        let params = [];

        if (eventType) {
            query += ` AND event_type = ?`;
            params.push(eventType);
        }

        query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
        params.push(Math.min(parseInt(limit) || 100, 500), parseInt(offset) || 0);

        const logs = db.prepare(query).all(...params);
        res.json(logs);
    } catch (err) {
        console.error('Error fetching audit log:', err);
        res.status(500).json({ error: 'Failed to fetch audit log' });
    }
});

// Get active sessions
app.get('/api/admin/sessions', authenticateToken, (req, res) => {
    try {
        const sessions = db.prepare(`
            SELECT id, ip_address, user_agent, created_at, expires_at
            FROM sessions
            WHERE admin_id = ? AND expires_at > datetime('now')
            ORDER BY created_at DESC
        `).all(req.user.id);

        res.json(sessions.map(s => ({
            ...s,
            isCurrent: s.id === req.user.sessionId
        })));
    } catch (err) {
        console.error('Error fetching sessions:', err);
        res.status(500).json({ error: 'Failed to fetch sessions' });
    }
});

// Revoke a specific session
app.delete('/api/admin/sessions/:id', authenticateToken, (req, res) => {
    const sessionId = parseInt(req.params.id, 10);

    if (isNaN(sessionId)) {
        return res.status(400).json({ error: 'Invalid session ID' });
    }

    try {
        // Can only revoke own sessions
        const result = db.prepare('DELETE FROM sessions WHERE id = ? AND admin_id = ?').run(
            sessionId, req.user.id
        );

        if (result.changes === 0) {
            return res.status(404).json({ error: 'Session not found' });
        }

        logAudit('SESSION_REVOKED', req, { sessionId }, req.user.id, req.user.username);
        res.json({ message: 'Session revoked' });
    } catch (err) {
        console.error('Error revoking session:', err);
        res.status(500).json({ error: 'Failed to revoke session' });
    }
});

// Export to CSV (admin)
app.get('/api/admin/export/csv', authenticateToken, (req, res) => {
    const { type = 'all' } = req.query;

    logAudit('DATA_EXPORTED', req, { type }, req.user.id, req.user.username);

    try {
        let csvContent = '';
        
        if (type === 'referrers' || type === 'all') {
            const referrers = db.prepare(`
                SELECT code, referral_count, is_flagged, flag_reason, created_at, last_referral_at 
                FROM referrers 
                ORDER BY referral_count DESC
            `).all();

            csvContent += 'REFERRERS\n';
            csvContent += 'Code,Referral Count,Flagged,Flag Reason,Created At,Last Referral At\n';
            referrers.forEach(r => {
                const flagReason = (r.flag_reason || '').replace(/"/g, '""');
                csvContent += `${r.code},${r.referral_count},${r.is_flagged ? 'Yes' : 'No'},"${flagReason}",${r.created_at || ''},${r.last_referral_at || ''}\n`;
            });
            csvContent += '\n';
        }

        if (type === 'referrals' || type === 'all') {
            const referrals = db.prepare(`
                SELECT r.referrer_code, r.referred_name, r.referred_phone, r.notes, r.created_at, a.username as logged_by
                FROM referrals r
                LEFT JOIN admins a ON r.logged_by = a.id
                ORDER BY r.created_at DESC
            `).all();

            csvContent += 'REFERRALS\n';
            csvContent += 'Referrer Code,Referred Name,Referred Phone,Notes,Logged By,Created At\n';
            referrals.forEach(r => {
                const name = (r.referred_name || '').replace(/"/g, '""');
                const phone = (r.referred_phone || '').replace(/"/g, '""');
                const notes = (r.notes || '').replace(/"/g, '""');
                csvContent += `${r.referrer_code},"${name}","${phone}","${notes}",${r.logged_by || 'system'},${r.created_at}\n`;
            });
        }

        const filename = `reflink-export-${new Date().toISOString().split('T')[0]}.csv`;
        
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.send(csvContent);
    } catch (err) {
        console.error('Error exporting CSV:', err);
        res.status(500).json({ error: 'Failed to export data' });
    }
});

// ===================
// SERVE FRONTEND
// ===================
app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: CONFIG.nodeEnv === 'production' ? '1d' : 0,
    etag: true
}));

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ===================
// ERROR HANDLER
// ===================
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    logAudit('SERVER_ERROR', req, { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
});

// ===================
// CLEANUP JOBS
// ===================
function runCleanupJobs() {
    try {
        // Clean expired sessions
        db.prepare(`DELETE FROM sessions WHERE expires_at < datetime('now')`).run();
        
        // Clean old rate limit records
        const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        db.prepare(`DELETE FROM rate_limits WHERE window_start < ?`).run(dayAgo);
        
        // Clean old audit logs (keep 90 days)
        const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();
        db.prepare(`DELETE FROM audit_log WHERE created_at < ?`).run(ninetyDaysAgo);
        
        console.log('✅ Cleanup jobs completed');
    } catch (err) {
        console.error('Cleanup job error:', err);
    }
}

// Run cleanup every hour
setInterval(runCleanupJobs, 60 * 60 * 1000);

// ===================
// START SERVER
// ===================
initializeAdmin().then(() => {
    app.listen(CONFIG.port, () => {
        runCleanupJobs(); // Run once at startup
        
        console.log(`
╔═══════════════════════════════════════════════════════════════╗
║               RefLink - Secure Referral Tracker               ║
╠═══════════════════════════════════════════════════════════════╣
║  Server running on http://localhost:${CONFIG.port}                      ║
║  Environment: ${CONFIG.nodeEnv.padEnd(47)}║
║  WhatsApp: ${CONFIG.whatsappNumber.padEnd(50)}║
╠═══════════════════════════════════════════════════════════════╣
║  Security Features:                                           ║
║  ✓ JWT + Session-based authentication                         ║
║  ✓ bcrypt password hashing (${CONFIG.bcryptRounds} rounds)                       ║
║  ✓ Rate limiting (API + Auth + Code generation)               ║
║  ✓ CSRF protection                                            ║
║  ✓ Security headers (Helmet)                                  ║
║  ✓ Input validation & sanitization                            ║
║  ✓ Audit logging                                              ║
║  ✓ Account lockout after failed attempts                      ║
║  ✓ Suspicious activity auto-flagging                          ║
╚═══════════════════════════════════════════════════════════════╝
        `);
    });
});
