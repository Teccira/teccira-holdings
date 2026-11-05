// ============================================================================
// TECCIRA HOLDINGS — Enhanced Production Express.js Backend Server
// Features: SQLite Database, JWT Auth, Bcrypt, Helmet, Rate Limits & Migration
// ============================================================================

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'teccira-super-secret-jwt-key-2026';
const DB_FILE = path.join(__dirname, 'database.sqlite');
const LEGACY_JSON = path.join(__dirname, 'database.json');

// ==========================================
// 1. HTTP SECURITY & RATE LIMITING
// ==========================================
// Helmet for HTTP security headers
app.use(helmet({ contentSecurityPolicy: false }));

// CORS configuration for allowed origins
const allowedOrigins = ['http://localhost:3000', 'http://127.0.0.1:5500', 'http://localhost:5500'];
app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.indexOf(origin) !== -1 || origin.startsWith('http://192.168.')) {
            callback(null, true);
        } else {
            callback(null, true); // Permissive for local network development
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Idempotency-Key']
}));

app.use(express.json());

// Global Rate Limiter: 100 requests per 15 minutes per IP
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { success: false, message: 'Too many requests from this IP, please try again later.' }
});
app.use('/api/', globalLimiter);

// Auth Rate Limiter: 10 attempts per hour for login/signup
const authLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 10,
    message: { success: false, message: 'Too many login/signup attempts. Please wait an hour.' }
});

// ==========================================
// 2. SQLITE DATABASE INITIALIZATION
// ==========================================
const db = new sqlite3.Database(DB_FILE, (err) => {
    if (err) console.error('Error opening SQLite database:', err);
    else console.log('[DATABASE] SQLite Relational Database Connected Successfully.');
});

db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        createdAt TEXT
    )`);

    // Orders table
    db.run(`CREATE TABLE IF NOT EXISTS orders (
        id TEXT PRIMARY KEY,
        idempotencyKey TEXT UNIQUE,
        name TEXT NOT NULL,
        phone TEXT NOT NULL,
        item TEXT NOT NULL,
        jerseySize TEXT,
        itemPrice REAL,
        deliveryMethod TEXT,
        address TEXT,
        deliveryFee REAL,
        totalPayable REAL,
        paymentMethod TEXT,
        status TEXT DEFAULT 'Pending',
        createdAt TEXT
    )`);

    // Service Requests table
    db.run(`CREATE TABLE IF NOT EXISTS service_requests (
        id TEXT PRIMARY KEY,
        idempotencyKey TEXT UNIQUE,
        serviceName TEXT NOT NULL,
        clientName TEXT NOT NULL,
        clientPhone TEXT NOT NULL,
        alternativePhone TEXT,
        location TEXT,
        area TEXT,
        landmark TEXT,
        preferredDate TEXT,
        preferredTime TEXT,
        clientNotes TEXT,
        status TEXT DEFAULT 'Pending',
        createdAt TEXT
    )`);

    // Contacts table
    db.run(`CREATE TABLE IF NOT EXISTS contacts (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        subject TEXT,
        contactDetail TEXT,
        message TEXT NOT NULL,
        createdAt TEXT
    )`);

    // Auto-migrate legacy database.json if present
    migrateLegacyJson();
});

// ==========================================
// 3. AUTOMATIC DATA MIGRATION & BACKUP
// ==========================================
function migrateLegacyJson() {
    if (!fs.existsSync(LEGACY_JSON)) return;

    try {
        const rawData = fs.readFileSync(LEGACY_JSON, 'utf8');
        const legacyData = JSON.parse(rawData);

        // Create backup of JSON before migration
        const backupPath = path.join(__dirname, `database_backup_${Date.now()}.json`);
        fs.writeFileSync(backupPath, rawData, 'utf8');
        console.log(`[MIGRATION] Created JSON backup file at: ${backupPath}`);

        db.serialize(() => {
            // Migrate users with bcrypt hashing if unhashed
            if (Array.isArray(legacyData.users)) {
                const stmt = db.prepare(`INSERT OR IGNORE INTO users (id, name, email, phone, password, role, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)`);
                legacyData.users.forEach(u => {
                    const isHashed = u.password && u.password.startsWith('$2a$');
                    const hashedPassword = isHashed ? u.password : bcrypt.hashSync(u.password || 'password123', 10);
                    stmt.run(u.id, u.name || '', u.email || '', u.phone || '', hashedPassword, u.role || 'user', u.createdAt || new Date().toISOString());
                });
                stmt.finalize();
            }

            // Migrate orders
            if (Array.isArray(legacyData.orders)) {
                const stmt = db.prepare(`INSERT OR IGNORE INTO orders (id, name, phone, item, jerseySize, itemPrice, deliveryMethod, address, deliveryFee, totalPayable, paymentMethod, status, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
                legacyData.orders.forEach(o => {
                    stmt.run(o.id, o.name, o.phone, o.item, o.jerseySize || '', o.itemPrice || 0, o.deliveryMethod || '', o.address || '', o.deliveryFee || 0, o.totalPayable || 0, o.paymentMethod || '', o.status || 'Pending', o.createdAt || new Date().toISOString());
                });
                stmt.finalize();
            }

            // Migrate service requests
            if (Array.isArray(legacyData.serviceRequests)) {
                const stmt = db.prepare(`INSERT OR IGNORE INTO service_requests (id, idempotencyKey, serviceName, clientName, clientPhone, alternativePhone, location, area, landmark, preferredDate, preferredTime, clientNotes, status, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
                legacyData.serviceRequests.forEach(s => {
                    stmt.run(s.id, null, s.serviceName, s.clientName, s.clientPhone, s.alternativePhone || '', s.location || '', s.area || '', s.landmark || '', s.preferredDate || '', s.preferredTime || '', s.clientNotes || '', s.status || 'Pending', s.createdAt || new Date().toISOString());
                });
                stmt.finalize();
            }

            // Migrate contacts
            if (Array.isArray(legacyData.contacts)) {
                const stmt = db.prepare(`INSERT OR IGNORE INTO contacts (id, name, subject, contactDetail, message, createdAt) VALUES (?, ?, ?, ?, ?, ?)`);
                legacyData.contacts.forEach(c => {
                    stmt.run(c.id, c.name, c.subject || c.reference || '', c.contactDetail || '', c.message || '', c.createdAt || new Date().toISOString());
                });
                stmt.finalize();
            }
        });

        // Rename legacy json so migration doesn't run twice
        fs.renameSync(LEGACY_JSON, path.join(__dirname, 'database.json.migrated'));
        console.log('[MIGRATION] Successfully imported legacy database.json into SQLite DB!');
    } catch (err) {
        console.error('[MIGRATION ERROR]', err);
    }
}

// ==========================================
// 4. JWT & AUTHENTICATION MIDDLEWARE
// ==========================================
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ success: false, message: 'Access token required.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: 'Invalid or expired token.' });
        req.user = user;
        next();
    });
}

function requireAdmin(req, res, next) {
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({ success: false, message: 'Admin access privileges required.' });
    }
    next();
}

// ==========================================
// 5. API ROUTES
// ==========================================

app.get('/', (req, res) => {
    res.send('TECCIRA HOLDINGS Production Backend (SQLite & JWT Active)');
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// Authentication: Signup
app.post('/api/signup', authLimiter, async (req, res) => {
    const { name, fullName, email, phone, password } = req.body;
    const userName = (name || fullName || '').trim();
    const userEmail = (email || '').trim().toLowerCase();
    const userPhone = (phone || '').trim();

    if (!userName || (!userEmail && !userPhone) || !password) {
        return res.status(400).json({ success: false, message: 'Full name, valid contact info, and password required.' });
    }

    db.get(`SELECT * FROM users WHERE (email = ? AND email != '') OR (phone = ? AND phone != '')`, [userEmail, userPhone], async (err, row) => {
        if (row) {
            return res.status(400).json({ success: false, message: 'An account with this email or phone already exists.' });
        }

        try {
            const hashedPassword = await bcrypt.hash(password, 10);
            const userId = 'TH-USR-' + Date.now().toString().slice(-6);
            const createdAt = new Date().toISOString();
            const role = 'user';

            db.run(`INSERT INTO users (id, name, email, phone, password, role, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [userId, userName, userEmail, userPhone, hashedPassword, role, createdAt],
                function (err) {
                    if (err) return res.status(500).json({ success: false, message: 'Database error creating user.' });

                    const token = jwt.sign({ id: userId, name: userName, role }, JWT_SECRET, { expiresIn: '24h' });
                    res.status(201).json({
                        success: true,
                        message: 'Account created successfully!',
                        token,
                        user: { id: userId, name: userName, email: userEmail, phone: userPhone, role }
                    });
                }
            );
        } catch (error) {
            res.status(500).json({ success: false, message: 'Error hashing password.' });
        }
    });
});

// Authentication: Login
app.post('/api/login', authLimiter, (req, res) => {
    const { identifier, password } = req.body;
    const inputId = (identifier || '').trim();

    if (!inputId || !password) {
        return res.status(400).json({ success: false, message: 'Please provide credentials and password.' });
    }

    db.get(`SELECT * FROM users WHERE LOWER(email) = LOWER(?) OR phone = ? OR LOWER(name) = LOWER(?)`, [inputId, inputId, inputId], async (err, user) => {
        if (err || !user) {
            return res.status(401).json({ success: false, message: 'Invalid credentials.' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ success: false, message: 'Invalid credentials.' });
        }

        const token = jwt.sign({ id: user.id, name: user.name, role: user.role || 'user' }, JWT_SECRET, { expiresIn: '24h' });
        res.json({
            success: true,
            message: 'Login successful!',
            token,
            user: { id: user.id, name: user.name, email: user.email, phone: user.phone, role: user.role || 'user' }
        });
    });
});

// Orders Endpoint (with Idempotency-Key support)
app.post('/api/orders', (req, res) => {
    const idempotencyKey = req.headers['idempotency-key'] || null;
    const { name, phone, item, jerseySize, itemPrice, deliveryMethod, address, deliveryFee, totalPayable, paymentMethod } = req.body;

    if (idempotencyKey) {
        db.get(`SELECT * FROM orders WHERE idempotencyKey = ?`, [idempotencyKey], (err, existingOrder) => {
            if (existingOrder) {
                return res.json({ success: true, message: 'Duplicate submission caught by idempotency key.', order: existingOrder });
            }
            insertOrder();
        });
    } else {
        insertOrder();
    }

    function insertOrder() {
        const orderId = 'TH-ORD-' + Date.now().toString().slice(-6);
        const createdAt = new Date().toISOString();

        db.run(`INSERT INTO orders (id, idempotencyKey, name, phone, item, jerseySize, itemPrice, deliveryMethod, address, deliveryFee, totalPayable, paymentMethod, status, createdAt)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending', ?)`,
            [orderId, idempotencyKey, name, phone, item, jerseySize || '', itemPrice || 0, deliveryMethod || '', address || '', deliveryFee || 0, totalPayable || 0, paymentMethod || '', createdAt],
            function (err) {
                if (err) return res.status(500).json({ success: false, message: 'Error saving order.' });
                res.status(201).json({ success: true, message: 'Order submitted successfully!', order: { id: orderId, name, item, totalPayable } });
            }
        );
    }
});

app.get('/api/orders', (req, res) => {
    db.all(`SELECT * FROM orders ORDER BY createdAt DESC`, [], (err, rows) => {
        if (err) return res.status(500).json([]);
        res.json(rows);
    });
});

// Service Requests Endpoint
app.post('/api/services/request', (req, res) => {
    const idempotencyKey = req.headers['idempotency-key'] || null;
    const { serviceName, clientName, clientPhone, alternativePhone, location, area, landmark, preferredDate, preferredTime, clientNotes } = req.body;

    const reqId = 'TH-SRV-' + Date.now().toString().slice(-6);
    const createdAt = new Date().toISOString();

    db.run(`INSERT INTO service_requests (id, idempotencyKey, serviceName, clientName, clientPhone, alternativePhone, location, area, landmark, preferredDate, preferredTime, clientNotes, status, createdAt)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending', ?)`,
        [reqId, idempotencyKey, serviceName, clientName, clientPhone, alternativePhone || '', location || '', area || '', landmark || '', preferredDate || '', preferredTime || '', clientNotes || '', createdAt],
        function (err) {
            if (err) return res.status(500).json({ success: false, message: 'Error saving request.' });
            res.status(201).json({ success: true, message: 'Service request logged!', request: { id: reqId, serviceName, clientName } });
        }
    );
});

app.get('/api/services/requests', (req, res) => {
    db.all(`SELECT * FROM service_requests ORDER BY createdAt DESC`, [], (err, rows) => {
        if (err) return res.status(500).json([]);
        res.json(rows);
    });
});

// Users List API (Excludes Hashed Passwords)
app.get('/api/users', (req, res) => {
    db.all(`SELECT id, name, email, phone, role, createdAt FROM users ORDER BY createdAt DESC`, [], (err, rows) => {
        if (err) return res.status(500).json([]);
        res.json(rows);
    });
});

// Contact Messages Endpoint
app.post('/api/contact', (req, res) => {
    const msgId = 'TH-MSG-' + Date.now().toString().slice(-6);
    const createdAt = new Date().toISOString();

    db.run(`INSERT INTO contacts (id, name, subject, contactDetail, message, createdAt) VALUES (?, ?, ?, ?, ?, ?)`,
        [msgId, req.body.name || '', req.body.subject || '', req.body.contactDetail || '', req.body.message || '', createdAt],
        function (err) {
            if (err) return res.status(500).json({ success: false, message: 'Error saving message.' });
            res.status(201).json({ success: true, message: 'Contact message saved.', contactId: msgId });
        }
    );
});

app.get('/api/contact', (req, res) => {
    db.all(`SELECT * FROM contacts ORDER BY createdAt DESC`, [], (err, rows) => {
        if (err) return res.status(500).json([]);
        res.json({ success: true, count: rows.length, data: rows });
    });
});

// Admin Clear Endpoint (Protected Route option)
app.post('/api/admin/clear', (req, res) => {
    const { target } = req.body;
    let query = '';

    if (target === 'orders') query = 'DELETE FROM orders';
    else if (target === 'serviceRequests') query = 'DELETE FROM service_requests';
    else if (target === 'contacts') query = 'DELETE FROM contacts';
    else if (target === 'users') query = 'DELETE FROM users';
    else if (target === 'all') query = 'DELETE FROM orders; DELETE FROM service_requests; DELETE FROM contacts; DELETE FROM users;';
    else return res.status(400).json({ success: false, message: 'Invalid target specified.' });

    db.exec(query, (err) => {
        if (err) return res.status(500).json({ success: false, message: 'Error clearing logs.' });
        console.log(`[ADMIN ACTION] Cleared SQLite records for target: ${target}`);
        res.json({ success: true, message: `Successfully cleared ${target} from SQLite database.` });
    });
});

// Start Server
app.listen(PORT, () => {
    console.log(`===========================================================`);
    console.log(`  TECCIRA HOLDINGS Production Server Running on Port ${PORT}`);
    console.log(`  Database: SQLite (database.sqlite)`);
    console.log(`  Security: Helmet, Rate-Limiter, Bcrypt & Signed JWT Active`);
    console.log(`===========================================================`);
});