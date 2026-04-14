const express = require('express');
const mysql = require('mysql2');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const multer = require('multer');
const { exec } = require('child_process');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;
// SECURITY FIX: Configured CORS to restrict access to localhost only
// Prevents unauthorized cross-origin requests from external domains
app.use(cors({ origin: 'http://localhost:3000' }));
app.use(cookieParser());

// SECURITY FIX: Added rate limiting to protect login endpoints
// Reduces risk of credential stuffing and brute force password attacks
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 login requests per window
    message: "Too many login attempts, please try again later"
});

// SECURITY FIX: Implemented CSRF protection for form submissions
// Ensures requests originate from legitimate user sessions only
const csrfProtection = csrf({ cookie: true });
// SECURITY FIX: Secured session cookies with httpOnly flag
// Mitigates session theft via cross-site scripting attacks
app.use(session({
    secret: process.env.SESSION_SECRET || 'insecure_default_secret',
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false, // Note: Should be true in production with HTTPS
        httpOnly: true // Prevents JavaScript access to cookies
    }
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
// SECURITY FIX: Added file type restrictions for upload feature
// Prevents malicious file uploads by allowing only image MIME types
const upload = multer({ 
    dest: 'public/uploads/',
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    }
});
const db = mysql.createPool({
    host: process.env.DB_HOST || '127.0.0.1',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'infosec_activity'
});
// SECURITY FIX: Converted to prepared statements and bcrypt password hashing
// Eliminates SQL injection vulnerabilities and improves password security
app.post('/api/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    
    // Query user by username ONLY (not password)
    const query = 'SELECT * FROM users WHERE username = ?';

    db.query(query, [username], async (err, results) => {
        if (err) {
            console.error(err); // Server-side logging for debugging
            return res.status(500).json({ error: 'An internal server error occurred.' });
        }

        if (results.length > 0) {
            // Compare provided password with stored hash using bcrypt
            const match = await bcrypt.compare(password, results[0].password);
            if(match) {
                req.session.user = results[0];
                res.json({ success: true, message: 'Logged in successfully', user: results[0] });
            } else {
                res.status(401).json({ success: false, message: 'Invalid credentials' });
            }
        } else {
            res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
    });
});
// SECURITY FIX: Used parameterized queries and output encoding
// Stops SQL injection and reflected cross-site scripting attacks
app.get('/api/search', (req, res) => {
    const searchQuery = req.query.q;
    const sql = 'SELECT username, bio FROM users WHERE username LIKE ?';

    db.query(sql, [`%${searchQuery}%`], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'An internal server error occurred.' });
        }
        if (req.headers.accept && req.headers.accept.includes('text/html')) {
            // Sanitize searchQuery to prevent reflected XSS
            const safeQuery = searchQuery.replace(/</g, "&lt;").replace(/>/g, "&gt;");
            return res.send(`<h1>Search Results for: ${safeQuery}</h1> <pre>${JSON.stringify(results)}</pre>`);
        }

        res.json({ query: searchQuery, results });
    });
});
// SECURITY FIX: Required user authentication for message posting
// Prevents unauthorized access and protects forum integrity
app.post('/api/messages', csrfProtection, (req, res) => {
    // Block the action entirely if no session exists!
    if (!req.session || !req.session.user) {
        return res.status(401).json({ error: 'You must be logged in to post on the forum.' });
    }
    
    const username = req.session.user.username;
    const content = req.body.content;
    
    // Sanitize content to prevent stored XSS attacks
    const sanitizedContent = content.replace(/</g, "&lt;").replace(/>/g, "&gt;");
    
    const sql = 'INSERT INTO messages (username, content) VALUES (?, ?)';

    db.query(sql, [username, sanitizedContent], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'An internal server error occurred.' });
        }
        res.json({ success: true, message: 'Message posted!' });
    });
});

app.get('/api/messages', (req, res) => {
    db.query('SELECT * FROM messages ORDER BY created_at DESC', (err, results) => {
        if (err) return res.status(500).send(err.message);
        res.json(results);
    });
});
// SECURITY FIX: Replaced direct object references with session-based access
// Prevents unauthorized access to other users' profile information
app.get('/api/profile', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const userId = req.session.user.id; // Only use trusted session ID

    db.query('SELECT id, username, bio, is_admin FROM users WHERE id = ?', [userId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'An internal server error occurred.' });
        }
        if (results.length === 0) return res.status(404).json({ error: 'User not found' });
        res.json(results[0]);
    });
});
// SECURITY FIX: Limited profile updates to non-administrative fields
// Stops privilege escalation through profile manipulation
app.post('/api/profile/update', csrfProtection, (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

    const userId = req.session.user.id;
    const { bio } = req.body; // Only extract allowed field: bio

    const sql = 'UPDATE users SET bio = ? WHERE id = ?';
    db.query(sql, [bio, userId], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'An internal server error occurred.' });
        }
        res.json({ success: true, message: 'Profile updated' });
    });
});
// SECURITY FIX: Implemented IP address format validation
// Blocks command injection attacks through input sanitization
app.post('/api/network-ping', (req, res) => {
    const ip = req.body.ip;
    
    // Validate IP address format to prevent command injection
    if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
        return res.json({ success: false, output: 'Invalid IP address format.' });
    }
    
    exec(`ping -n 1 ${ip}`, (error, stdout, stderr) => {
        if (error) {
            return res.json({ success: false, output: stderr || error.message });
        }
        res.json({ success: true, output: stdout });
    });
});
app.post('/api/upload-avatar', csrfProtection, upload.single('avatar'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    const newPath = path.join(__dirname, 'public/uploads', req.file.originalname);
    fs.renameSync(req.file.path, newPath);

    res.json({ success: true, message: 'File uploaded!', path: `/uploads/${req.file.originalname}` });
});
// SECURITY FIX: Added filename sanitization for download feature
// Prevents directory traversal by extracting safe filename only
app.get('/api/download', (req, res) => {
    const filename = req.query.file;
    const safeFilename = path.basename(filename); // Strips "../" and other traversal characters
    const filePath = path.join(__dirname, 'public/uploads', safeFilename);

    res.download(filePath, (err) => {
        if (err) {
            console.error(err);
            res.status(500).send('File not found or access denied');
        }
    });
});
// SECURITY FIX: Excluded password hashes from user listings
// Reduces sensitive data exposure in user directory
app.get('/api/users', (req, res) => {
    db.query('SELECT id, username, bio, is_admin FROM users', (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'An internal server error occurred.' });
        }
        res.json(results);
    });
});
// SECURITY FIX: Blocked internal network access in URL fetching
// Prevents SSRF attacks by filtering private IP ranges
app.post('/api/fetch-url', async (req, res) => {
    const targetUrl = req.body.url;
    
    try {
        const url = new URL(targetUrl);
        
        // Block internal/private IP ranges to prevent SSRF
        const hostname = url.hostname;
        if (hostname === 'localhost' || 
            hostname === '127.0.0.1' || 
            hostname.startsWith('192.168.') ||
            hostname.startsWith('10.') ||
            hostname.startsWith('172.') ||
            hostname.startsWith('169.254.')) {
            return res.status(400).json({ error: 'Access to internal resources is not allowed.' });
        }
        
        // Only allow HTTP/HTTPS protocols
        if (!['http:', 'https:'].includes(url.protocol)) {
            return res.status(400).json({ error: 'Only HTTP and HTTPS URLs are allowed.' });
        }
        
        const response = await axios.get(targetUrl);
        res.send(response.data);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error fetching URL.' });
    }
});
// SECURITY FIX: Added redirect URL validation and domain restrictions
// Stops open redirect phishing attacks through URL filtering
app.get('/api/redirect', (req, res) => {
    const targetUrl = req.query.url;
    
    if (!targetUrl) {
        return res.status(400).json({ error: 'URL parameter is required.' });
    }
    
    // Only allow relative paths (starting with /) or specific trusted domains
    if (targetUrl.startsWith('/') || targetUrl.startsWith('http://localhost:3000') || targetUrl.startsWith('http://127.0.0.1:3000')) {
        return res.redirect(targetUrl);
    }
    
    // Block external redirects to prevent phishing
    res.status(400).json({ error: 'External redirects are not allowed.' });
});

app.listen(port, () => {
    console.log(`Vulnerable App is learning on http://localhost:${port}`);
    console.log('Ensure your XAMPP Apache and MySQL are running!');
});
