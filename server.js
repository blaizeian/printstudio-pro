require('dotenv').config();

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');
const cors = require('cors');
const path = require('path');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet'); // [PATCH] Added helmet for security headers
const crypto = require('crypto'); // [PATCH] Added crypto for secure random generation

const app = express();
// --- TRUST PROXY SETTING ---
// Tells Express it is sitting behind a trusted reverse proxy (like Nginx)
app.set('trust proxy', 1);
const PORT = 3000;

// [FIX] Relax Content Security Policy so local Tailwind CDN and scripts load correctly
app.use(
    helmet({
        contentSecurityPolicy: false,
    })
);

// Middleware Configurations
app.use(cors({
    origin: [
        'http://localhost:3000',
        'https://printstudio-pos-production.up.railway.app',
        process.env.CORS_ORIGIN
    ].filter(Boolean), // Removes any undefined values safely
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
//app.use(express.static(path.join(__dirname, 'private')));

// Connect to XAMPP MySQL instance database
// [PATCH] DB connection now uses .env variables instead of hardcoded values
const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// SESSION CONFIG
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback_secret_key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // true on VPS (HTTPS), false locally (HTTP)
        httpOnly: true, // Prevents client-side JS from reading the cookie (stops XSS cookie theft)
        sameSite: 'strict', // [PATCH] Prevents cookie from being sent on cross-site requests (CSRF protection)
        maxAge: 1000 * 60 * 60 * 8 // 8 hour session timeout
    }
}));

// [PATCH] Rate limiter for login route — already existed, kept as-is
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes window
    max: 10, // Limit each IP to 10 login attempts per windowMs
    message: {
        success: false,
        message: "Too many login attempts from this IP address. Please try again after 15 minutes."
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// [PATCH] Dedicated rate limiter for the password reset route (was completely unprotected before)
const resetPasswordLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minute window
    max: 5, // Only 5 reset attempts per IP per window
    message: {
        success: false,
        message: "Too many password reset attempts. Please try again after 15 minutes."
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// [PATCH] Secure random ID generator using crypto instead of Math.random()
// Math.random() is not cryptographically secure and its output is predictable
function generateSecureId(length = 6) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars[crypto.randomInt(0, chars.length)];
    }
    return result;
}

function verifyRole(allowedRoles) {
    return (req, res, next) => {
        if (!req.session || !req.session.user || !req.session.loggedIn) {
            if (req.originalUrl.startsWith('/api/')) {
                return res.status(401).json({ success: false, message: "Unauthorized session." });
            }
            return res.redirect('/login');
        }

        const userRole = (req.session.user.role || '').trim().toLowerCase();
        const normalizedAllowed = allowedRoles.map(r => r.toLowerCase());

        if (normalizedAllowed.includes(userRole)) {
            next();
        } else {
            if (req.originalUrl.startsWith('/api/')) {
                return res.status(403).json({ success: false, message: "Forbidden. Insufficient permissions." });
            }
            res.status(403).send("<h1>403 Forbidden</h1><p>Access Denied</p>");
        }
    };
}

app.get('/api/current-user', (req, res) => {
    if (!req.session || !req.session.user) {
        return res.status(401).json({ role: 'guest' });
    }
    res.json({ username: req.session.user.username, role: req.session.user.role });
});

function isAuthenticated(req, res, next) {
    if (req.session.loggedIn) return next();
    res.redirect('/login');
}

// ================= API ENDPOINT: GET HISTORICAL ARCHIVE =================
app.get('/api/history', verifyRole(['admin', 'cashier']), async (req, res) => {
    try {
        const [rows] = await db.execute(`
            SELECT 
                o.id as tx_number, 
                o.total_amount as total, 
                o.created_at,
                0 as tax,
                oi.product_name as item_name, 
                oi.quantity, 
                0 as unit_price,
                u.username as cashier_name,
                u.role as cashier_role
            FROM orders o
            LEFT JOIN order_items oi ON o.id = oi.order_id
            LEFT JOIN users u ON o.user_id = u.id
            ORDER BY o.id DESC
        `);

        const archiveMap = {};
        rows.forEach(row => {
            if (!archiveMap[row.tx_number]) {
                const dateObj = new Date(row.created_at);
                const timeStr = dateObj.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

                archiveMap[row.tx_number] = {
                    id: row.tx_number,
                    date: `Today, ${timeStr}`,
                    total: parseFloat(row.total) || 0,
                    tax: parseFloat(row.tax) || 0,
                    status: 'Completed',
                    cashier_name: row.cashier_name || 'System / Unassigned',
                    cashier_role: row.cashier_role || '',
                    items: []
                };
            }

            if (row.item_name) {
                archiveMap[row.tx_number].items.push({
                    name: row.item_name,
                    qty: row.quantity,
                    price: parseFloat(row.unit_price) || 0
                });
            }
        });

        const records = Object.values(archiveMap).sort((a, b) => b.id - a.id).map(record => {
            record.itemSummary = record.items.map(i => `${i.name} ×${i.qty}`).join(', ');
            return record;
        });

        res.json(records);
    } catch (error) {
        console.error('SQL retrieval exception:', error);
        res.status(500).json({ success: false, message: 'Database structural read failure.' });
    }
});

// Analytics API Endpoint
app.get('/api/analytics', verifyRole(['admin']), async (req, res) => {
    const type = req.query.type || 'daily';
    const today = new Date().toISOString().split('T')[0];
    const start = (req.query.start && req.query.start !== "") ? req.query.start : today;
    const end = (req.query.end && req.query.end !== "") ? req.query.end : today;

    let sqlQuery = '';
    let params = [];
    let isYearly = (type === 'yearly');

    if (type === 'daily') {
        sqlQuery = `SELECT DATE_FORMAT(created_at, '%H:00') as label, SUM(total_amount) as total 
                    FROM orders WHERE DATE(created_at) = ? 
                    GROUP BY HOUR(created_at), DATE_FORMAT(created_at, '%H:00') 
                    ORDER BY HOUR(created_at) ASC`;
        params = [start];
    } else if (type === 'weekly') {
        sqlQuery = `SELECT DATE_FORMAT(created_at, '%a %d') as label, SUM(total_amount) as total 
                    FROM orders WHERE DATE(created_at) BETWEEN ? AND ? 
                    GROUP BY DATE(created_at), DATE_FORMAT(created_at, '%a %d') 
                    ORDER BY DATE(created_at) ASC`;
        params = [start, end];
    } else if (type === 'monthly') {
        sqlQuery = `SELECT DATE_FORMAT(created_at, '%b %d') as label, SUM(total_amount) as total 
                    FROM orders WHERE DATE(created_at) BETWEEN ? AND ? 
                    GROUP BY DATE(created_at), DATE_FORMAT(created_at, '%b %d') 
                    ORDER BY DATE(created_at) ASC`;
        params = [start, end];
    } else if (type === 'yearly') {
        const year = start.substring(0, 4) || new Date().getFullYear();
        sqlQuery = `SELECT MONTH(created_at) as month_num, SUM(total_amount) as total 
                    FROM orders WHERE YEAR(created_at) = ? 
                    GROUP BY MONTH(created_at) ORDER BY MONTH(created_at) ASC`;
        params = [year];
    }

    try {
        const [rawChartData] = await db.execute(sqlQuery, params);

        let chartData = rawChartData;

        if (isYearly) {
            const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
            chartData = monthNames.map((name, index) => {
                const found = rawChartData.find(row => row.month_num === (index + 1));
                return {
                    label: name,
                    total: found ? parseFloat(found.total) : 0
                };
            });
        }

        let statsSql = `SELECT IFNULL(SUM(total_amount), 0) as totalRevenue, COUNT(*) as totalOrders 
                        FROM orders WHERE DATE(created_at) BETWEEN ? AND ?`;
        let statsParams = [start, end];

        if (isYearly) {
            const year = start.substring(0, 4) || new Date().getFullYear();
            statsSql = `SELECT IFNULL(SUM(total_amount), 0) as totalRevenue, COUNT(*) as totalOrders 
                        FROM orders WHERE YEAR(created_at) = ?`;
            statsParams = [year];
        }

        const [statsResult] = await db.execute(statsSql, statsParams);
        const stats = statsResult[0] || { totalRevenue: 0, totalOrders: 0 };

        res.json({
            success: true,
            chartData: chartData,
            stats: stats
        });
    } catch (err) {
        console.error("Database error:", err);
        res.status(500).json({ success: false, message: "Error fetching analytics" });
    }
});

app.get('/api/first-sale-date', verifyRole(['admin', 'cashier']), async (req, res) => {
    try {
        const [rows] = await db.execute("SELECT DATE(MIN(created_at)) as minDate FROM orders");
        res.json({ minDate: rows[0].minDate || new Date().toISOString().split('T')[0] });
    } catch (err) {
        res.status(500).json({ error: "Could not fetch date" });
    }
});

// --- INVENTORY API ROUTES ---

// [PATCH] Removed stray double comma in allowedRoles array (was ['admin', 'cashier', , 'vendor'])
app.get('/api/products', verifyRole(['admin', 'cashier', 'vendor']), async (req, res) => {
    try {
        const [rows] = await db.execute("SELECT * FROM products ORDER BY id DESC");
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch products" });
    }
});

app.post('/api/products', verifyRole(['admin']), async (req, res) => {
    const { name, price, stock, category } = req.body;
    try {
        await db.execute(
            "INSERT INTO products (name, price, stock, category) VALUES (?, ?, ?, ?)",
            [name, price, stock, category]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: "Database error" });
    }
});

app.post('/api/products/update', verifyRole(['admin']), async (req, res) => {
    const { id, change } = req.body;
    try {
        await db.execute("UPDATE products SET stock = stock + ? WHERE id = ?", [change, id]);

        const [rows] = await db.execute("SELECT name, stock FROM products WHERE id = ?", [id]);
        if (rows.length > 0) {
            const { name, stock } = rows[0];
            const formattedChange = parseInt(change) > 0 ? `+${change}` : `${change}`;

            await db.execute(
                "INSERT INTO audit_logs (action_type, description) VALUES (?, ?)",
                ['STOCK_UPDATE', `Stock updated for "${name}": adjusted by ${formattedChange}. New total: ${stock} units.`]
            );

            if (stock < 10) {
                await db.execute(
                    "INSERT INTO audit_logs (action_type, description) VALUES (?, ?)",
                    ['LOW_STOCK', `Low stock warning: "${name}" has dropped to ${stock} units.`]
                );
            }
        }

        res.json({ success: true });
    } catch (err) {
        console.error("Error updating stock:", err);
        res.status(500).json({ success: false });
    }
});

// --- SALES CHECKOUT ROUTE ---
app.post('/api/checkout', verifyRole(['admin', 'cashier', 'vendor']), async (req, res) => {
    // 1. Extract items, loan fields, AND depositAmount from req.body
    const { items, isLoan, customerName, customerPhone, depositAmount } = req.body;
    const currentUser = req.session.user || req.user;

    if (!items || !Array.isArray(items) || items.length === 0) {
        return res.status(400).json({ success: false, message: "Invalid or empty cart" });
    }

    // 2. Validate customer name if it's marked as a loan
    if (isLoan && (!customerName || customerName.trim() === '')) {
        return res.status(400).json({ success: false, message: "Customer name is required for loan transactions." });
    }

    const connection = await db.getConnection();

    try {
        await connection.beginTransaction();

        let calculatedTotal = 0;
        const processedItems = [];

        for (const item of items) {
            const finalId = item.id || item.orderId;
            const finalQty = parseInt(item.qty || item.quantity) || 0;

            if (!finalId || finalQty <= 0) {
                throw new Error("Invalid product ID or quantity.");
            }

            const [rows] = await connection.execute('SELECT id, name, price, stock FROM products WHERE id = ?', [finalId]);
            if (rows.length === 0) {
                throw new Error(`Product not found.`);
            }

            const product = rows[0];
            const finalName = product.name;
            const finalPrice = parseFloat(product.price) || 0;

            if (product.stock < finalQty) {
                throw new Error(`Insufficient stock for ${finalName}`);
            }

            calculatedTotal += finalPrice * finalQty;

            processedItems.push({
                id: product.id,
                name: finalName,
                qty: finalQty,
                price: finalPrice
            });
        }

        // 3. Process and validate deposit & loan balance calculations
        const parsedDeposit = parseFloat(depositAmount) || 0;

        if (isLoan && parsedDeposit > calculatedTotal) {
            throw new Error("Deposit cannot be greater than the total order amount.");
        }

        const finalDeposit = isLoan ? parsedDeposit : 0;
        const loanBalance = isLoan ? Math.max(0, calculatedTotal - finalDeposit) : 0;
        const userId = currentUser ? currentUser.id : null;

        // 4. Insert into the orders table with deposit and loan balance included
        const [orderResult] = await connection.execute(
            `INSERT INTO orders (total_amount, user_id, is_loan, customer_name, customer_phone, deposit_amount, loan_balance, loan_status) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                calculatedTotal,
                userId,
                isLoan ? 1 : 0,
                isLoan ? customerName.trim() : null,
                isLoan && customerPhone ? customerPhone.trim() : null,
                finalDeposit,
                loanBalance,
                isLoan ? 'unpaid' : 'paid'
            ]
        );
        const orderId = orderResult.insertId;

        for (const item of processedItems) {
            await connection.execute(
                'INSERT INTO order_items (order_id, product_name, quantity, price_at_sale) VALUES (?, ?, ?, ?)',
                [orderId, item.name, item.qty, item.price]
            );

            await connection.execute(
                'UPDATE products SET stock = stock - ? WHERE id = ?',
                [item.qty, item.id]
            );

            const [stockRows] = await connection.execute('SELECT name, stock FROM products WHERE id = ?', [item.id]);
            if (stockRows.length > 0) {
                const updatedProduct = stockRows[0];
                if (updatedProduct.stock < 10) {
                    await connection.execute(
                        "INSERT INTO audit_logs (action_type, description) VALUES (?, ?)",
                        ['LOW_STOCK', `Low stock warning: "${updatedProduct.name}" has dropped to ${updatedProduct.stock} units.`]
                    );
                }
            }
        }

        await connection.commit();
        res.json({ success: true, orderId: orderId, message: isLoan ? "Loan order recorded successfully!" : "Order recorded successfully!" });

    } catch (error) {
        await connection.rollback();
        console.error("--- CHECKOUT ERROR ---", error);
        res.status(400).json({ success: false, message: error.message });
    } finally {
        connection.release();
    }
}); 
app.get('/api/reports', verifyRole(['admin']), async (req, res) => {
    const type = req.query.type || 'weekly';

    let dateFilter = "";
    let params = [];

    if (type === 'daily') {
        dateFilter = "DATE(created_at) = CURDATE()";
    } else {
        const days = type === 'monthly' ? 30 : 7;
        dateFilter = "created_at >= NOW() - INTERVAL ? DAY";
        params = [days];
    }

    try {
        const [kpiRows] = await db.execute(`
            SELECT 
                IFNULL(SUM(total_amount), 0) as totalRevenue,
                COUNT(*) as totalTrans,
                IFNULL(AVG(total_amount), 0) as avgSale
            FROM orders 
            WHERE ${dateFilter}
        `, params);

        const [topItemRows] = await db.execute(`
            SELECT oi.product_name, SUM(oi.quantity) as totalQty
            FROM order_items oi
            JOIN orders o ON o.id = oi.order_id
            WHERE ${dateFilter.replace(/created_at/g, 'o.created_at')}
            GROUP BY oi.product_name
            ORDER BY totalQty DESC
            LIMIT 1
        `, params);

        const topItem = topItemRows.length > 0 ? topItemRows[0].product_name : '-';

        const [txRows] = await db.execute(`
            SELECT 
                o.id,
                o.total_amount,
                o.created_at,
                IFNULL(GROUP_CONCAT(CONCAT(oi.product_name, ' (x', oi.quantity, ')') SEPARATOR ', '), 'General Item') as itemsSummary
            FROM orders o
            LEFT JOIN order_items oi ON o.id = oi.order_id
            WHERE ${dateFilter.replace(/created_at/g, 'o.created_at')}
            GROUP BY o.id
            ORDER BY o.created_at DESC
        `, params);

        res.json({
            success: true,
            kpis: {
                revenue: parseFloat(kpiRows[0].totalRevenue),
                transactions: kpiRows[0].totalTrans,
                avgSale: parseFloat(kpiRows[0].avgSale),
                topItem: topItem
            },
            transactions: txRows
        });

    } catch (error) {
        console.error("Reports API error:", error);
        res.status(500).json({ success: false, message: "Error fetching financial reports" });
    }
});

// --- PUBLIC ROUTES ---
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'private', 'login.html'));
});

app.post('/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.json({ success: false, message: 'All fields are required' });
    }

    try {
        const inputVal = username.trim();

        const [results] = await db.execute(
            'SELECT * FROM users WHERE username = ? OR UPPER(login_id) = UPPER(?)',
            [inputVal, inputVal]
        );

        if (results.length === 0) {
            return res.json({ success: false, message: 'Invalid credentials' });
        }

        const user = results[0];
        const match = await bcrypt.compare(password, user.password_hash);

        if (match) {
            req.session.loggedIn = true;
            req.session.user = {
                id: user.id,
                username: user.username,
                role: user.role
            };
            return res.json({ success: true });
        } else {
            return res.json({ success: false, message: 'Invalid credentials' });
        }
    } catch (err) {
        console.error('Login error:', err);
        return res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Logout failed' });
        }
        res.clearCookie('connect.sid');
        res.json({ success: true });
    });
});

// --- PROTECTED PAGE ROUTES ---
app.get('/', verifyRole(['admin', 'cashier', 'vendor']), (req, res) => {
    res.sendFile(path.join(__dirname, 'private', 'index.html'));
});

app.get('/reports', verifyRole(['admin']), (req, res) => {
    res.sendFile(path.join(__dirname, 'private', 'reports.html'));
});

app.get('/history', verifyRole(['admin', 'cashier']), (req, res) => {
    res.sendFile(path.join(__dirname, 'private', 'history.html'));
});

app.get('/analytics', verifyRole(['admin']), (req, res) => {
    res.sendFile(path.join(__dirname, 'private', 'analytics.html'));
});

app.get('/inventory', verifyRole(['admin', 'cashier']), (req, res) => {
    res.sendFile(path.join(__dirname, 'private', 'inventory.html'));
});

// --- CASHIER MANAGEMENT ROUTES (Admin Only) ---

// [PATCH] generateLoginId now uses generateSecureId() — crypto.randomInt() instead of Math.random()
function generateLoginId() {
    return generateSecureId(6);
}

app.get('/cashiers', verifyRole(['admin']), (req, res) => {
    res.sendFile(path.join(__dirname, 'private', 'cashiers.html'));
});

app.get('/api/cashiers', verifyRole(['admin']), async (req, res) => {
    try {
        const [rows] = await db.execute(
            "SELECT id, username, role, login_id, created_at FROM users WHERE role IN ('cashier', 'vendor') ORDER BY id DESC"
        );
        res.json(rows);
    } catch (err) {
        console.error("Error fetching cashiers:", err);
        res.status(500).json({ success: false, message: "Failed to fetch cashiers" });
    }
});

app.post('/api/cashiers', verifyRole(['admin']), async (req, res) => {
    const { username, password, role } = req.body;

    if (!username || !password) {
        return res.status(400).json({ success: false, message: "Username and password are required." });
    }

    const userRole = (role === 'vendor') ? 'vendor' : 'cashier';

    try {
        const [existing] = await db.execute('SELECT id FROM users WHERE username = ?', [username]);
        if (existing.length > 0) {
            return res.status(400).json({ success: false, message: "Username already exists." });
        }

        // [PATCH] generateLoginId() now calls generateSecureId() which uses crypto.randomInt()
        let loginId = generateLoginId();
        let isUnique = false;
        while (!isUnique) {
            const [check] = await db.execute('SELECT id FROM users WHERE login_id = ?', [loginId]);
            if (check.length === 0) {
                isUnique = true;
            } else {
                loginId = generateLoginId();
            }
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await db.execute(
            'INSERT INTO users (username, password_hash, role, login_id) VALUES (?, ?, ?, ?)',
            [username, hashedPassword, userRole, loginId]
        );

        res.json({ success: true, message: `${userRole === 'vendor' ? 'Vendor' : 'Cashier'} created! Login ID: ${loginId}` });
    } catch (err) {
        console.error('Error creating user:', err);
        res.status(500).json({ success: false, message: "Internal server error." });
    }
});

app.delete('/api/cashiers/:id', verifyRole(['admin']), async (req, res) => {
    const userId = req.params.id;

    try {
        const [rows] = await db.execute("SELECT * FROM users WHERE id = ? AND role != 'admin'", [userId]);
        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: "User not found or cannot be deleted." });
        }

        const deletedUser = rows[0];

        await db.execute("DELETE FROM users WHERE id = ?", [userId]);

        await db.execute(
            "INSERT INTO audit_logs (action_type, description) VALUES (?, ?)",
            ['USER_DELETE', `Deleted ${deletedUser.role} account: "${deletedUser.username || deletedUser.name}"`]
        );

        res.json({ success: true, message: "User deleted successfully." });
    } catch (err) {
        console.error("Error deleting user:", err);
        res.status(500).json({ success: false, message: "Failed to delete user." });
    }
});

app.post('/api/cashiers/:id/generate-reset-code', verifyRole(['admin']), async (req, res) => {
    const cashierId = req.params.id;

    try {
        const [rows] = await db.execute(
            "SELECT * FROM users WHERE id = ? AND (role = 'cashier' OR role = 'vendor')",
            [cashierId]
        );

        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        // [PATCH] Reset code now uses generateSecureId() — crypto.randomInt() instead of Math.random()
        const resetCode = generateSecureId(6);
        const expires = new Date(Date.now() + 15 * 60 * 1000);

        await db.execute(
            "UPDATE users SET reset_code = ?, reset_expires = ? WHERE id = ?",
            [resetCode, expires, cashierId]
        );

        res.json({ success: true, message: `Reset Code Generated: ${resetCode} (Valid for 15 mins)`, resetCode });
    } catch (err) {
        console.error("Error generating reset code:", err);
        res.status(500).json({ success: false, message: "Internal server error." });
    }
});

// [PATCH] Added resetPasswordLimiter — this route had zero rate limiting before
app.post('/api/auth/reset-password', resetPasswordLimiter, async (req, res) => {
    const { identifier, reset_code, new_password } = req.body;

    if (!identifier || !reset_code || !new_password) {
        return res.json({ success: false, message: "All fields are required." });
    }

    try {
        const cleanIdentifier = identifier.trim();
        const cleanCode = reset_code.trim();

        const [users] = await db.execute(
            `SELECT * FROM users 
             WHERE (UPPER(login_id) = UPPER(?) OR UPPER(username) = UPPER(?)) 
             AND UPPER(reset_code) = UPPER(?) 
             AND reset_expires > NOW()`,
            [cleanIdentifier, cleanIdentifier, cleanCode]
        );

        if (users.length === 0) {
            return res.json({ success: false, message: "Invalid username/login ID, incorrect reset code, or code has expired." });
        }

        const user = users[0];
        const hashedPassword = await bcrypt.hash(new_password, 10);

        await db.execute(
            "UPDATE users SET password_hash = ?, reset_code = NULL, reset_expires = NULL WHERE id = ?",
            [hashedPassword, user.id]
        );

        res.json({ success: true, message: "Password reset successful! You can now log in." });
    } catch (err) {
        console.error("Password reset error:", err);
        res.json({ success: false, message: "Internal server error." });
    }
});

// API: Get sales history for the logged-in vendor
app.get('/api/vendor/my-sales', verifyRole(['vendor']), async (req, res) => {
    try {
        const vendorId = req.session.user.id;

        const [orders] = await db.execute(`
            SELECT o.id as order_id, o.total_amount, o.created_at, 
                   GROUP_CONCAT(CONCAT(oi.product_name, ' (x', oi.quantity, ')') SEPARATOR ', ') as items_summary
            FROM orders o
            LEFT JOIN order_items oi ON o.id = oi.order_id
            WHERE o.user_id = ?
            GROUP BY o.id
            ORDER BY o.created_at DESC
        `, [vendorId]);

        res.json({ success: true, sales: orders });
    } catch (err) {
        console.error("Error fetching vendor sales:", err);
        res.status(500).json({ success: false, message: "Internal server error." });
    }
});

app.get('/vendor-sales', verifyRole(['vendor']), (req, res) => {
    res.sendFile(path.join(__dirname, 'private', 'vendor-sales.html'));
});

app.get('/api/cashiers/sales-summary', verifyRole(['admin']), async (req, res) => {
    try {
        const { period = 'all', date } = req.query;

        let dateCondition = '';
        const queryParams = [];

        if (period === 'daily') {
            if (date) {
                dateCondition = 'AND DATE(t.created_at) = ?';
                queryParams.push(date);
            } else {
                dateCondition = 'AND DATE(t.created_at) = CURDATE()';
            }
        } else if (period === 'weekly') {
            dateCondition = 'AND YEARWEEK(t.created_at, 1) = YEARWEEK(CURDATE(), 1)';
        } else if (period === 'monthly') {
            dateCondition = 'AND YEAR(t.created_at) = YEAR(CURDATE()) AND MONTH(t.created_at) = MONTH(CURDATE())';
        }

        const query = `
            SELECT u.id, u.username, u.role, 
                   COUNT(t.id) AS total_orders, 
                   COALESCE(SUM(t.total_amount), 0) AS total_revenue
            FROM users u
            LEFT JOIN orders t ON u.id = t.user_id ${dateCondition}
            WHERE u.role IN ('cashier', 'vendor')
            GROUP BY u.id, u.username, u.role
        `;

        const [rows] = await db.query(query, queryParams);

        const [minMaxResult] = await db.query('SELECT MIN(DATE(created_at)) as min_date, MAX(DATE(created_at)) as max_date FROM orders');
        const minDate = minMaxResult[0]?.min_date || new Date().toISOString().split('T')[0];
        const maxDate = new Date().toISOString().split('T')[0];

        res.json({ success: true, sales: rows, minDate, maxDate });
    } catch (err) {
        console.error("Failed to load cashier sales summary:", err);
        res.status(500).json({ success: false, message: "Internal server error." });
    }
});

app.get('/api/cashiers/:id/sales-details', verifyRole(['admin']), async (req, res) => {
    const operatorId = req.params.id;
    const period = req.query.period || 'all';
    const targetDate = req.query.date;

    try {
        let query = `
            SELECT o.*, 
                   GROUP_CONCAT(CONCAT(oi.quantity, 'x ', oi.product_name) SEPARATOR ', ') AS items_detail
            FROM orders o
            LEFT JOIN order_items oi ON o.id = oi.order_id
            WHERE o.user_id = ?
        `;
        let params = [operatorId];

        if (period === 'daily' && targetDate) {
            query += ` AND DATE(o.created_at) = ?`;
            params.push(targetDate);
        } else if (period === 'weekly') {
            query += ` AND o.created_at >= DATE_SUB(NOW(), INTERVAL 1 WEEK)`;
        } else if (period === 'monthly') {
            query += ` AND o.created_at >= DATE_SUB(NOW(), INTERVAL 1 MONTH)`;
        }

        query += ` GROUP BY o.id ORDER BY o.created_at DESC`;

        const [transactions] = await db.execute(query, params);
        res.json({ success: true, transactions });
    } catch (err) {
        console.error('Error fetching operator sales details:', err);
        res.status(500).json({ success: false, message: 'Failed to fetch transaction details.' });
    }
});

app.delete('/api/products/:id', verifyRole(['admin']), async (req, res) => {
    const productId = req.params.id;

    try {
        const [rows] = await db.execute("SELECT * FROM products WHERE id = ?", [productId]);
        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: "Product not found." });
        }

        const product = rows[0];
        const productName = product.name;
        const productStock = product.stock;
        const productPrice = product.price;

        await db.execute("DELETE FROM products WHERE id = ?", [productId]);

        await db.execute(
            "INSERT INTO audit_logs (action_type, description) VALUES (?, ?)",
            ['PRODUCT_DELETE', `Deleted product: "${productName}" — Was holding ${productStock} units in stock (Price: ksh${productPrice}).`]
        );

        res.json({ success: true, message: "Product deleted successfully." });
    } catch (err) {
        console.error("Error deleting product:", err);
        res.status(500).json({ success: false, message: "Failed to delete product." });
    }
});

app.delete('/api/categories/:name', verifyRole(['admin']), async (req, res) => {
    const categoryName = decodeURIComponent(req.params.name);

    try {
        const [rows] = await db.execute("SELECT * FROM products WHERE category = ?", [categoryName]);
        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: "Category not found or contains no items." });
        }

        await db.execute("UPDATE products SET category = 'Uncategorized' WHERE category = ?", [categoryName]);

        await db.execute(
            "INSERT INTO audit_logs (action_type, description) VALUES (?, ?)",
            ['CATEGORY_DELETE', `Deleted category: "${categoryName}" (Items moved to Uncategorized)`]
        );

        res.json({ success: true, message: `Category "${categoryName}" deleted. Items moved to Uncategorized.` });
    } catch (err) {
        console.error("Error deleting category:", err);
        res.status(500).json({ success: false, message: "Failed to delete category." });
    }
});

app.get('/messages', verifyRole(['admin']), (req, res) => {
    res.sendFile(path.join(__dirname, 'private', 'messages.html'));
});

app.get('/api/messages', verifyRole(['admin']), async (req, res) => {
    try {
        const { date, limit } = req.query;
        const safeLimit = parseInt(limit) || 50;

        let rows;
        if (date) {
            const [result] = await db.execute(
                `SELECT * FROM audit_logs WHERE DATE(created_at) = ? ORDER BY created_at DESC LIMIT ${safeLimit}`,
                [date]
            );
            rows = result;
        } else {
            const [result] = await db.execute(
                `SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ${safeLimit}`
            );
            rows = result;
        }

        res.json(rows);
    } catch (err) {
        console.error("Error fetching logs:", err);
        res.status(500).json({ success: false, message: "Failed to load messages." });
    }
});

app.get('/account', verifyRole(['admin', 'cashier', 'vendor']), (req, res) => {
    res.sendFile(path.join(__dirname, 'private', 'account.html'));
});

app.get('/api/account-info', verifyRole(['admin', 'cashier', 'vendor']), async (req, res) => {
    try {
        const userId = req.session.user.id;

        const [userRows] = await db.execute(
            "SELECT username, role FROM users WHERE id = ?",
            [userId]
        );

        if (userRows.length === 0) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        const [settingRows] = await db.execute(
            "SELECT shop_name, low_stock_limit, currency FROM settings WHERE id = 1"
        );

        const settings = settingRows.length > 0 ? settingRows[0] : { shop_name: 'PrintStudio Pro', low_stock_limit: 10, currency: 'KES' };

        res.json({
            user: userRows[0],
            settings: settings
        });
    } catch (err) {
        console.error("Error fetching account info:", err);
        res.status(500).json({ success: false, message: "Failed to load account information." });
    }
});

app.put('/api/account/password', verifyRole(['admin', 'cashier', 'vendor']), async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const userId = req.session.user.id;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ success: false, message: "Both current and new passwords are required." });
        }

        const [userRows] = await db.execute(
            "SELECT password_hash FROM users WHERE id = ?",
            [userId]
        );

        if (userRows.length === 0) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        const user = userRows[0];
        const dbPasswordHash = user.password_hash;

        if (!dbPasswordHash) {
            return res.status(500).json({ success: false, message: "Password hash missing in database." });
        }

        const passwordMatch = await bcrypt.compare(currentPassword, dbPasswordHash);

        if (!passwordMatch) {
            return res.status(400).json({ success: false, message: "Incorrect current password." });
        }

        const hashedNewPassword = await bcrypt.hash(newPassword, 10);

        await db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            [hashedNewPassword, userId]
        );

        res.json({ success: true, message: "Password updated successfully." });
    } catch (err) {
        console.error("Error updating password:", err);
        res.status(500).json({ success: false, message: "Failed to update password." });
    }
});

app.put('/api/account/profile', verifyRole(['admin']), async (req, res) => {
    try {
        const { username } = req.body;
        const userId = req.session.user.id;

        if (!username || username.trim() === "") {
            return res.status(400).json({ success: false, message: "Username cannot be empty." });
        }

        const [existing] = await db.execute("SELECT id FROM users WHERE username = ? AND id != ?", [username, userId]);
        if (existing.length > 0) {
            return res.status(400).json({ success: false, message: "Username is already taken." });
        }

        await db.execute(
            "UPDATE users SET username = ? WHERE id = ?",
            [username, userId]
        );

        req.session.user.username = username;

        res.json({ success: true, message: "Username updated successfully." });
    } catch (err) {
        console.error("Error updating username:", err);
        res.status(500).json({ success: false, message: "Failed to update username." });
    }
});

// ================= API ENDPOINT: GET ALL LOAN RECORDS (Admin Only) =================
app.get('/api/loans', verifyRole(['admin']), async (req, res) => {
    const connection = await db.getConnection();
    try {
        const [loans] = await connection.execute(
            `SELECT id, total_amount, created_at, is_loan, customer_name, customer_phone, deposit_amount, loan_balance, loan_status 
             FROM orders 
             WHERE is_loan = 1 
             ORDER BY created_at DESC`
        );
        res.json({ success: true, loans });
    } catch (error) {
        console.error("--- FETCH LOANS ERROR ---", error);
        res.status(500).json({ success: false, message: error.message });
    } finally {
        connection.release();
    }
});

// ================= API ENDPOINT: MARK LOAN AS PAID (Admin Only) =================
app.post('/api/loans/:id/pay', verifyRole(['admin']), async (req, res) => {
    const orderId = req.params.id;
    const connection = await db.getConnection();

    try {
        const [result] = await connection.execute(
            `UPDATE orders 
             SET loan_status = 'paid', loan_balance = 0.00 
             WHERE id = ? AND is_loan = 1`,
            [orderId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: "Loan record not found." });
        }

        res.json({ success: true, message: "Loan successfully marked as paid and settled." });
    } catch (error) {
        console.error("--- MARK LOAN PAID ERROR ---", error);
        res.status(500).json({ success: false, message: error.message });
    } finally {
        connection.release();
    }
});

// ================= ROUTE: SERVE LOANS PAGE (Admin Only) =================
app.get('/loans', verifyRole(['admin']), (req, res) => {
    res.sendFile(path.join(__dirname, 'private', 'loans.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 Server running at http://localhost:${PORT}`);
});