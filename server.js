
const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;

if (!process.env.JWT_SECRET || process.env.JWT_SECRET === "replace_this_with_a_long_random_secret") {
    console.error("Please set a secure JWT_SECRET in your .env file.");
    process.exit(1);
}

const pool = mysql.createPool({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME || "library_management",
    waitForConnections: true,
    connectionLimit: 10
});

function authenticate(req, res, next) {
    const header = req.headers.authorization;

    if (!header || !header.startsWith("Bearer ")) {
        return res.status(401).json({ message: "Please log in first." });
    }

    try {
        req.user = jwt.verify(header.substring(7), process.env.JWT_SECRET);
        next();
    } catch {
        return res.status(401).json({ message: "Your login has expired. Please log in again." });
    }
}

function adminOnly(req, res, next) {
    if (req.user.role !== "admin") {
        return res.status(403).json({ message: "Only an administrator can do this." });
    }
    next();
}

async function createInitialAdmin() {
    const username = process.env.ADMIN_USERNAME || "admin";
    const password = process.env.ADMIN_PASSWORD;

    if (!password) {
        throw new Error("Set ADMIN_PASSWORD in your .env file.");
    }

    const [existing] = await pool.execute(
        "SELECT id FROM users WHERE username = ?",
        [username]
    );

    if (existing.length === 0) {
        const hashedPassword = await bcrypt.hash(password, 10);

        await pool.execute(
            "INSERT INTO users (name, membership_id, username, password, role) VALUES (?, ?, ?, ?, 'admin')",
            [
                process.env.ADMIN_NAME || "Library Administrator",
                process.env.ADMIN_MEMBERSHIP_ID || "ADMIN001",
                username,
                hashedPassword
            ]
        );

        console.log("Initial administrator account created.");
    }
}

app.get("/", (req, res) => {
    res.json({ message: "Community Library backend is running." });
});

app.post("/users/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: "Enter your username and password." });
        }

        const [rows] = await pool.execute(
            "SELECT id, name, membership_id, username, password, role FROM users WHERE username = ?",
            [username]
        );

        if (rows.length === 0 || !(await bcrypt.compare(password, rows[0].password))) {
            return res.status(401).json({ message: "Incorrect username or password." });
        }

        const user = rows[0];
        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "8h" }
        );

        res.json({
            message: "Login successful.",
            token,
            user: {
                id: user.id,
                name: user.name,
                membership_id: user.membership_id,
                username: user.username,
                role: user.role
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Login failed." });
    }
});

app.get("/books", async (req, res) => {
    try {
        const [books] = await pool.execute("SELECT * FROM books ORDER BY title");
        res.json(books);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Could not retrieve books." });
    }
});

app.post("/books", authenticate, adminOnly, async (req, res) => {
    try {
        const { title, author, genre, isbn, quantity } = req.body;

        if (!title || !author || quantity === undefined || Number(quantity) < 0 || !Number.isInteger(Number(quantity))) {
            return res.status(400).json({ message: "Enter a title, author, and valid quantity." });
        }

        const [result] = await pool.execute(
            "INSERT INTO books (title, author, genre, isbn, quantity) VALUES (?, ?, ?, ?, ?)",
            [title, author, genre || null, isbn || null, Number(quantity)]
        );

        res.status(201).json({ message: "Book added.", id: result.insertId });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Could not add book. Check whether the ISBN already exists." });
    }
});

app.put("/books/:id", authenticate, adminOnly, async (req, res) => {
    try {
        const { title, author, genre, isbn, quantity } = req.body;

        if (!title || !author || quantity === undefined || Number(quantity) < 0 || !Number.isInteger(Number(quantity))) {
            return res.status(400).json({ message: "Enter a title, author, and valid quantity." });
        }

        const [result] = await pool.execute(
            "UPDATE books SET title = ?, author = ?, genre = ?, isbn = ?, quantity = ? WHERE id = ?",
            [title, author, genre || null, isbn || null, Number(quantity), req.params.id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "Book not found." });
        }

        res.json({ message: "Book updated." });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Could not update book." });
    }
});

app.delete("/books/:id", authenticate, adminOnly, async (req, res) => {
    try {
        const [result] = await pool.execute(
            "DELETE FROM books WHERE id = ?",
            [req.params.id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "Book not found." });
        }

        res.json({ message: "Book deleted." });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Could not delete book. It may have transaction history." });
    }
});

app.get("/users", authenticate, adminOnly, async (req, res) => {
    try {
        const [users] = await pool.execute(
            "SELECT id, name, membership_id, username, role FROM users ORDER BY name"
        );
        res.json(users);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Could not retrieve users." });
    }
});

app.post("/users", authenticate, adminOnly, async (req, res) => {
    try {
        const { name, membership_id, username, password, role } = req.body;

        if (!name || !membership_id || !username || !password) {
            return res.status(400).json({ message: "Complete all required user fields." });
        }

        if (!["admin", "member"].includes(role || "member")) {
            return res.status(400).json({ message: "Invalid user role." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const [result] = await pool.execute(
            "INSERT INTO users (name, membership_id, username, password, role) VALUES (?, ?, ?, ?, ?)",
            [name, membership_id, username, hashedPassword, role || "member"]
        );

        res.status(201).json({ message: "User added.", id: result.insertId });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Could not add user. Check that the username and membership ID are unique." });
    }
});

app.put("/users/:id", authenticate, adminOnly, async (req, res) => {
    try {
        const { name, membership_id, username, password, role } = req.body;
        const id = Number(req.params.id);

        if (!name || !membership_id || !username || !["admin", "member"].includes(role)) {
            return res.status(400).json({ message: "Enter valid user details." });
        }

        if (id === req.user.id && role !== "admin") {
            return res.status(400).json({ message: "You cannot remove your own administrator role." });
        }

        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            await pool.execute(
                "UPDATE users SET name = ?, membership_id = ?, username = ?, password = ?, role = ? WHERE id = ?",
                [name, membership_id, username, hashedPassword, role, id]
            );
        } else {
            await pool.execute(
                "UPDATE users SET name = ?, membership_id = ?, username = ?, role = ? WHERE id = ?",
                [name, membership_id, username, role, id]
            );
        }

        res.json({ message: "User updated." });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Could not update user." });
    }
});

app.delete("/users/:id", authenticate, adminOnly, async (req, res) => {
    try {
        if (Number(req.params.id) === req.user.id) {
            return res.status(400).json({ message: "You cannot delete your own account while logged in." });
        }

        const [result] = await pool.execute(
            "DELETE FROM users WHERE id = ?",
            [req.params.id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "User not found." });
        }

        res.json({ message: "User deleted." });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Could not delete user." });
    }
});

app.get("/transactions", authenticate, async (req, res) => {
    try {
        const [transactions] = await pool.execute(`
            SELECT t.id, t.transaction_type, t.quantity, t.transaction_date,
                   u.name AS member_name, b.title AS book_title
            FROM transactions t
            LEFT JOIN users u ON t.user_id = u.id
            JOIN books b ON t.book_id = b.id
            ORDER BY t.transaction_date DESC
        `);

        res.json(transactions);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Could not retrieve transactions." });
    }
});

app.post("/transactions", authenticate, async (req, res) => {
    const connection = await pool.getConnection();

    try {
        const { book_id, transaction_type, quantity } = req.body;
        const amount = Number(quantity);

        if (!book_id || !Number.isInteger(amount) || amount < 1) {
            return res.status(400).json({ message: "Choose a book and enter a valid quantity." });
        }

        if (!["borrow", "return", "stock_added"].includes(transaction_type)) {
            return res.status(400).json({ message: "Invalid transaction type." });
        }

        if (transaction_type === "stock_added" && req.user.role !== "admin") {
            return res.status(403).json({ message: "Only an administrator can add stock." });
        }

        await connection.beginTransaction();

        const [books] = await connection.execute(
            "SELECT id, quantity FROM books WHERE id = ? FOR UPDATE",
            [book_id]
        );

        if (books.length === 0) {
            await connection.rollback();
            return res.status(404).json({ message: "Book not found." });
        }

        const current = Number(books[0].quantity);
        let updated = current;

        if (transaction_type === "borrow") {
            if (current < amount) {
                await connection.rollback();
                return res.status(400).json({ message: "Not enough copies available." });
            }
            updated -= amount;
        } else {
            updated += amount;
        }

        await connection.execute(
            "UPDATE books SET quantity = ? WHERE id = ?",
            [updated, book_id]
        );

        await connection.execute(
            "INSERT INTO transactions (user_id, book_id, transaction_type, quantity) VALUES (?, ?, ?, ?)",
            [req.user.id, book_id, transaction_type, amount]
        );

        await connection.commit();
        res.status(201).json({ message: "Transaction recorded.", quantity: updated });
    } catch (error) {
        await connection.rollback();
        console.error(error);
        res.status(500).json({ message: "Could not record transaction." });
    } finally {
        connection.release();
    }
});

async function startServer() {
    try {
        const connection = await pool.getConnection();
        console.log("Connected to the MySQL database.");
        connection.release();

        await createInitialAdmin();

        app.listen(PORT, () => {
            console.log(`Community Library backend running at http://localhost:${PORT}`);
        });
    } catch (error) {
        console.error("Could not start the server:", error.message);
        process.exit(1);
    }
}

startServer();
