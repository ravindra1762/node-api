require('dotenv').config();
const express = require('express');
const db = require('./db');
const upload = require('./middleware/upload');
const auth = require('./middleware/auth');
const app = express();
const bcrypt = require('bcrypt');
// JSON parser (still needed for non-file routes)
app.use(express.json());

// Serve uploaded files
app.use('/uploads', express.static('uploads'));

const jwt = require('jsonwebtoken');


const JWT_SECRET = "mysecretkey123";

app.post('/api/register', upload.single('image'), async (req, res) => {
  try {
    const { name, email, mobile, password } = req.body;
    const image = req.file ? req.file.filename : null;
    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, email, and password are required"
      });
    }
    const [existingUser] = await db.query(
      'SELECT id FROM tbl_users WHERE email = ?',
      [email]
    );

    if (existingUser.length > 0) {
      return res.status(409).json({
        success: false,
        message: "User already exists with this email"
      });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await db.query(
      `INSERT INTO tbl_users (name, email, image, mobile, password, update_date)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [name, email, image, mobile, hashedPassword, new Date()]
    );

    return res.status(201).json({
      success: true,
      message: "User registered successfully",
      data: {
        id: result.insertId,
        name,
        email,
        image: `/uploads/${image}`
      }
    });

  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Server error",
      error: err.message
    });
  }
});


app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" });
    }
    const [rows] = await db.query(
      'SELECT * FROM tbl_users WHERE email = ?',
      [email]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: "Invalid email or password" });
    }
    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ error: "Invalid email or password" });
    }
    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: "1h" }
    );
     res.json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


app.post('/api/send-otp', async (req, res) => {
  try {
    const { identifier } = req.body;

    if (!identifier) {
      return res.status(400).json({
        message: "Mobile or Email required"
      });
    }

    let query;
    let value;

    // 📱 detect mobile (basic check: numbers only)
    const isMobile = /^[0-9]{10}$/.test(identifier);

    if (isMobile) {
      query = 'SELECT * FROM tbl_users WHERE mobile = ?';
      value = identifier;
    } else {
      query = 'SELECT * FROM tbl_users WHERE email = ?';
      value = identifier;
    }

    const [user] = await db.query(query, [value]);

    if (user.length === 0) {
      return res.status(404).json({
        message: "User not found"
      });
    }

    const otp = Math.floor(100000 + Math.random() * 900000);
    const expiry = new Date(Date.now() + 5 * 60 * 1000);

    // 💾 update OTP
    if (isMobile) {
      await db.query(
        'UPDATE tbl_users SET otp = ?, otp_expiry = ? WHERE mobile = ?',
        [otp, expiry, value]
      );
    } else {
      await db.query(
        'UPDATE tbl_users SET otp = ?, otp_expiry = ? WHERE email = ?',
        [otp, expiry, value]
      );
    }

    res.status(200).json({
      message: "OTP sent successfully",
      otp, // remove in production
      sentTo: identifier
    });

  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


app.post('/api/verify-otp', async (req, res) => {
  try {
    const { identifier, otp } = req.body;

    if (!identifier || !otp) {
      return res.status(400).json({
        message: "Identifier and OTP required"
      });
    }
    const isMobile = /^[0-9]{10}$/.test(identifier);

    const query = isMobile
      ? 'SELECT * FROM tbl_users WHERE mobile = ?'
      : 'SELECT * FROM tbl_users WHERE email = ?';

    const [rows] = await db.query(query, [identifier]);

    if (rows.length === 0) {
      return res.status(404).json({
        message: "User not found"
      });
    }

    const user = rows[0];
    if (user.otp !== otp) {
      return res.status(401).json({
        message: "Invalid OTP"
      });
    }
    if (new Date() > new Date(user.otp_expiry)) {
      return res.status(401).json({
        message: "OTP expired"
      });
    }
    const token = jwt.sign(
      { id: user.id, email: user.email, mobile: user.mobile },
      JWT_SECRET,
      { expiresIn: "1h" }
    );
    await db.query(
      'UPDATE tbl_users SET otp = NULL, otp_expiry = NULL WHERE id = ?',
      [user.id]
    );

    res.status(200).json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        mobile: user.mobile
      }
    });

  } catch (err) {
    res.status(500).json({
      message: err.message
    });
  }
});

app.get('/api/profile', auth, async (req, res) => {
  const [user] = await db.query(
    'SELECT id, name, email FROM tbl_users WHERE id = ?',
    [req.user.id]
  );

  res.json(user[0]);
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});