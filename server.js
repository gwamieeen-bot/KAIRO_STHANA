
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const crypto = require("crypto");
const { rateLimit } = require("express-rate-limit");

const app = express();
app.set('trust proxy', 1);
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
// Penyimpanan foto privat
const uploadDirectory = path.join(__dirname, "uploads");

fs.mkdirSync(uploadDirectory, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDirectory);
  },

  filename: (req, file, cb) => {
    const extension = path.extname(file.originalname).toLowerCase();
    cb(null, crypto.randomUUID() + extension);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: 20 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      "image/jpeg",
      "image/png",
      "image/webp"
    ];

    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error("Format foto harus JPG, PNG, atau WEBP."));
    }

    cb(null, true);
  }
});

// Periksa konfigurasi rahasia
if (
  !process.env.SESSION_SECRET ||
  !process.env.MEMBER_PASSWORD ||
  !process.env.ADMIN_PASSWORD
) {
  throw new Error("Konfigurasi .env belum lengkap!");
}

if (process.env.SESSION_SECRET.length < 32) {
  throw new Error("SESSION_SECRET harus minimal 32 karakter.");
}

if (process.env.MEMBER_PASSWORD === process.env.ADMIN_PASSWORD) {
  throw new Error("Password admin dan anggota harus berbeda.");
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 24 * 60 * 60 * 1000
  }
});

app.use(sessionMiddleware);
io.engine.use(sessionMiddleware);

// Folder publik hanya berisi halaman login
app.use(express.static(path.join(__dirname, "public")));

// Database
const db = new sqlite3.Database(
  path.join(__dirname, "kairo_sthana.db"),
  (err) => {
    if (err) {
      console.error("Database gagal dibuka:", err.message);
      return;
    }

    console.log("Database KAIRO_STHANA berhasil terhubung.");
  }
);

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'member'
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

// Hash password dari .env
const memberHash = bcrypt.hashSync(process.env.MEMBER_PASSWORD, 12);
const adminHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);

// Pembatas percobaan login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    success: false,
    message: "Terlalu banyak percobaan. Coba lagi nanti."
  }
});

// Pemeriksaan login
function requireLogin(req, res, next) {
  if (!req.session.authenticated) {
    return res.redirect("/");
  }

  next();
}

// Pemeriksaan khusus admin
function requireAdmin(req, res, next) {
  if (!req.session.authenticated) {
    return res.status(401).json({
      success: false,
      message: "Silakan login terlebih dahulu."
    });
  }

  if (req.session.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Akses khusus admin."
    });
  }

  next();
}

// Upload foto khusus administrator
app.post(
  "/api/admin/upload",
  requireAdmin,
  upload.single("photo"),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: "Foto belum dipilih."
      });
    }

    const category = req.body.category;

    if (!["moment-random", "arsip-kejuaraan"].includes(category)) {
      fs.unlink(req.file.path, () => {});
      return res.status(400).json({
        success: false,
        message: "Kategori galeri tidak valid."
      });
    }

    const filename =
      category + "__" +
      crypto.randomUUID() +
      path.extname(req.file.originalname).toLowerCase();

    const destination = path.join(uploadDirectory, filename);

    fs.rename(req.file.path, destination, (err) => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: "Gagal menyimpan foto."
        });
      }

      res.json({
        success: true,
        message: "Foto berhasil diunggah.",
        filename,
        category
      });
    });
  }
);

// Daftar foto berdasarkan kategori
app.get("/api/photos", requireLogin, (req, res) => {
  const category = req.query.category;

  if (!["moment-random", "arsip-kejuaraan"].includes(category)) {
    return res.status(400).json({
      success: false,
      message: "Kategori galeri tidak valid."
    });
  }

  fs.readdir(uploadDirectory, (err, files) => {
    if (err) {
      return res.status(500).json({
        success: false,
        message: "Gagal membaca galeri."
      });
    }

    const photos = files
      .filter(file => /\.(jpg|jpeg|png|webp)$/i.test(file))
      .filter(file => {
        if (category === "arsip-kejuaraan") {
          return file.startsWith("arsip-kejuaraan__");
        }

        // Foto lama yang belum memiliki kategori masuk ke Moment Random.
        return !file.startsWith("arsip-kejuaraan__") && !file.startsWith("arsip-sesepuh__");
      })
      .map(filename => ({
        filename,
        url: "/media/" + encodeURIComponent(filename)
      }));

    res.json({ success: true, photos });
  });
});

// Menampilkan foto hanya untuk pengguna yang login
app.get("/media/:filename", requireLogin, (req, res) => {
  const filename = path.basename(req.params.filename);
  const filePath = path.join(uploadDirectory, filename);

  res.sendFile(filePath, (err) => {
    if (err && !res.headersSent) {
      res.status(404).send("Foto tidak ditemukan.");
    }
  });
});

// API Login
app.post("/api/login", loginLimiter, async (req, res) => {
  try {
    const password = req.body.password;

    if (typeof password !== "string" || !password) {
      return res.status(400).json({
        success: false,
        message: "Password wajib diisi."
      });
    }

    const isAdmin = await bcrypt.compare(password, adminHash);
    const isMember = isAdmin
      ? false
      : await bcrypt.compare(password, memberHash);

    if (!isAdmin && !isMember) {
      return res.status(401).json({
        success: false,
        message: "Password tidak sesuai."
      });
    }

    req.session.regenerate((err) => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: "Gagal membuat sesi login."
        });
      }

      req.session.authenticated = true;
      req.session.role = isAdmin ? "admin" : "member";
      req.session.username = isAdmin ? "Administrator" : "Anggota";

      req.session.save((saveErr) => {
        if (saveErr) {
          return res.status(500).json({
            success: false,
            message: "Gagal menyimpan sesi."
          });
        }

        res.json({
          success: true,
          role: req.session.role
        });
      });
    });
  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      success: false,
      message: "Terjadi kesalahan pada server."
    });
  }
});

// Dashboard hanya untuk pengguna yang sudah login
app.get("/dashboard", requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "views", "dashboard.html"));
});

// Informasi pengguna yang sedang login
app.get("/api/me", requireLogin, (req, res) => {
  res.json({
    success: true,
    username: req.session.username,
    role: req.session.role
  });
});

// Contoh jalur khusus admin
app.get("/api/admin/check", requireAdmin, (req, res) => {
  res.json({
    success: true,
    message: "Akses admin berhasil."
  });
});

// Logout
app.post("/api/logout", requireLogin, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({
        success: false,
        message: "Gagal logout."
      });
    }

    res.clearCookie("connect.sid");

    res.json({
      success: true,
      message: "Berhasil logout."
    });
  });
});

// Lindungi koneksi chat
io.use((socket, next) => {
  const userSession = socket.request.session;

  if (userSession && userSession.authenticated) {
    return next();
  }

  next(new Error("Silakan login terlebih dahulu."));
});

io.on("connection", (socket) => {
  console.log("Pengguna terhubung ke chat.");
});

// Status server
app.get("/api/status", (req, res) => {
  res.json({
    success: true,
    message: "Server KAIRO_STHANA aktif."
  });
});

// Jalankan server
server.listen(PORT, () => {
  console.log(`KAIRO_STHANA berjalan di http://localhost:${PORT}`);
});



  db.run(`
    CREATE TABLE IF NOT EXISTS elders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      biography TEXT NOT NULL,
      filename TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

// ================================
// API ARSIP SESEPUH
// ================================

app.get("/api/elders", requireLogin, (req, res) => {
  db.all(
    "SELECT id, name, biography, filename, created_at FROM elders ORDER BY id DESC",
    [],
    (err, rows) => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: "Arsip gagal dimuat."
        });
      }

      res.json({
        success: true,
        elders: rows.map(row => ({
          ...row,
          url: "/media/" + row.filename
        }))
      });
    }
  );
});

app.post("/api/admin/elders", requireAdmin, upload.single("photo"), (req, res) => {
  const name = (req.body.name || "").trim();
  const biography = (req.body.biography || "").trim();

  if (!name || !biography || !req.file) {
    if (req.file) fs.unlink(req.file.path, () => {});
    return res.status(400).json({
      success: false,
      message: "Nama, biografi, dan foto wajib diisi."
    });
  }

  const filename =
    "arsip-sesepuh__" +
    crypto.randomUUID() +
    path.extname(req.file.originalname).toLowerCase();

  const destination = path.join(uploadDirectory, filename);

  fs.rename(req.file.path, destination, err => {
    if (err) {
      fs.unlink(req.file.path, () => {});
      return res.status(500).json({
        success: false,
        message: "Foto gagal disimpan."
      });
    }

    db.run(
      "INSERT INTO elders (name, biography, filename) VALUES (?, ?, ?)",
      [name, biography, filename],
      function (dbErr) {
        if (dbErr) {
          fs.unlink(destination, () => {});
          return res.status(500).json({
            success: false,
            message: "Data sesepuh gagal disimpan."
          });
        }

        res.json({
          success: true,
          message: "Arsip sesepuh berhasil disimpan."
        });
      }
    );
  });
});


 // ================================
 // API CHAT BOARD KAIRO_STHANA
 // ================================

app.get("/api/chat/messages", requireLogin, (req, res) => {
  db.all(
    `SELECT id, username, message, created_at
     FROM messages
     ORDER BY id DESC
     LIMIT 100`,
    [],
    (err, rows) => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: "Pesan gagal dimuat."
        });
      }

      res.json({
        success: true,
        messages: rows.reverse()
      });
    }
  );
});

app.post("/api/chat/messages", requireLogin, (req, res) => {
  const message = (req.body.message || "").trim();
  const username =
    req.session.username ||
    req.session.user?.username ||
    req.session.member?.username;

  if (!username) {
    return res.status(401).json({
      success: false,
      message: "Sesi anggota tidak ditemukan. Silakan login ulang."
    });
  }

  if (!message || message.length > 1000) {
    return res.status(400).json({
      success: false,
      message: "Pesan wajib diisi dan maksimal 1000 karakter."
    });
  }

  db.run(
    "INSERT INTO messages (username, message) VALUES (?, ?)",
    [username, message],
    function (err) {
      if (err) {
        return res.status(500).json({
          success: false,
          message: "Pesan gagal dikirim."
        });
      }

      res.json({
        success: true,
        id: this.lastID
      });
    }
  );
});

