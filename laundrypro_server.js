import express from "express";
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const db = new Database(process.env.DB_FILE || "laundrypro.sqlite");

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS businesses (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  address TEXT NOT NULL DEFAULT '',
  phone TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  business_id INTEGER NOT NULL REFERENCES businesses(id),
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('owner','cashier')),
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS customers (
  id INTEGER PRIMARY KEY,
  business_id INTEGER NOT NULL REFERENCES businesses(id),
  name TEXT NOT NULL,
  phone TEXT NOT NULL DEFAULT '',
  points INTEGER NOT NULL DEFAULT 0,
  visits INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS services (
  id INTEGER PRIMARY KEY,
  business_id INTEGER NOT NULL REFERENCES businesses(id),
  name TEXT NOT NULL,
  unit TEXT NOT NULL,
  price INTEGER NOT NULL CHECK(price>=0),
  active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY,
  business_id INTEGER NOT NULL REFERENCES businesses(id),
  customer_id INTEGER NOT NULL REFERENCES customers(id),
  code TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK(status IN ('menunggu','cuci','kering','setrika','siap','selesai')),
  subtotal INTEGER NOT NULL,
  member_discount INTEGER NOT NULL DEFAULT 0,
  promo_discount INTEGER NOT NULL DEFAULT 0,
  point_discount INTEGER NOT NULL DEFAULT 0,
  total INTEGER NOT NULL,
  paid INTEGER NOT NULL DEFAULT 0,
  payment_method TEXT NOT NULL DEFAULT 'belum_bayar',
  voucher_id INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS order_items (
  id INTEGER PRIMARY KEY,
  order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  service_name TEXT NOT NULL,
  unit TEXT NOT NULL,
  price INTEGER NOT NULL,
  quantity REAL NOT NULL CHECK(quantity>0),
  subtotal INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS stock (
  id INTEGER PRIMARY KEY,
  business_id INTEGER NOT NULL REFERENCES businesses(id),
  name TEXT NOT NULL,
  unit TEXT NOT NULL,
  quantity REAL NOT NULL DEFAULT 0,
  minimum REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS stock_movements (
  id INTEGER PRIMARY KEY,
  business_id INTEGER NOT NULL REFERENCES businesses(id),
  stock_id INTEGER NOT NULL REFERENCES stock(id),
  delta REAL NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  user_id INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vouchers (
  id INTEGER PRIMARY KEY,
  business_id INTEGER NOT NULL REFERENCES businesses(id),
  code TEXT NOT NULL COLLATE NOCASE,
  type TEXT NOT NULL CHECK(type IN ('percent','fixed')),
  value INTEGER NOT NULL CHECK(value>0),
  minimum INTEGER NOT NULL DEFAULT 0,
  expires_on TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  max_uses INTEGER NOT NULL DEFAULT 0,
  uses INTEGER NOT NULL DEFAULT 0,
  UNIQUE(business_id, code)
);

CREATE TABLE IF NOT EXISTS activities (
  id INTEGER PRIMARY KEY,
  business_id INTEGER NOT NULL REFERENCES businesses(id),
  user_id INTEGER REFERENCES users(id),
  action TEXT NOT NULL,
  detail TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_orders_business_created
ON orders(business_id, created_at);

CREATE INDEX IF NOT EXISTS idx_customers_business
ON customers(business_id);

CREATE INDEX IF NOT EXISTS idx_activities_business
ON activities(business_id, created_at);
`);

const now = () => new Date().toISOString();
const day = () => now().slice(0, 10);

const err = (status, message) => {
  const e = new Error(message);
  e.status = status;
  throw e;
};

const integer = (v, label, min = 0, max = 1000000000) => {
  const n = Number(v);

  if (!Number.isSafeInteger(n) || n < min || n > max)
    err(400, `${label} tidak valid`);

  return n;
};

const quantity = (v) => {
  const n = Number(v);

  if (
    !Number.isFinite(n) ||
    n <= 0 ||
    n > 10000 ||
    Math.round(n * 1000) !== n * 1000
  )
    err(400, "Jumlah tidak valid (maksimal 3 desimal)");

  return n;
};

const text = (v, label, max = 120) => {
  if (typeof v !== "string" || !v.trim() || v.trim().length > max)
    err(400, `${label} wajib diisi (maks. ${max} karakter)`);

  return v.trim();
};

const phone = (v) => {
  const p = String(v || "").trim();

  if (p && !/^\+?[0-9]{9,15}$/.test(p))
    err(400, "Nomor telepon tidak valid");

  return p;
};

const log = (r, action, detail) =>
  db
    .prepare(
      "INSERT INTO activities(business_id,user_id,action,detail,created_at) VALUES(?,?,?,?,?)"
    )
    .run(
      r.user.business_id,
      r.user.id,
      action,
      detail,
      now()
    );

const owner = (req, res, next) =>
  req.user.role === "owner"
    ? next()
    : next(
        Object.assign(
          new Error("Hanya pemilik yang dapat mengakses fitur ini"),
          { status: 403 }
        )
      );

app.disable("x-powered-by");
app.set("trust proxy", process.env.TRUST_PROXY === "1" ? 1 : false);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));
app.use(cookieParser());

app.use(
  "/api/auth",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 30,
    standardHeaders: "draft-7",
    legacyHeaders: false,
  })
);

app.use("/api", (req, res, next) => {
  if (["/auth/register", "/auth/login"].includes(req.path))
    return next();

  const token = req.cookies.lp_session;

  if (!token)
    return res.status(401).json({ error: "Silakan masuk" });

  const hash = crypto.createHash("sha256")
    .update(token)
    .digest("hex");

  const user = db
    .prepare(
      `SELECT u.id,u.business_id,u.name,u.email,u.role
       FROM sessions s
       JOIN users u ON u.id=s.user_id
       WHERE s.token_hash=? AND s.expires_at>?`
    )
    .get(hash, now());

  if (!user)
    return res.status(401).json({
      error: "Sesi habis, silakan masuk kembali"
    });

  req.user = user;
  req.tokenHash = hash;

  next();
});

function session(res, userId) {
  const token = crypto.randomBytes(32).toString("hex");

  db.prepare(
    "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)"
  ).run(
    crypto.createHash("sha256").update(token).digest("hex"),
    userId,
    new Date(Date.now() + 7 * 86400000).toISOString()
  );

  res.cookie("lp_session", token, {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 86400000,
    path: "/",
  });
}

app.post("/api/auth/register", (req, res) => {
  const b = text(req.body.business, "Nama usaha");
  const name = text(req.body.name, "Nama pengguna");
  const email = text(req.body.email, "Email", 200).toLowerCase();

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    err(400, "Email tidak valid");

  if (
    typeof req.body.password !== "string" ||
    req.body.password.length < 10 ||
    req.body.password.length > 128
  )
    err(400, "Kata sandi minimal 10 karakter");

  const hash = bcrypt.hashSync(req.body.password, 12);

  const id = db.transaction(() => {
    const bid = db
      .prepare(
        "INSERT INTO businesses(name,created_at) VALUES(?,?)"
      )
      .run(b, now()).lastInsertRowid;

    const uid = db
      .prepare(
        `INSERT INTO users
         (business_id,name,email,password_hash,role,created_at)
         VALUES(?,?,?,?,?,?)`
      )
      .run(bid, name, email, hash, "owner", now())
      .lastInsertRowid;

    for (const [n, u, p] of [
      ["Cuci Kering", "kg", 7000],
      ["Cuci Setrika", "kg", 9000],
      ["Setrika Saja", "kg", 6000],
      ["Bed Cover", "pcs", 25000],
      ["Selimut", "pcs", 20000],
    ]) {
      db.prepare(
        "INSERT INTO services(business_id,name,unit,price) VALUES(?,?,?,?)"
      ).run(bid, n, u, p);
    }

    for (const [n, u, q, m] of [
      ["Deterjen Cair", "liter", 10, 3],
      ["Pewangi", "botol", 5, 2],
      ["Plastik", "lembar", 200, 50],
    ]) {
      db.prepare(
        `INSERT INTO stock
         (business_id,name,unit,quantity,minimum)
         VALUES(?,?,?,?,?)`
      ).run(bid, n, u, q, m);
    }

    return uid;
  })();

  session(res, id);
  res.status(201).json({ ok: true });
});

app.post("/api/auth/login", (req, res) => {
  const email = String(req.body.email || "").trim();

  const u = db
    .prepare("SELECT * FROM users WHERE email=?")
    .get(email);

  if (
    !u ||
    !bcrypt.compareSync(
      String(req.body.password || ""),
      u.password_hash
    )
  )
    err(401, "Email atau kata sandi salah");

  session(res, u.id);
  res.json({ ok: true });
});

app.post("/api/auth/logout", (req, res) => {
  db.prepare("DELETE FROM sessions WHERE token_hash=?")
    .run(req.tokenHash);

  res.clearCookie("lp_session", { path: "/" });
  res.json({ ok: true });
});

app.get("/api/me", (req, res) => {
  const business = db
    .prepare(
      "SELECT id,name,address,phone FROM businesses WHERE id=?"
    )
    .get(req.user.business_id);

  res.json({ user: req.user, business });
});

app.get("/api/dashboard", (req, res) => {
  const b = req.user.business_id;

  const stats = db
    .prepare(
      `SELECT COUNT(*) orders,
       COALESCE(SUM(CASE WHEN status NOT IN ('siap','selesai')
       THEN 1 ELSE 0 END),0) processing,
       COALESCE(SUM(CASE WHEN status='siap'
       THEN 1 ELSE 0 END),0) ready,
       COALESCE(SUM(paid),0) received,
       COALESCE(SUM(total-paid),0) outstanding
       FROM orders WHERE business_id=?`
    )
    .get(b);

  const revenue = db
    .prepare(
      `SELECT substr(created_at,1,10) date,
       SUM(paid) amount FROM orders
       WHERE business_id=? AND created_at>=?
       GROUP BY substr(created_at,1,10)
       ORDER BY date`
    )
    .all(
      b,
      new Date(Date.now() - 6 * 86400000)
        .toISOString().slice(0, 10)
    );

  const low = db
    .prepare(
      "SELECT * FROM stock WHERE business_id=? AND quantity<=minimum ORDER BY quantity"
    )
    .all(b);

  const recent = db
    .prepare(
      `SELECT o.*,c.name customer_name FROM orders o
       JOIN customers c ON c.id=o.customer_id
       WHERE o.business_id=? ORDER BY o.id DESC LIMIT 8`
    )
    .all(b);

  res.json({ stats, revenue, low, recent });
});
app.get("/api/services", (req, res) =>
  res.json(
    db
      .prepare("SELECT * FROM services WHERE business_id=? ORDER BY id")
      .all(req.user.business_id)
  )
);

app.post("/api/services", owner, (req, res) => {
  const n = text(req.body.name, "Nama layanan");
  const unit = text(req.body.unit, "Satuan", 20);
  const price = integer(req.body.price, "Harga");

  const id = db
    .prepare(
      "INSERT INTO services(business_id,name,unit,price) VALUES(?,?,?,?)"
    )
    .run(req.user.business_id, n, unit, price).lastInsertRowid;

  log(req, "Layanan baru", n);
  res.status(201).json({ id });
});

app.patch("/api/services/:id", owner, (req, res) => {
  const old = db
    .prepare("SELECT * FROM services WHERE id=? AND business_id=?")
    .get(req.params.id, req.user.business_id);

  if (!old) err(404, "Layanan tidak ditemukan");

  const name = text(req.body.name ?? old.name, "Nama layanan");
  const unit = text(req.body.unit ?? old.unit, "Satuan", 20);
  const price = integer(req.body.price ?? old.price, "Harga");

  const active =
    req.body.active === undefined ? old.active : req.body.active ? 1 : 0;

  db.prepare(
    "UPDATE services SET name=?,unit=?,price=?,active=? WHERE id=?"
  ).run(name, unit, price, active, old.id);

  log(req, "Ubah layanan", name);
  res.json({ ok: true });
});

app.get("/api/customers", (req, res) => {
  const q = String(req.query.q || "").slice(0, 100).trim();

  res.json(
    db
      .prepare(
        "SELECT * FROM customers WHERE business_id=? AND (name LIKE ? OR phone LIKE ?) ORDER BY name LIMIT 300"
      )
      .all(req.user.business_id, `%${q}%`, `%${q}%`)
  );
});

app.post("/api/customers", (req, res) => {
  const name = text(req.body.name, "Nama pelanggan");
  const p = phone(req.body.phone);

  const id = db
    .prepare(
      "INSERT INTO customers(business_id,name,phone,created_at) VALUES(?,?,?,?)"
    )
    .run(req.user.business_id, name, p, now()).lastInsertRowid;

  log(req, "Pelanggan baru", name);
  res.status(201).json({ id });
});
app.get("/api/vouchers", (req, res) =>
  res.json(
    db
      .prepare("SELECT * FROM vouchers WHERE business_id=? ORDER BY id DESC")
      .all(req.user.business_id)
  )
);

app.post("/api/vouchers", owner, (req, res) => {
  const code = text(req.body.code, "Kode", 32).toUpperCase();

  if (!/^[A-Z0-9_-]+$/.test(code))
    err(400, "Kode hanya boleh huruf, angka, _ dan -");

  const type = req.body.type;
  if (!["percent", "fixed"].includes(type))
    err(400, "Tipe tidak valid");

  const value = integer(req.body.value, "Nilai", 1);

  if (type === "percent" && value > 100)
    err(400, "Diskon persen maksimal 100");

  const minimum = integer(req.body.minimum || 0, "Minimum");
  const max = integer(req.body.max_uses || 0, "Maksimal pemakaian");
  const exp = text(req.body.expires_on, "Tanggal kedaluwarsa", 10);

  if (
    !/^\d{4}-\d{2}-\d{2}$/.test(exp) ||
    Number.isNaN(new Date(exp).getTime()) ||
    exp < day()
  )
    err(400, "Tanggal kedaluwarsa tidak valid");

  const id = db
    .prepare(
      "INSERT INTO vouchers(business_id,code,type,value,minimum,expires_on,max_uses) VALUES(?,?,?,?,?,?,?)"
    )
    .run(
      req.user.business_id,
      code,
      type,
      value,
      minimum,
      exp,
      max
    ).lastInsertRowid;

  log(req, "Voucher baru", code);
  res.status(201).json({ id });
});

app.patch("/api/vouchers/:id", owner, (req, res) => {
  const active = req.body.active ? 1 : 0;

  const result = db
    .prepare("UPDATE vouchers SET active=? WHERE id=? AND business_id=?")
    .run(active, req.params.id, req.user.business_id);

  if (!result.changes)
    err(404, "Voucher tidak ditemukan");

  log(req, "Ubah voucher", String(req.params.id));
  res.json({ ok: true });
});

app.get("/api/stock", (req, res) =>
  res.json(
    db
      .prepare("SELECT * FROM stock WHERE business_id=? ORDER BY name")
      .all(req.user.business_id)
  )
);

app.post("/api/stock", owner, (req, res) => {
  const n = text(req.body.name, "Nama stok");
  const u = text(req.body.unit, "Satuan", 20);
  const q = Number(req.body.quantity);
  const min = Number(req.body.minimum);

  if (!Number.isFinite(q) || q < 0 ||
      !Number.isFinite(min) || min < 0)
    err(400, "Jumlah stok tidak valid");

  const id = db
    .prepare(
      "INSERT INTO stock(business_id,name,unit,quantity,minimum) VALUES(?,?,?,?,?)"
    )
    .run(req.user.business_id, n, u, q, min).lastInsertRowid;

  log(req, "Stok baru", n);
  res.status(201).json({ id });
});

app.post("/api/stock/:id/move", (req, res) => {
  const delta = Number(req.body.delta);

  if (!Number.isFinite(delta) ||
      delta === 0 ||
      Math.abs(delta) > 100000)
    err(400, "Perubahan stok tidak valid");

  const note = text(req.body.note, "Keterangan", 150);

  db.transaction(() => {
    const s = db
      .prepare("SELECT * FROM stock WHERE id=? AND business_id=?")
      .get(req.params.id, req.user.business_id);

    if (!s) err(404, "Stok tidak ditemukan");
    if (s.quantity + delta < 0)
      err(400, "Stok tidak boleh negatif");

    db.prepare("UPDATE stock SET quantity=quantity+? WHERE id=?")
      .run(delta, s.id);

    db.prepare(
      "INSERT INTO stock_movements(business_id,stock_id,delta,note,user_id,created_at) VALUES(?,?,?,?,?,?)"
    ).run(
      req.user.business_id,
      s.id,
      delta,
      note,
      req.user.id,
      now()
    );

    log(req, "Mutasi stok", `${s.name}: ${delta} (${note})`);
  })();

  res.json({ ok: true });
});
app.get("/api/orders", (req, res) => {
  const b = req.user.business_id,
    q = String(req.query.q || "").slice(0, 100).trim(),
    status = String(req.query.status || "");

  if (
    status &&
    !["menunggu", "cuci", "kering", "setrika", "siap", "selesai"].includes(status)
  )
    err(400, "Filter status tidak valid");

  res.json(
    db
      .prepare(
        `SELECT o.*,c.name customer_name,c.phone customer_phone
         FROM orders o JOIN customers c ON c.id=o.customer_id
         WHERE o.business_id=? AND (?='' OR o.status=?)
         AND (o.code LIKE ? OR c.name LIKE ? OR c.phone LIKE ?)
         ORDER BY o.id DESC LIMIT 500`
      )
      .all(b, status, status, `%${q}%`, `%${q}%`, `%${q}%`)
  );
});

app.get("/api/orders/:id", (req, res) => {
  const o = db
    .prepare(
      `SELECT o.*,c.name customer_name,c.phone customer_phone
       FROM orders o JOIN customers c ON c.id=o.customer_id
       WHERE o.id=? AND o.business_id=?`
    )
    .get(req.params.id, req.user.business_id);

  if (!o) err(404, "Pesanan tidak ditemukan");

  res.json({
    ...o,
    items: db
      .prepare("SELECT * FROM order_items WHERE order_id=?")
      .all(o.id),
  });
});
app.post("/api/orders", (req, res) => {
  const result = db.transaction(() => {
    const bid = req.user.business_id;
    const cid = integer(req.body.customer_id, "Pelanggan", 1);

    const c = db
      .prepare("SELECT * FROM customers WHERE id=? AND business_id=?")
      .get(cid, bid);

    if (!c) err(400, "Pelanggan tidak ditemukan");

    if (
      !Array.isArray(req.body.items) ||
      !req.body.items.length ||
      req.body.items.length > 30
    )
      err(400, "Isi 1-30 layanan");

    const items = req.body.items.map((x) => {
      const s = db
        .prepare(
          "SELECT * FROM services WHERE id=? AND business_id=? AND active=1"
        )
        .get(integer(x.service_id, "Layanan", 1), bid);

      if (!s) err(400, "Layanan tidak tersedia");

      const qty = quantity(x.quantity);
      const subtotal = Math.round(s.price * qty);

      return {
        name: s.name,
        unit: s.unit,
        price: s.price,
        qty,
        subtotal,
      };
    });

    const subtotal = items.reduce((a, x) => a + x.subtotal, 0);

    if (subtotal > 1000000000)
      err(400, "Total terlalu besar");

    const discountPct =
      c.visits >= 30 ? 5 : c.visits >= 10 ? 3 : 0;

    const member = Math.floor((subtotal * discountPct) / 100);

    let voucher = null;
    let promo = 0;

    const vc = String(req.body.voucher || "")
      .trim()
      .toUpperCase();

    if (vc) {
      voucher = db
        .prepare(
          "SELECT * FROM vouchers WHERE business_id=? AND code=?"
        )
        .get(bid, vc);

      if (
        !voucher ||
        !voucher.active ||
        voucher.expires_on < day() ||
        (voucher.max_uses && voucher.uses >= voucher.max_uses) ||
        subtotal < voucher.minimum
      )
        err(400, "Voucher tidak berlaku untuk transaksi ini");

      promo = Math.min(
        subtotal - member,
        voucher.type === "percent"
          ? Math.floor((subtotal * voucher.value) / 100)
          : voucher.value
      );
    }

    const redeem = req.body.redeem_points === true;

    if (redeem && c.points < 100)
      err(400, "Poin pelanggan kurang dari 100");

    const point = redeem
      ? Math.min(5000, subtotal - member - promo)
      : 0;

    const total = Math.max(
      0,
      subtotal - member - promo - point
    );

    const paid = integer(
      req.body.paid ?? 0,
      "Pembayaran",
      0,
      total
    );

    const method = paid
      ? text(req.body.payment_method, "Metode pembayaran", 30)
      : "belum_bayar";

    if (
      paid &&
      !["tunai", "transfer", "qris", "lainnya"].includes(method)
    )
      err(400, "Metode pembayaran tidak valid");

    const stamp = now();
    const placeholder = `TMP-${crypto.randomUUID()}`;

    const id = db
      .prepare(
        `INSERT INTO orders(
          business_id,customer_id,code,status,subtotal,
          member_discount,promo_discount,point_discount,
          total,paid,payment_method,voucher_id,created_at,updated_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
      )
      .run(
        bid,
        cid,
        placeholder,
        "menunggu",
        subtotal,
        member,
        promo,
        point,
        total,
        paid,
        method,
        voucher?.id || null,
        stamp,
        stamp
      ).lastInsertRowid;

    const code =
      `LP-${stamp.slice(0, 10).replaceAll("-", "")}-${String(id).padStart(6, "0")}`;

    db.prepare("UPDATE orders SET code=? WHERE id=?")
      .run(code, id);

    for (const x of items) {
      db.prepare(
        `INSERT INTO order_items(
          order_id,service_name,unit,price,quantity,subtotal
        ) VALUES(?,?,?,?,?,?)`
      ).run(
        id,
        x.name,
        x.unit,
        x.price,
        x.qty,
        x.subtotal
      );
    }

    db.prepare(
      "UPDATE customers SET visits=visits+1,points=points+? WHERE id=?"
    ).run(
      Math.floor(total / 1000) - (redeem ? 100 : 0),
      cid
    );

    if (voucher) {
      db.prepare("UPDATE vouchers SET uses=uses+1 WHERE id=?")
        .run(voucher.id);
    }

    log(req, "Pesanan baru", code);

    return { id, code, total };
  })();

  res.status(201).json(result);
});
app.patch("/api/orders/:id/status", (req, res) => {
  const allowed = [
    "menunggu",
    "cuci",
    "kering",
    "setrika",
    "siap",
    "selesai",
  ];

  const status = req.body.status;

  if (!allowed.includes(status))
    err(400, "Status tidak valid");

  db.transaction(() => {
    const o = db
      .prepare(
        "SELECT * FROM orders WHERE id=? AND business_id=?"
      )
      .get(req.params.id, req.user.business_id);

    if (!o) err(404, "Pesanan tidak ditemukan");

    if (
      allowed.indexOf(status) !==
      allowed.indexOf(o.status) + 1
    )
      err(400, "Status harus maju satu tahap");

    db.prepare(
      "UPDATE orders SET status=?,updated_at=? WHERE id=?"
    ).run(status, now(), o.id);

    log(req, "Status pesanan", `${o.code} → ${status}`);
  })();

  res.json({ ok: true });
});
app.post("/api/orders/:id/payment", (req, res) => {
  db.transaction(() => {
    const o = db
      .prepare(
        "SELECT * FROM orders WHERE id=? AND business_id=?"
      )
      .get(req.params.id, req.user.business_id);

    if (!o) err(404, "Pesanan tidak ditemukan");

    const amount = integer(
      req.body.amount,
      "Jumlah bayar",
      1,
      o.total - o.paid
    );

    const method = text(req.body.method, "Metode", 30);

    if (!["tunai", "transfer", "qris", "lainnya"].includes(method))
      err(400, "Metode tidak valid");

    db.prepare(
      `UPDATE orders
       SET paid=paid+?,payment_method=?,updated_at=?
       WHERE id=?`
    ).run(amount, method, now(), o.id);

    log(req, "Pembayaran", `${o.code}: ${amount}`);
  })();

  res.json({ ok: true });
});
app.get("/api/activities", owner, (req, res) =>
  res.json(
    db
      .prepare(
        `SELECT a.*,u.name user_name
         FROM activities a LEFT JOIN users u ON a.user_id=u.id
         WHERE a.business_id=? ORDER BY a.id DESC LIMIT 200`
      )
      .all(req.user.business_id)
  )
);

app.get("/api/report", owner, (req, res) => {
  const from = String(req.query.from || day());
  const to = String(req.query.to || day());

  if (
    !/^\d{4}-\d{2}-\d{2}$/.test(from) ||
    !/^\d{4}-\d{2}-\d{2}$/.test(to) ||
    from > to
  )
    err(400, "Rentang tanggal tidak valid");

  const rows = db
    .prepare(
      `SELECT o.code,o.created_at,c.name customer,o.status,
       o.subtotal,o.member_discount,o.promo_discount,
       o.point_discount,o.total,o.paid,
       (o.total-o.paid) outstanding,o.payment_method
       FROM orders o JOIN customers c ON c.id=o.customer_id
       WHERE o.business_id=?
       AND substr(o.created_at,1,10) BETWEEN ? AND ?
       ORDER BY o.id DESC LIMIT 10000`
    )
    .all(req.user.business_id, from, to);

  res.json({
    rows,
    summary: {
      orders: rows.length,
      sales: rows.reduce((s, x) => s + x.total, 0),
      received: rows.reduce((s, x) => s + x.paid, 0),
      outstanding: rows.reduce((s, x) => s + x.outstanding, 0),
    },
  });
});
app.get("/api/backup", owner, (req, res) => {
  const b = req.user.business_id;
  const tables = {};

  for (const table of [
    "businesses",
    "users",
    "customers",
    "services",
    "orders",
    "order_items",
    "stock",
    "stock_movements",
    "vouchers",
    "activities",
  ]) {
    if (table === "users") {
      tables.users = db
        .prepare(
          `SELECT id,business_id,name,email,role,created_at
           FROM users WHERE business_id=?`
        )
        .all(b);
    } else if (table === "order_items") {
      tables.order_items = db
        .prepare(
          `SELECT i.* FROM order_items i
           JOIN orders o ON o.id=i.order_id
           WHERE o.business_id=?`
        )
        .all(b);
    } else {
      tables[table] = db
        .prepare(
          `SELECT * FROM ${table}
           WHERE ${table === "businesses" ? "id" : "business_id"}=?`
        )
        .all(b);
    }
  }

  res.set(
    "Content-Disposition",
    `attachment; filename="laundrypro-backup-${day()}.json"`
  );

  res.json({
    exported_at: now(),
    note: "Arsip baca-saja; tidak berisi sandi. Restore harus dilakukan oleh administrator melalui prosedur terverifikasi.",
    tables,
  });
});
app.get("/api/settings", owner, (req, res) =>
  res.json(
    db
      .prepare(
        "SELECT id,name,address,phone FROM businesses WHERE id=?"
      )
      .get(req.user.business_id)
  )
);

app.patch("/api/settings", owner, (req, res) => {
  const name = text(req.body.name, "Nama usaha");
  const address = String(req.body.address || "")
    .trim()
    .slice(0, 250);
  const p = phone(req.body.phone);

  db.prepare(
    "UPDATE businesses SET name=?,address=?,phone=? WHERE id=?"
  ).run(name, address, p, req.user.business_id);

  log(req, "Pengaturan", "Profil usaha diubah");
  res.json({ ok: true });
});
app.get("/api/users", owner, (req, res) =>
  res.json(
    db
      .prepare(
        "SELECT id,name,email,role FROM users WHERE business_id=? ORDER BY id"
      )
      .all(req.user.business_id)
  )
);

app.post("/api/users", owner, (req, res) => {
  const name = text(req.body.name, "Nama");
  const email = text(req.body.email, "Email", 200).toLowerCase();

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    err(400, "Email tidak valid");

  if (
    typeof req.body.password !== "string" ||
    req.body.password.length < 10
  )
    err(400, "Kata sandi minimal 10 karakter");

  const id = db
    .prepare(
      `INSERT INTO users(
        business_id,name,email,password_hash,role,created_at
      ) VALUES(?,?,?,?,?,?)`
    )
    .run(
      req.user.business_id,
      name,
      email,
      bcrypt.hashSync(req.body.password, 12),
      "cashier",
      now()
    ).lastInsertRowid;

  log(req, "Kasir baru", email);
  res.status(201).json({ id });
});
app.use(express.static(__dirname, {
  index: "laundrypro.html"
}));

app.get("*", (req, res) =>
  res.sendFile(path.join(__dirname, "laundrypro.html"))
);

app.use((error, req, res, next) => {
  if (error.code?.startsWith("SQLITE_CONSTRAINT"))
    return res.status(409).json({
      error: "Data sudah ada atau tidak valid"
    });

  if (error instanceof SyntaxError && "body" in error)
    return res.status(400).json({
      error: "JSON tidak valid"
    });

  console.error(error);

  res
    .status(error.status || 500)
    .json({
      error: error.status
        ? error.message
        : "Kesalahan server"
    });
});

const port = Number(process.env.PORT || 3000);

app.listen(port, () =>
  console.log(`LaundryPro: http://localhost:${port}`)
);