require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret-in-production";

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(express.json({ limit: "2mb" }));

let pool = null;

if (process.env.DATABASE_URL) {
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false
  });

  pool.on("error", (err) => {
    console.error("PostgreSQL pool error:", err.message);
  });
}

async function db(query, params = []) {
  if (!pool) {
    throw new Error("DATABASE_URL is not configured");
  }

  return pool.query(query, params);
}

function createToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      companyId: user.company_id,
      role: user.role
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        ok: false,
        message: "Authentication required"
      });
    }

    const token = header.substring(7);

    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();
  } catch (error) {
    return res.status(401).json({
      ok: false,
      message: "Invalid or expired token"
    });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({
        ok: false,
        message: "Permission denied"
      });
    }

    next();
  };
}

function cleanUser(row) {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    role: row.role,
    status: row.status,
    company_id: row.company_id,
    created_at: row.created_at
  };
}

/* =========================
   HEALTH
========================= */

app.get("/", (req, res) => {
  res.json({
    ok: true,
    app: "AUNG SMART BUSINESS ERP",
    version: "4.0.0",
    mode: "Cloud SaaS",
    database: pool ? "configured" : "not-configured"
  });
});

app.get("/api/health", async (req, res) => {
  try {
    if (!pool) {
      return res.json({
        ok: true,
        server: "online",
        database: "not-configured"
      });
    }

    await db("SELECT 1");

    res.json({
      ok: true,
      server: "online",
      database: "connected"
    });
  } catch (error) {
    res.status(500).json({
      ok: false,
      server: "online",
      database: "error",
      message: error.message
    });
  }
});

/* =========================
   REGISTER
========================= */

app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      companyName,
      ownerName,
      email,
      password
    } = req.body;

    if (!companyName || !ownerName || !email || !password) {
      return res.status(400).json({
        ok: false,
        message: "Company name, owner name, email and password are required"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        ok: false,
        message: "Password must be at least 6 characters"
      });
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    const existing = await db(
      "SELECT id FROM users WHERE email = $1",
      [normalizedEmail]
    );

    if (existing.rows.length) {
      return res.status(409).json({
        ok: false,
        message: "Email already exists"
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const companyResult = await db(
      `
      INSERT INTO companies
      (name, owner_name, currency, monthly_target)
      VALUES ($1, $2, 'MMK', 100000000)
      RETURNING *
      `,
      [companyName.trim(), ownerName.trim()]
    );

    const company = companyResult.rows[0];

    const userResult = await db(
      `
      INSERT INTO users
      (company_id, name, email, password_hash, role, status)
      VALUES ($1, $2, $3, $4, 'Owner', 'Active')
      RETURNING id, company_id, name, email, role, status, created_at
      `,
      [
        company.id,
        ownerName.trim(),
        normalizedEmail,
        passwordHash
      ]
    );

    const user = userResult.rows[0];

    const token = createToken(user);

    res.status(201).json({
      ok: true,
      token,
      user: cleanUser(user),
      company: {
        id: company.id,
        name: company.name,
        owner_name: company.owner_name,
        currency: company.currency,
        monthly_target: company.monthly_target
      }
    });

  } catch (error) {
    console.error("REGISTER ERROR:", error);

    res.status(500).json({
      ok: false,
      message: "Registration failed"
    });
  }
});

/* =========================
   LOGIN
========================= */

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        ok: false,
        message: "Email and password are required"
      });
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    const result = await db(
      `
      SELECT
        id,
        company_id,
        name,
        email,
        password_hash,
        role,
        status,
        created_at
      FROM users
      WHERE email = $1
      LIMIT 1
      `,
      [normalizedEmail]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        ok: false,
        message: "Invalid email or password"
      });
    }

    const user = result.rows[0];

    if (user.status !== "Active") {
      return res.status(403).json({
        ok: false,
        message: "This user account is inactive"
      });
    }

    const validPassword = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!validPassword) {
      return res.status(401).json({
        ok: false,
        message: "Invalid email or password"
      });
    }

    const companyResult = await db(
      `
      SELECT
        id,
        name,
        owner_name,
        currency,
        monthly_target
      FROM companies
      WHERE id = $1
      `,
      [user.company_id]
    );

    const company = companyResult.rows[0];

    const token = createToken(user);

    res.json({
      ok: true,
      token,
      user: cleanUser(user),
      company
    });

  } catch (error) {
    console.error("LOGIN ERROR:", error);

    res.status(500).json({
      ok: false,
      message: "Login failed"
    });
  }
});

/* =========================
   CURRENT USER
========================= */

app.get("/api/auth/me", auth, async (req, res) => {
  try {
    const result = await db(
      `
      SELECT
        id,
        company_id,
        name,
        email,
        role,
        status,
        created_at
      FROM users
      WHERE id = $1
      AND company_id = $2
      `,
      [req.user.userId, req.user.companyId]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        ok: false,
        message: "User not found"
      });
    }

    res.json({
      ok: true,
      user: cleanUser(result.rows[0])
    });

  } catch (error) {
    res.status(500).json({
      ok: false,
      message: "Unable to load user"
    });
  }
});

/* =========================
   COMPANY
========================= */

app.get("/api/company", auth, async (req, res) => {
  try {
    const result = await db(
      `
      SELECT
        id,
        name,
        owner_name,
        currency,
        monthly_target,
        created_at
      FROM companies
      WHERE id = $1
      `,
      [req.user.companyId]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        ok: false,
        message: "Company not found"
      });
    }

    res.json({
      ok: true,
      company: result.rows[0]
    });

  } catch (error) {
    res.status(500).json({
      ok: false,
      message: "Unable to load company"
    });
  }
});

app.put(
  "/api/company",
  auth,
  requireRole("Owner", "Admin"),
  async (req, res) => {
    try {
      const {
        name,
        owner_name,
        currency,
        monthly_target
      } = req.body;

      const result = await db(
        `
        UPDATE companies
        SET
          name = COALESCE($1, name),
          owner_name = COALESCE($2, owner_name),
          currency = COALESCE($3, currency),
          monthly_target = COALESCE($4, monthly_target),
          updated_at = NOW()
        WHERE id = $5
        RETURNING
          id,
          name,
          owner_name,
          currency,
          monthly_target,
          created_at,
          updated_at
        `,
        [
          name || null,
          owner_name || null,
          currency || null,
          monthly_target ?? null,
          req.user.companyId
        ]
      );

      res.json({
        ok: true,
        company: result.rows[0]
      });

    } catch (error) {
      res.status(500).json({
        ok: false,
        message: "Unable to update company"
      });
    }
  }
);

/* =========================
   USERS
========================= */

app.get(
  "/api/users",
  auth,
  requireRole("Owner", "Admin"),
  async (req, res) => {
    try {
      const result = await db(
        `
        SELECT
          id,
          company_id,
          name,
          email,
          role,
          status,
          created_at
        FROM users
        WHERE company_id = $1
        ORDER BY created_at DESC
        `,
        [req.user.companyId]
      );

      res.json({
        ok: true,
        users: result.rows.map(cleanUser)
      });

    } catch (error) {
      res.status(500).json({
        ok: false,
        message: "Unable to load users"
      });
    }
  }
);

app.post(
  "/api/users",
  auth,
  requireRole("Owner", "Admin"),
  async (req, res) => {
    try {
      const {
        name,
        email,
        password,
        role
      } = req.body;

      const allowedRoles = [
        "Admin",
        "Sales Manager",
        "Salesperson",
        "Accountant",
        "Warehouse",
        "HR"
      ];

      if (!name || !email || !password || !role) {
        return res.status(400).json({
          ok: false,
          message: "Name, email, password and role are required"
        });
      }

      if (!allowedRoles.includes(role)) {
        return res.status(400).json({
          ok: false,
          message: "Invalid role"
        });
      }

      const normalizedEmail = String(email).trim().toLowerCase();

      const existing = await db(
        "SELECT id FROM users WHERE email = $1",
        [normalizedEmail]
      );

      if (existing.rows.length) {
        return res.status(409).json({
          ok: false,
          message: "Email already exists"
        });
      }

      const hash = await bcrypt.hash(password, 12);

      const result = await db(
        `
        INSERT INTO users
        (company_id, name, email, password_hash, role, status)
        VALUES ($1, $2, $3, $4, $5, 'Active')
        RETURNING
          id,
          company_id,
          name,
          email,
          role,
          status,
          created_at
        `,
        [
          req.user.companyId,
          name.trim(),
          normalizedEmail,
          hash,
          role
        ]
      );

      res.status(201).json({
        ok: true,
        user: cleanUser(result.rows[0])
      });

    } catch (error) {
      res.status(500).json({
        ok: false,
        message: "Unable to create user"
      });
    }
  }
);

app.patch(
  "/api/users/:id/status",
  auth,
  requireRole("Owner", "Admin"),
  async (req, res) => {
    try {
      const { status } = req.body;

      if (!["Active", "Inactive"].includes(status)) {
        return res.status(400).json({
          ok: false,
          message: "Invalid status"
        });
      }

      if (String(req.params.id) === String(req.user.userId)) {
        return res.status(400).json({
          ok: false,
          message: "You cannot change your own status"
        });
      }

      const result = await db(
        `
        UPDATE users
        SET status = $1
        WHERE id = $2
        AND company_id = $3
        AND role <> 'Owner'
        RETURNING
          id,
          company_id,
          name,
          email,
          role,
          status,
          created_at
        `,
        [
          status,
          req.params.id,
          req.user.companyId
        ]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          ok: false,
          message: "User not found"
        });
      }

      res.json({
        ok: true,
        user: cleanUser(result.rows[0])
      });

    } catch (error) {
      res.status(500).json({
        ok: false,
        message: "Unable to update user"
      });
    }
  }
);

/* =========================
   CUSTOMERS
========================= */

app.get("/api/customers", auth, async (req, res) => {
  try {
    const result = await db(
      `
      SELECT *
      FROM customers
      WHERE company_id = $1
      ORDER BY created_at DESC
      `,
      [req.user.companyId]
    );

    res.json({
      ok: true,
      customers: result.rows
    });

  } catch (error) {
    res.status(500).json({
      ok: false,
      message: "Unable to load customers"
    });
  }
});

app.post("/api/customers", auth, async (req, res) => {
  try {
    const {
      name,
      phone,
      email,
      customer_type,
      address
    } = req.body;

    if (!name) {
      return res.status(400).json({
        ok: false,
        message: "Customer name is required"
      });
    }

    const result = await db(
      `
      INSERT INTO customers
      (
        company_id,
        name,
        phone,
        email,
        customer_type,
        address
      )
      VALUES ($1,$2,$3,$4,$5,$6)
      RETURNING *
      `,
      [
        req.user.companyId,
        name.trim(),
        phone || null,
        email || null,
        customer_type || "Retail",
        address || null
      ]
    );

    res.status(201).json({
      ok: true,
      customer: result.rows[0]
    });

  } catch (error) {
    res.status(500).json({
      ok: false,
      message: "Unable to create customer"
    });
  }
});

/* =========================
   PRODUCTS
========================= */

app.get("/api/products", auth, async (req, res) => {
  try {
    const result = await db(
      `
      SELECT *
      FROM products
      WHERE company_id = $1
      ORDER BY created_at DESC
      `,
      [req.user.companyId]
    );

    res.json({
      ok: true,
      products: result.rows
    });

  } catch (error) {
    res.status(500).json({
      ok: false,
      message: "Unable to load products"
    });
  }
});

app.post("/api/products", auth, async (req, res) => {
  try {
    const {
      name,
      category,
      unit,
      cost_price,
      selling_price,
      stock,
      low_stock
    } = req.body;

    if (!name) {
      return res.status(400).json({
        ok: false,
        message: "Product name is required"
      });
    }

    const result = await db(
      `
      INSERT INTO products
      (
        company_id,
        name,
        category,
        unit,
        cost_price,
        selling_price,
        stock,
        low_stock
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      RETURNING *
      `,
      [
        req.user.companyId,
        name.trim(),
        category || "General",
        unit || "pcs",
        Number(cost_price || 0),
        Number(selling_price || 0),
        Number(stock || 0),
        Number(low_stock || 0)
      ]
    );

    res.status(201).json({
      ok: true,
      product: result.rows[0]
    });

  } catch (error) {
    res.status(500).json({
      ok: false,
      message: "Unable to create product"
    });
  }
});

/* =========================
   SALES
========================= */

app.get("/api/sales", auth, async (req, res) => {
  try {
    const result = await db(
      `
      SELECT
        s.*,
        c.name AS customer_name,
        p.name AS product_name
      FROM sales s
      LEFT JOIN customers c
        ON c.id = s.customer_id
      LEFT JOIN products p
        ON p.id = s.product_id
      WHERE s.company_id = $1
      ORDER BY s.sale_date DESC, s.created_at DESC
      `,
      [req.user.companyId]
    );

    res.json({
      ok: true,
      sales: result.rows
    });

  } catch (error) {
    res.status(500).json({
      ok: false,
      message: "Unable to load sales"
    });
  }
});

app.post("/api/sales", auth, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const {
      sale_date,
      customer_id,
      product_id,
      qty,
      selling_price,
      payment_status,
      invoice_no
    } = req.body;

    const quantity = Number(qty || 0);
    const price = Number(selling_price || 0);

    if (!product_id || quantity <= 0 || price < 0) {
      await client.query("ROLLBACK");

      return res.status(400).json({
        ok: false,
        message: "Invalid sale data"
      });
    }

    const productResult = await client.query(
      `
      SELECT *
      FROM products
      WHERE id = $1
      AND company_id = $2
      FOR UPDATE
      `,
      [
        product_id,
        req.user.companyId
      ]
    );

    if (!productResult.rows.length) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        ok: false,
        message: "Product not found"
      });
    }

    const product = productResult.rows[0];

    if (Number(product.stock) < quantity) {
      await client.query("ROLLBACK");

      return res.status(400).json({
        ok: false,
        message: `Insufficient stock. Available: ${product.stock}`
      });
    }

    const total = quantity * price;
    const costTotal = quantity * Number(product.cost_price || 0);

    const saleResult = await client.query(
      `
      INSERT INTO sales
      (
        company_id,
        sale_date,
        customer_id,
        product_id,
        qty,
        selling_price,
        total,
        cost_total,
        payment_status,
        invoice_no,
        salesperson_id
      )
      VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      RETURNING *
      `,
      [
        req.user.companyId,
        sale_date || new Date(),
        customer_id || null,
        product_id,
        quantity,
        price,
        total,
        costTotal,
        payment_status || "Paid",
        invoice_no || null,
        req.user.userId
      ]
    );

    await client.query(
      `
      UPDATE products
      SET
        stock = stock - $1,
        updated_at = NOW()
      WHERE id = $2
      AND company_id = $3
      `,
      [
        quantity,
        product_id,
        req.user.companyId
      ]
    );

    await client.query("COMMIT");

    res.status(201).json({
      ok: true,
      sale: saleResult.rows[0]
    });

  } catch (error) {
    await client.query("ROLLBACK");

    console.error("SALE ERROR:", error);

    res.status(500).json({
      ok: false,
      message: "Unable to create sale"
    });

  } finally {
    client.release();
  }
});

/* =========================
   PURCHASES
========================= */

app.get("/api/purchases", auth, async (req, res) => {
  try {
    const result = await db(
      `
      SELECT
        pu.*,
        p.name AS product_name
      FROM purchases pu
      LEFT JOIN products p
        ON p.id = pu.product_id
      WHERE pu.company_id = $1
      ORDER BY pu.purchase_date DESC
      `,
      [req.user.companyId]
    );

    res.json({
      ok: true,
      purchases: result.rows
    });

  } catch (error) {
    res.status(500).json({
      ok: false,
      message: "Unable to load purchases"
    });
  }
});

app.post("/api/purchases", auth, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const {
      purchase_date,
      supplier_name,
      product_id,
      qty,
      cost_price,
      invoice_no
    } = req.body;

    const quantity = Number(qty || 0);
    const cost = Number(cost_price || 0);

    if (!product_id || quantity <= 0 || cost < 0) {
      await client.query("ROLLBACK");

      return res.status(400).json({
        ok: false,
        message: "Invalid purchase data"
      });
    }

    const product = await client.query(
      `
      SELECT id
      FROM products
      WHERE id = $1
      AND company_id = $2
      FOR UPDATE
      `,
      [
        product_id,
        req.user.companyId
      ]
    );

    if (!product.rows.length) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        ok: false,
        message: "Product not found"
      });
    }

    const total = quantity * cost;

    const result = await client.query(
      `
      INSERT INTO purchases
      (
        company_id,
        purchase_date,
        supplier_name,
        product_id,
        qty,
        cost_price,
        total,
        invoice_no
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      RETURNING *
      `,
      [
        req.user.companyId,
        purchase_date || new Date(),
        supplier_name || null,
        product_id,
        quantity,
        cost,
        total,
        invoice_no || null
      ]
    );

    await client.query(
      `
      UPDATE products
      SET
        stock = stock + $1,
        cost_price = $2,
        updated_at = NOW()
      WHERE id = $3
      AND company_id = $4
      `,
      [
        quantity,
        cost,
        product_id,
        req.user.companyId
      ]
    );

    await client.query("COMMIT");

    res.status(201).json({
      ok: true,
      purchase: result.rows[0]
    });

  } catch (error) {
    await client.query("ROLLBACK");

    res.status(500).json({
      ok: false,
      message: "Unable to create purchase"
    });

  } finally {
    client.release();
  }
});

/* =========================
   EXPENSES
========================= */

app.get("/api/expenses", auth, async (req, res) => {
  try {
    const result = await db(
      `
      SELECT *
      FROM expenses
      WHERE company_id = $1
      ORDER BY expense_date DESC
      `,
      [req.user.companyId]
    );

    res.json({
      ok: true,
      expenses: result.rows
    });

  } catch (error) {
    res.status(500).json({
      ok: false,
      message: "Unable to load expenses"
    });
  }
});

app.post("/api/expenses", auth, async (req, res) => {
  try {
    const {
      expense_date,
      category,
      description,
      amount
    } = req.body;

    const value = Number(amount || 0);

    if (value <= 0) {
      return res.status(400).json({
        ok: false,
        message: "Expense amount must be greater than zero"
      });
    }

    const result = await db(
      `
      INSERT INTO expenses
      (
        company_id,
        expense_date,
        category,
        description,
        amount
      )
      VALUES ($1,$2,$3,$4,$5)
      RETURNING *
      `,
      [
        req.user.companyId,
        expense_date || new Date(),
        category || "Other",
        description || null,
        value
      ]
    );

    res.status(201).json({
      ok: true,
      expense: result.rows[0]
    });

  } catch (error) {
    res.status(500).json({
      ok: false,
      message: "Unable to create expense"
    });
  }
});

/* =========================
   DASHBOARD
========================= */

app.get("/api/dashboard", auth, async (req, res) => {
  try {
    const sales = await db(
      `
      SELECT
        COALESCE(SUM(total),0) AS revenue,
        COALESCE(SUM(cost_total),0) AS cogs,
        COUNT(*) AS invoice_count,
        COALESCE(
          SUM(
            CASE
              WHEN payment_status = 'Paid'
              THEN total
              ELSE 0
            END
          ),0
        ) AS paid_amount,
        COALESCE(
          SUM(
            CASE
              WHEN payment_status = 'Credit'
              THEN total
              ELSE 0
            END
          ),0
        ) AS credit_amount
      FROM sales
      WHERE company_id = $1
      `,
      [req.user.companyId]
    );

    const expenses = await db(
      `
      SELECT COALESCE(SUM(amount),0) AS expenses
      FROM expenses
      WHERE company_id = $1
      `,
      [req.user.companyId]
    );

    const customers = await db(
      `
      SELECT COUNT(*) AS count
      FROM customers
      WHERE company_id = $1
      `,
      [req.user.companyId]
    );

    const products = await db(
      `
      SELECT
        COUNT(*) AS product_count,
        COALESCE(SUM(stock),0) AS stock_units,
        COALESCE(
          SUM(stock * cost_price),0
        ) AS stock_value,
        COUNT(*) FILTER (
          WHERE stock <= low_stock
        ) AS low_stock
      FROM products
      WHERE company_id = $1
      `,
      [req.user.companyId]
    );

    const revenue = Number(sales.rows[0].revenue);
    const cogs = Number(sales.rows[0].cogs);
    const expense = Number(expenses.rows[0].expenses);

    const grossProfit = revenue - cogs;
    const netProfit = grossProfit - expense;

    res.json({
      ok: true,
      dashboard: {
        revenue,
        cogs,
        gross_profit: grossProfit,
        expenses: expense,
        net_profit: netProfit,
        invoice_count: Number(sales.rows[0].invoice_count),
        paid_amount: Number(sales.rows[0].paid_amount),
        credit_amount: Number(sales.rows[0].credit_amount),
        customer_count: Number(customers.rows[0].count),
        product_count: Number(products.rows[0].product_count),
        stock_units: Number(products.rows[0].stock_units),
        stock_value: Number(products.rows[0].stock_value),
        low_stock: Number(products.rows[0].low_stock)
      }
    });

  } catch (error) {
    console.error("DASHBOARD ERROR:", error);

    res.status(500).json({
      ok: false,
      message: "Unable to load dashboard"
    });
  }
});

/* =========================
   404
========================= */

app.use((req, res) => {
  res.status(404).json({
    ok: false,
    message: "API route not found",
    path: req.path
  });
});

/* =========================
   ERROR HANDLER
========================= */

app.use((err, req, res, next) => {
  console.error("SERVER ERROR:", err);

  res.status(500).json({
    ok: false,
    message: "Internal server error"
  });
});

/* =========================
   START
========================= */

app.listen(PORT, () => {
  console.log("======================================");
  console.log("AUNG SMART BUSINESS ERP");
  console.log("Version: 4.0.0");
  console.log(`Server: http://localhost:${PORT}`);
  console.log(`Database: ${pool ? "configured" : "not configured"}`);
  console.log("======================================");
});
