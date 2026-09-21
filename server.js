require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 10000;
const JWT_SECRET =
  process.env.JWT_SECRET ||
  "CHANGE_THIS_SECRET_IN_PRODUCTION";

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl:
        process.env.NODE_ENV === "production"
          ? { rejectUnauthorized: false }
          : false
    })
  : null;

app.use(
  helmet({
    crossOriginResourcePolicy: false
  })
);

app.use(
  cors({
    origin: true,
    credentials: true
  })
);

app.use(express.json({ limit: "2mb" }));

async function query(sql, params = []) {
  if (!pool) {
    throw new Error("DATABASE_URL is not configured");
  }

  return pool.query(sql, params);
}

function tokenFor(user) {
  return jwt.sign(
    {
      userId: user.id,
      companyId: user.company_id,
      role: user.role
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      ok: false,
      message: "Authentication required"
    });
  }

  try {
    req.user = jwt.verify(
      header.substring(7),
      JWT_SECRET
    );

    next();
  } catch {
    return res.status(401).json({
      ok: false,
      message: "Invalid or expired session"
    });
  }
}

function roles(...allowed) {
  return (req, res, next) => {
    if (!allowed.includes(req.user.role)) {
      return res.status(403).json({
        ok: false,
        message: "Permission denied"
      });
    }

    next();
  };
}

function userView(user) {
  return {
    id: user.id,
    company_id: user.company_id,
    name: user.name,
    email: user.email,
    role: user.role,
    status: user.status,
    created_at: user.created_at
  };
}

function number(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

function invoiceNumber(prefix = "INV") {
  const date = new Date();
  const stamp =
    date.getFullYear().toString() +
    String(date.getMonth() + 1).padStart(2, "0") +
    String(date.getDate()).padStart(2, "0") +
    "-" +
    String(Date.now()).slice(-6);

  return `${prefix}-${stamp}`;
}

async function audit(
  companyId,
  userId,
  action,
  entityType,
  entityId,
  details = {}
) {
  try {
    await query(
      `
      INSERT INTO audit_logs
      (
        company_id,
        user_id,
        action,
        entity_type,
        entity_id,
        details
      )
      VALUES ($1,$2,$3,$4,$5,$6)
      `,
      [
        companyId,
        userId || null,
        action,
        entityType || null,
        entityId || null,
        JSON.stringify(details)
      ]
    );
  } catch (e) {
    console.error("AUDIT ERROR:", e.message);
  }
}

/* =========================
   HEALTH
========================= */

app.get("/", (req, res) => {
  res.json({
    ok: true,
    app: "AUNG SMART BUSINESS ERP",
    version: "5.0.0",
    mode: "Commercial ERP Core",
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

    await query("SELECT 1");

    res.json({
      ok: true,
      server: "online",
      database: "connected"
    });
  } catch (error) {
    res.status(500).json({
      ok: false,
      server: "online",
      database: "error"
    });
  }
});

/* =========================
   AUTH
========================= */

app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      companyName,
      ownerName,
      email,
      password
    } = req.body;

    if (
      !companyName ||
      !ownerName ||
      !email ||
      !password
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Company name, owner name, email and password are required"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        ok: false,
        message:
          "Password must contain at least 6 characters"
      });
    }

    const normalizedEmail =
      String(email).trim().toLowerCase();

    const existing = await query(
      "SELECT id FROM users WHERE email=$1",
      [normalizedEmail]
    );

    if (existing.rows.length) {
      return res.status(409).json({
        ok: false,
        message: "Email already exists"
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const companyResult = await client.query(
        `
        INSERT INTO companies
        (
          name,
          owner_name,
          currency,
          monthly_target
        )
        VALUES ($1,$2,'MMK',100000000)
        RETURNING *
        `,
        [
          String(companyName).trim(),
          String(ownerName).trim()
        ]
      );

      const company = companyResult.rows[0];

      const hash = await bcrypt.hash(
        password,
        12
      );

      const userResult = await client.query(
        `
        INSERT INTO users
        (
          company_id,
          name,
          email,
          password_hash,
          role,
          status
        )
        VALUES ($1,$2,$3,$4,'Owner','Active')
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
          company.id,
          String(ownerName).trim(),
          normalizedEmail,
          hash
        ]
      );

      const user = userResult.rows[0];

      await client.query("COMMIT");

      res.status(201).json({
        ok: true,
        token: tokenFor(user),
        user: userView(user),
        company
      });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error("REGISTER:", error);

    res.status(500).json({
      ok: false,
      message: "Registration failed"
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const {
      email,
      password
    } = req.body;

    const normalizedEmail =
      String(email || "")
        .trim()
        .toLowerCase();

    const result = await query(
      `
      SELECT *
      FROM users
      WHERE email=$1
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
        message: "User account is inactive"
      });
    }

    const valid = await bcrypt.compare(
      password || "",
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        ok: false,
        message: "Invalid email or password"
      });
    }

    const company = await query(
      `
      SELECT *
      FROM companies
      WHERE id=$1
      `,
      [user.company_id]
    );

    res.json({
      ok: true,
      token: tokenFor(user),
      user: userView(user),
      company: company.rows[0]
    });
  } catch (error) {
    console.error("LOGIN:", error);

    res.status(500).json({
      ok: false,
      message: "Login failed"
    });
  }
});

app.get("/api/auth/me", auth, async (req, res) => {
  try {
    const result = await query(
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
      WHERE id=$1
      AND company_id=$2
      `,
      [
        req.user.userId,
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
      user: userView(result.rows[0])
    });
  } catch {
    res.status(500).json({
      ok: false,
      message: "Unable to load account"
    });
  }
});

/* =========================
   CUSTOMERS
========================= */

app.get("/api/customers", auth, async (req, res) => {
  try {
    const result = await query(
      `
      SELECT
        c.*,
        COALESCE(
          (
            SELECT SUM(s.balance_due)
            FROM sales s
            WHERE s.customer_id=c.id
            AND s.company_id=c.company_id
          ),0
        ) AS receivable
      FROM customers c
      WHERE c.company_id=$1
      ORDER BY c.created_at DESC
      `,
      [req.user.companyId]
    );

    res.json({
      ok: true,
      customers: result.rows
    });
  } catch {
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
      address,
      credit_limit,
      opening_balance
    } = req.body;

    if (!name) {
      return res.status(400).json({
        ok: false,
        message: "Customer name is required"
      });
    }

    const result = await query(
      `
      INSERT INTO customers
      (
        company_id,
        name,
        phone,
        email,
        customer_type,
        address,
        credit_limit,
        opening_balance
      )
      VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8)
      RETURNING *
      `,
      [
        req.user.companyId,
        String(name).trim(),
        phone || null,
        email || null,
        customer_type || "Retail",
        address || null,
        number(credit_limit),
        number(opening_balance)
      ]
    );

    await audit(
      req.user.companyId,
      req.user.userId,
      "CREATE",
      "customer",
      result.rows[0].id
    );

    res.status(201).json({
      ok: true,
      customer: result.rows[0]
    });
  } catch {
    res.status(500).json({
      ok: false,
      message: "Unable to create customer"
    });
  }
});

/* =========================
   SUPPLIERS
========================= */

app.get("/api/suppliers", auth, async (req, res) => {
  try {
    const result = await query(
      `
      SELECT
        s.*,
        COALESCE(
          (
            SELECT SUM(p.balance_due)
            FROM purchases p
            WHERE p.supplier_id=s.id
            AND p.company_id=s.company_id
          ),0
        ) AS payable
      FROM suppliers s
      WHERE s.company_id=$1
      ORDER BY s.created_at DESC
      `,
      [req.user.companyId]
    );

    res.json({
      ok: true,
      suppliers: result.rows
    });
  } catch {
    res.status(500).json({
      ok: false,
      message: "Unable to load suppliers"
    });
  }
});

app.post("/api/suppliers", auth, async (req, res) => {
  try {
    const {
      name,
      phone,
      email,
      address,
      credit_limit,
      opening_balance
    } = req.body;

    if (!name) {
      return res.status(400).json({
        ok: false,
        message: "Supplier name is required"
      });
    }

    const result = await query(
      `
      INSERT INTO suppliers
      (
        company_id,
        name,
        phone,
        email,
        address,
        credit_limit,
        opening_balance
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7)
      RETURNING *
      `,
      [
        req.user.companyId,
        String(name).trim(),
        phone || null,
        email || null,
        address || null,
        number(credit_limit),
        number(opening_balance)
      ]
    );

    res.status(201).json({
      ok: true,
      supplier: result.rows[0]
    });
  } catch {
    res.status(500).json({
      ok: false,
      message: "Unable to create supplier"
    });
  }
});

/* =========================
   PRODUCTS
========================= */

app.get("/api/products", auth, async (req, res) => {
  try {
    const result = await query(
      `
      SELECT *
      FROM products
      WHERE company_id=$1
      AND active=true
      ORDER BY created_at DESC
      `,
      [req.user.companyId]
    );

    res.json({
      ok: true,
      products: result.rows
    });
  } catch {
    res.status(500).json({
      ok: false,
      message: "Unable to load products"
    });
  }
});

app.post("/api/products", auth, async (req, res) => {
  try {
    const {
      sku,
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

    const result = await query(
      `
      INSERT INTO products
      (
        company_id,
        sku,
        name,
        category,
        unit,
        cost_price,
        selling_price,
        stock,
        low_stock
      )
      VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8,$9)
      RETURNING *
      `,
      [
        req.user.companyId,
        sku || null,
        String(name).trim(),
        category || "General",
        unit || "pcs",
        number(cost_price),
        number(selling_price),
        number(stock),
        number(low_stock)
      ]
    );

    const product = result.rows[0];

    if (number(stock) !== 0) {
      await query(
        `
        INSERT INTO stock_movements
        (
          company_id,
          product_id,
          movement_type,
          qty,
          reference_type,
          note,
          created_by
        )
        VALUES
        ($1,$2,'OPENING',$3,'PRODUCT','Opening stock',$4)
        `,
        [
          req.user.companyId,
          product.id,
          number(stock),
          req.user.userId
        ]
      );
    }

    res.status(201).json({
      ok: true,
      product
    });
  } catch (error) {
    console.error("PRODUCT:", error);

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
    const result = await query(
      `
      SELECT
        s.*,
        c.name AS customer_name,
        p.name AS product_name,
        u.name AS salesperson_name
      FROM sales s
      LEFT JOIN customers c
        ON c.id=s.customer_id
      LEFT JOIN products p
        ON p.id=s.product_id
      LEFT JOIN users u
        ON u.id=s.salesperson_id
      WHERE s.company_id=$1
      ORDER BY s.sale_date DESC
      `,
      [req.user.companyId]
    );

    res.json({
      ok: true,
      sales: result.rows
    });
  } catch {
    res.status(500).json({
      ok: false,
      message: "Unable to load sales"
    });
  }
});

app.post("/api/sales", auth, async (req, res) => {
  if (!pool) {
    return res.status(500).json({
      ok: false,
      message: "Database is not configured"
    });
  }

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
      paid_amount,
      invoice_no
    } = req.body;

    const quantity = number(qty);
    const price = number(selling_price);

    if (!product_id || quantity <= 0) {
      throw new Error("Invalid sale quantity");
    }

    const productResult = await client.query(
      `
      SELECT *
      FROM products
      WHERE id=$1
      AND company_id=$2
      AND active=true
      FOR UPDATE
      `,
      [
        product_id,
        req.user.companyId
      ]
    );

    if (!productResult.rows.length) {
      throw new Error("Product not found");
    }

    const product = productResult.rows[0];

    if (number(product.stock) < quantity) {
      throw new Error(
        `Insufficient stock. Available: ${product.stock}`
      );
    }

    const total = quantity * price;
    const costTotal =
      quantity * number(product.cost_price);

    let paid = number(paid_amount);

    if (payment_status === "Paid") {
      paid = total;
    }

    if (paid > total) {
      paid = total;
    }

    const balance = total - paid;

    const invoice =
      invoice_no || invoiceNumber("INV");

    const saleResult = await client.query(
      `
      INSERT INTO sales
      (
        company_id,
        invoice_no,
        sale_date,
        customer_id,
        product_id,
        qty,
        selling_price,
        total,
        cost_total,
        payment_status,
        paid_amount,
        balance_due,
        salesperson_id
      )
      VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
      RETURNING *
      `,
      [
        req.user.companyId,
        invoice,
        sale_date || new Date(),
        customer_id || null,
        product_id,
        quantity,
        price,
        total,
        costTotal,
        balance === 0 ? "Paid" : "Credit",
        paid,
        balance,
        req.user.userId
      ]
    );

    const sale = saleResult.rows[0];

    if (paid > 0) {
      await client.query(
        `
        INSERT INTO sales_payments
        (
          company_id,
          sale_id,
          amount,
          payment_method,
          received_by
        )
        VALUES
        ($1,$2,$3,'Cash',$4)
        `,
        [
          req.user.companyId,
          sale.id,
          paid,
          req.user.userId
        ]
      );
    }

    await client.query(
      `
      UPDATE products
      SET
        stock=stock-$1,
        updated_at=NOW()
      WHERE id=$2
      AND company_id=$3
      `,
      [
        quantity,
        product_id,
        req.user.companyId
      ]
    );

    await client.query(
      `
      INSERT INTO stock_movements
      (
        company_id,
        product_id,
        movement_type,
        qty,
        reference_type,
        reference_id,
        note,
        created_by
      )
      VALUES
      ($1,$2,'SALE',$3,'SALE',$4,$5,$6)
      `,
      [
        req.user.companyId,
        product_id,
        -quantity,
        sale.id,
        invoice,
        req.user.userId
      ]
    );

    await client.query("COMMIT");

    await audit(
      req.user.companyId,
      req.user.userId,
      "CREATE",
      "sale",
      sale.id,
      {
        invoice_no: invoice,
        total
      }
    );

    res.status(201).json({
      ok: true,
      sale
    });
  } catch (error) {
    await client.query("ROLLBACK");

    res.status(400).json({
      ok: false,
      message: error.message
    });
  } finally {
    client.release();
  }
});

/* =========================
   SALES PAYMENT
========================= */

app.post(
  "/api/sales/:id/payment",
  auth,
  async (req, res) => {
    if (!pool) {
      return res.status(500).json({
        ok: false,
        message: "Database is not configured"
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const amount = number(req.body.amount);

      if (amount <= 0) {
        throw new Error(
          "Payment amount must be greater than zero"
        );
      }

      const saleResult = await client.query(
        `
        SELECT *
        FROM sales
        WHERE id=$1
        AND company_id=$2
        FOR UPDATE
        `,
        [
          req.params.id,
          req.user.companyId
        ]
      );

      if (!saleResult.rows.length) {
        throw new Error("Invoice not found");
      }

      const sale = saleResult.rows[0];

      const actual =
        Math.min(amount, number(sale.balance_due));

      if (actual <= 0) {
        throw new Error(
          "This invoice has no outstanding balance"
        );
      }

      const newPaid =
        number(sale.paid_amount) + actual;

      const newBalance =
        Math.max(
          0,
          number(sale.total) - newPaid
        );

      await client.query(
        `
        INSERT INTO sales_payments
        (
          company_id,
          sale_id,
          amount,
          payment_method,
          reference_no,
          note,
          received_by
        )
        VALUES
        ($1,$2,$3,$4,$5,$6,$7)
        `,
        [
          req.user.companyId,
          sale.id,
          actual,
          req.body.payment_method || "Cash",
          req.body.reference_no || null,
          req.body.note || null,
          req.user.userId
        ]
      );

      const updated = await client.query(
        `
        UPDATE sales
        SET
          paid_amount=$1,
          balance_due=$2,
          payment_status=$3
        WHERE id=$4
        AND company_id=$5
        RETURNING *
        `,
        [
          newPaid,
          newBalance,
          newBalance === 0
            ? "Paid"
            : "Credit",
          sale.id,
          req.user.companyId
        ]
      );

      await client.query("COMMIT");

      res.json({
        ok: true,
        sale: updated.rows[0],
        payment: actual
      });
    } catch (error) {
      await client.query("ROLLBACK");

      res.status(400).json({
        ok: false,
        message: error.message
      });
    } finally {
      client.release();
    }
  }
);

/* =========================
   PURCHASES
========================= */

app.get("/api/purchases", auth, async (req, res) => {
  try {
    const result = await query(
      `
      SELECT
        p.*,
        s.name AS supplier_name,
        pr.name AS product_name
      FROM purchases p
      LEFT JOIN suppliers s
        ON s.id=p.supplier_id
      LEFT JOIN products pr
        ON pr.id=p.product_id
      WHERE p.company_id=$1
      ORDER BY p.purchase_date DESC
      `,
      [req.user.companyId]
    );

    res.json({
      ok: true,
      purchases: result.rows
    });
  } catch {
    res.status(500).json({
      ok: false,
      message: "Unable to load purchases"
    });
  }
});

app.post(
  "/api/purchases",
  auth,
  async (req, res) => {
    if (!pool) {
      return res.status(500).json({
        ok: false,
        message: "Database is not configured"
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const {
        purchase_date,
        supplier_id,
        product_id,
        qty,
        cost_price,
        payment_status,
        paid_amount,
        purchase_no
      } = req.body;

      const quantity = number(qty);
      const cost = number(cost_price);

      if (!product_id || quantity <= 0) {
        throw new Error(
          "Invalid purchase quantity"
        );
      }

      const productResult = await client.query(
        `
        SELECT *
        FROM products
        WHERE id=$1
        AND company_id=$2
        FOR UPDATE
        `,
        [
          product_id,
          req.user.companyId
        ]
      );

      if (!productResult.rows.length) {
        throw new Error("Product not found");
      }

      const total = quantity * cost;

      let paid = number(paid_amount);

      if (payment_status === "Paid") {
        paid = total;
      }

      paid = Math.min(paid, total);

      const balance = total - paid;

      const purchase =
        purchase_no || invoiceNumber("PUR");

      const result = await client.query(
        `
        INSERT INTO purchases
        (
          company_id,
          purchase_no,
          purchase_date,
          supplier_id,
          product_id,
          qty,
          cost_price,
          total,
          payment_status,
          paid_amount,
          balance_due
        )
        VALUES
        ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        RETURNING *
        `,
        [
          req.user.companyId,
          purchase,
          purchase_date || new Date(),
          supplier_id || null,
          product_id,
          quantity,
          cost,
          total,
          balance === 0
            ? "Paid"
            : "Credit",
          paid,
          balance
        ]
      );

      const row = result.rows[0];

      if (paid > 0) {
        await client.query(
          `
          INSERT INTO purchase_payments
          (
            company_id,
            purchase_id,
            amount,
            payment_method,
            paid_by
          )
          VALUES
          ($1,$2,$3,'Cash',$4)
          `,
          [
            req.user.companyId,
            row.id,
            paid,
            req.user.userId
          ]
        );
      }

      await client.query(
        `
        UPDATE products
        SET
          stock=stock+$1,
          cost_price=$2,
          updated_at=NOW()
        WHERE id=$3
        AND company_id=$4
        `,
        [
          quantity,
          cost,
          product_id,
          req.user.companyId
        ]
      );

      await client.query(
        `
        INSERT INTO stock_movements
        (
          company_id,
          product_id,
          movement_type,
          qty,
          reference_type,
          reference_id,
          note,
          created_by
        )
        VALUES
        ($1,$2,'PURCHASE',$3,'PURCHASE',$4,$5,$6)
        `,
        [
          req.user.companyId,
          product_id,
          quantity,
          row.id,
          purchase,
          req.user.userId
        ]
      );

      await client.query("COMMIT");

      res.status(201).json({
        ok: true,
        purchase: row
      });
    } catch (error) {
      await client.query("ROLLBACK");

      res.status(400).json({
        ok: false,
        message: error.message
      });
    } finally {
      client.release();
    }
  }
);

/* =========================
   EXPENSES
========================= */

app.get("/api/expenses", auth, async (req, res) => {
  try {
    const result = await query(
      `
      SELECT *
      FROM expenses
      WHERE company_id=$1
      ORDER BY expense_date DESC
      `,
      [req.user.companyId]
    );

    res.json({
      ok: true,
      expenses: result.rows
    });
  } catch {
    res.status(500).json({
      ok: false,
      message: "Unable to load expenses"
    });
  }
});

app.post("/api/expenses", auth, async (req, res) => {
  try {
    const amount = number(req.body.amount);

    if (amount <= 0) {
      return res.status(400).json({
        ok: false,
        message: "Amount must be greater than zero"
      });
    }

    const result = await query(
      `
      INSERT INTO expenses
      (
        company_id,
        expense_date,
        category,
        description,
        amount,
        payment_method
      )
      VALUES
      ($1,$2,$3,$4,$5,$6)
      RETURNING *
      `,
      [
        req.user.companyId,
        req.body.expense_date || new Date(),
        req.body.category || "Other",
        req.body.description || null,
        amount,
        req.body.payment_method || "Cash"
      ]
    );

    res.status(201).json({
      ok: true,
      expense: result.rows[0]
    });
  } catch {
    res.status(500).json({
      ok: false,
      message: "Unable to create expense"
    });
  }
});

/* =========================
   STOCK MOVEMENTS
========================= */

app.get(
  "/api/stock-movements",
  auth,
  async (req, res) => {
    try {
      const result = await query(
        `
        SELECT
          sm.*,
          p.name AS product_name,
          u.name AS created_by_name
        FROM stock_movements sm
        JOIN products p
          ON p.id=sm.product_id
        LEFT JOIN users u
          ON u.id=sm.created_by
        WHERE sm.company_id=$1
        ORDER BY sm.created_at DESC
        LIMIT 500
        `,
        [req.user.companyId]
      );

      res.json({
        ok: true,
        movements: result.rows
      });
    } catch {
      res.status(500).json({
        ok: false,
        message: "Unable to load stock movements"
      });
    }
  }
);

/* =========================
   DASHBOARD
========================= */

app.get(
  "/api/dashboard",
  auth,
  async (req, res) => {
    try {
      const sales = await query(
        `
        SELECT
          COALESCE(SUM(total),0) revenue,
          COALESCE(SUM(cost_total),0) cogs,
          COALESCE(SUM(paid_amount),0) collected,
          COALESCE(SUM(balance_due),0) receivable,
          COUNT(*) invoice_count
        FROM sales
        WHERE company_id=$1
        `,
        [req.user.companyId]
      );

      const purchases = await query(
        `
        SELECT
          COALESCE(SUM(total),0) purchase_total,
          COALESCE(SUM(balance_due),0) payable
        FROM purchases
        WHERE company_id=$1
        `,
        [req.user.companyId]
      );

      const expenses = await query(
        `
        SELECT
          COALESCE(SUM(amount),0) total
        FROM expenses
        WHERE company_id=$1
        `,
        [req.user.companyId]
      );

      const stock = await query(
        `
        SELECT
          COUNT(*) product_count,
          COALESCE(SUM(stock),0) stock_units,
          COALESCE(
            SUM(stock*cost_price),0
          ) stock_value,
          COUNT(*) FILTER(
            WHERE stock<=low_stock
          ) low_stock
        FROM products
        WHERE company_id=$1
        AND active=true
        `,
        [req.user.companyId]
      );

      const customers = await query(
        `
        SELECT COUNT(*) count
        FROM customers
        WHERE company_id=$1
        `,
        [req.user.companyId]
      );

      const revenue =
        number(sales.rows[0].revenue);

      const cogs =
        number(sales.rows[0].cogs);

      const expense =
        number(expenses.rows[0].total);

      const gross =
        revenue - cogs;

      const net =
        gross - expense;

      res.json({
        ok: true,
        dashboard: {
          revenue,
          cogs,
          gross_profit: gross,
          expenses: expense,
          net_profit: net,

          collected:
            number(sales.rows[0].collected),

          receivable:
            number(sales.rows[0].receivable),

          invoice_count:
            number(sales.rows[0].invoice_count),

          purchase_total:
            number(
              purchases.rows[0].purchase_total
            ),

          payable:
            number(purchases.rows[0].payable),

          customer_count:
            number(customers.rows[0].count),

          product_count:
            number(stock.rows[0].product_count),

          stock_units:
            number(stock.rows[0].stock_units),

          stock_value:
            number(stock.rows[0].stock_value),

          low_stock:
            number(stock.rows[0].low_stock)
        }
      });
    } catch (error) {
      console.error("DASHBOARD:", error);

      res.status(500).json({
        ok: false,
        message: "Unable to load dashboard"
      });
    }
  }
);

/* =========================
   COMPANY
========================= */

app.get(
  "/api/company",
  auth,
  async (req, res) => {
    try {
      const result = await query(
        `
        SELECT *
        FROM companies
        WHERE id=$1
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
    } catch {
      res.status(500).json({
        ok: false,
        message: "Unable to load company"
      });
    }
  }
);

app.put(
  "/api/company",
  auth,
  roles("Owner", "Admin"),
  async (req, res) => {
    try {
      const result = await query(
        `
        UPDATE companies
        SET
          name=COALESCE($1,name),
          owner_name=COALESCE($2,owner_name),
          currency=COALESCE($3,currency),
          monthly_target=COALESCE($4,monthly_target),
          updated_at=NOW()
        WHERE id=$5
        RETURNING *
        `,
        [
          req.body.name || null,
          req.body.owner_name || null,
          req.body.currency || null,
          req.body.monthly_target == null
            ? null
            : number(req.body.monthly_target),
          req.user.companyId
        ]
      );

      res.json({
        ok: true,
        company: result.rows[0]
      });
    } catch {
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
  roles("Owner", "Admin"),
  async (req, res) => {
    try {
      const result = await query(
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
        WHERE company_id=$1
        ORDER BY created_at DESC
        `,
        [req.user.companyId]
      );

      res.json({
        ok: true,
        users: result.rows.map(userView)
      });
    } catch {
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
  roles("Owner", "Admin"),
  async (req, res) => {
    try {
      const allowed = [
        "Admin",
        "Sales Manager",
        "Salesperson",
        "Accountant",
        "Warehouse",
        "HR"
      ];

      if (
        !req.body.name ||
        !req.body.email ||
        !req.body.password ||
        !allowed.includes(req.body.role)
      ) {
        return res.status(400).json({
          ok: false,
          message: "Invalid user data"
        });
      }

      const email =
        String(req.body.email)
          .trim()
          .toLowerCase();

      const exists = await query(
        "SELECT id FROM users WHERE email=$1",
        [email]
      );

      if (exists.rows.length) {
        return res.status(409).json({
          ok: false,
          message: "Email already exists"
        });
      }

      const hash = await bcrypt.hash(
        req.body.password,
        12
      );

      const result = await query(
        `
        INSERT INTO users
        (
          company_id,
          name,
          email,
          password_hash,
          role,
          status
        )
        VALUES
        ($1,$2,$3,$4,$5,'Active')
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
          String(req.body.name).trim(),
          email,
          hash,
          req.body.role
        ]
      );

      res.status(201).json({
        ok: true,
        user: userView(result.rows[0])
      });
    } catch {
      res.status(500).json({
        ok: false,
        message: "Unable to create user"
      });
    }
  }
);

/* =========================
   404
========================= */

app.use((req, res) => {
  res.status(404).json({
    ok: false,
    message: "Route not found",
    path: req.path
  });
});

/* =========================
   ERROR
========================= */

app.use((err, req, res, next) => {
  console.error(err);

  res.status(500).json({
    ok: false,
    message: "Internal server error"
  });
});

/* =========================
   START
========================= */

app.listen(PORT, () => {
  console.log("--------------------------------------");
  console.log("AUNG SMART BUSINESS ERP");
  console.log("Version 5.0.0");
  console.log(`Port: ${PORT}`);
  console.log(
    `Database: ${pool ? "configured" : "not configured"}`
  );
  console.log("--------------------------------------");
});
