CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS companies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(200) NOT NULL,
    owner_name VARCHAR(200),
    currency VARCHAR(20) DEFAULT 'MMK',
    monthly_target NUMERIC(18,2) DEFAULT 100000000,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    email VARCHAR(320) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'Salesperson',
    status VARCHAR(20) NOT NULL DEFAULT 'Active',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_company
ON users(company_id);

CREATE TABLE IF NOT EXISTS customers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    phone VARCHAR(50),
    email VARCHAR(320),
    customer_type VARCHAR(50) DEFAULT 'Retail',
    address TEXT,
    credit_limit NUMERIC(18,2) DEFAULT 0,
    opening_balance NUMERIC(18,2) DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_customers_company
ON customers(company_id);

CREATE TABLE IF NOT EXISTS suppliers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    phone VARCHAR(50),
    email VARCHAR(320),
    address TEXT,
    credit_limit NUMERIC(18,2) DEFAULT 0,
    opening_balance NUMERIC(18,2) DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_suppliers_company
ON suppliers(company_id);

CREATE TABLE IF NOT EXISTS products (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    sku VARCHAR(100),
    name VARCHAR(200) NOT NULL,
    category VARCHAR(100) DEFAULT 'General',
    unit VARCHAR(50) DEFAULT 'pcs',
    cost_price NUMERIC(18,2) DEFAULT 0,
    selling_price NUMERIC(18,2) DEFAULT 0,
    stock NUMERIC(18,3) DEFAULT 0,
    low_stock NUMERIC(18,3) DEFAULT 0,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_products_company
ON products(company_id);

CREATE TABLE IF NOT EXISTS sales (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    invoice_no VARCHAR(100) NOT NULL,
    sale_date TIMESTAMPTZ DEFAULT NOW(),
    customer_id UUID REFERENCES customers(id) ON DELETE SET NULL,
    product_id UUID NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    qty NUMERIC(18,3) NOT NULL,
    selling_price NUMERIC(18,2) NOT NULL,
    total NUMERIC(18,2) NOT NULL,
    cost_total NUMERIC(18,2) DEFAULT 0,
    payment_status VARCHAR(30) DEFAULT 'Paid',
    paid_amount NUMERIC(18,2) DEFAULT 0,
    balance_due NUMERIC(18,2) DEFAULT 0,
    salesperson_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sales_company
ON sales(company_id);

CREATE INDEX IF NOT EXISTS idx_sales_invoice
ON sales(invoice_no);

CREATE TABLE IF NOT EXISTS sales_payments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    sale_id UUID NOT NULL REFERENCES sales(id) ON DELETE CASCADE,
    payment_date TIMESTAMPTZ DEFAULT NOW(),
    amount NUMERIC(18,2) NOT NULL,
    payment_method VARCHAR(50) DEFAULT 'Cash',
    reference_no VARCHAR(100),
    note TEXT,
    received_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sales_payments_company
ON sales_payments(company_id);

CREATE TABLE IF NOT EXISTS purchases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    purchase_no VARCHAR(100) NOT NULL,
    purchase_date TIMESTAMPTZ DEFAULT NOW(),
    supplier_id UUID REFERENCES suppliers(id) ON DELETE SET NULL,
    product_id UUID NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    qty NUMERIC(18,3) NOT NULL,
    cost_price NUMERIC(18,2) NOT NULL,
    total NUMERIC(18,2) NOT NULL,
    payment_status VARCHAR(30) DEFAULT 'Paid',
    paid_amount NUMERIC(18,2) DEFAULT 0,
    balance_due NUMERIC(18,2) DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_purchases_company
ON purchases(company_id);

CREATE TABLE IF NOT EXISTS purchase_payments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    purchase_id UUID NOT NULL REFERENCES purchases(id) ON DELETE CASCADE,
    payment_date TIMESTAMPTZ DEFAULT NOW(),
    amount NUMERIC(18,2) NOT NULL,
    payment_method VARCHAR(50) DEFAULT 'Cash',
    reference_no VARCHAR(100),
    note TEXT,
    paid_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS expenses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    expense_date TIMESTAMPTZ DEFAULT NOW(),
    category VARCHAR(100) DEFAULT 'Other',
    description TEXT,
    amount NUMERIC(18,2) NOT NULL,
    payment_method VARCHAR(50) DEFAULT 'Cash',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_expenses_company
ON expenses(company_id);

CREATE TABLE IF NOT EXISTS stock_movements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    product_id UUID NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    movement_type VARCHAR(50) NOT NULL,
    qty NUMERIC(18,3) NOT NULL,
    reference_type VARCHAR(50),
    reference_id UUID,
    note TEXT,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_stock_movements_company
ON stock_movements(company_id);

CREATE INDEX IF NOT EXISTS idx_stock_movements_product
ON stock_movements(product_id);

CREATE TABLE IF NOT EXISTS employees (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    department VARCHAR(100),
    position VARCHAR(100),
    salary NUMERIC(18,2) DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(100),
    entity_id UUID,
    details JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_company
ON audit_logs(company_id);

CREATE INDEX IF NOT EXISTS idx_audit_created
ON audit_logs(created_at);
