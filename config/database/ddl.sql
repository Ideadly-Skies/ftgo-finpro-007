-- DDL Queries: Database Schema Creation
DROP TABLE IF EXISTS gojek_drivers CASCADE;
DROP TABLE IF EXISTS gojek_transactions CASCADE;
DROP TABLE IF EXISTS factory_requests CASCADE;
DROP TABLE IF EXISTS factories CASCADE;
DROP TABLE IF EXISTS reports CASCADE;
DROP TABLE IF EXISTS tokens CASCADE;
DROP TABLE IF EXISTS customer_transactions CASCADE;
DROP TABLE IF EXISTS store_transactions CASCADE;
DROP TABLE IF EXISTS factory_admins CASCADE;
DROP TABLE IF EXISTS vendor_admins CASCADE;
DROP TABLE IF EXISTS store_admins CASCADE;
DROP TABLE IF EXISTS vending_machines CASCADE;
DROP TABLE IF EXISTS vendors CASCADE;
DROP TABLE IF EXISTS stores CASCADE;
DROP TABLE IF EXISTS suppliers CASCADE;
DROP TABLE IF EXISTS customers CASCADE;

-- Table: Customers
CREATE TABLE customers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    jwt_token TEXT,
    wallet_balance DECIMAL(10, 2) DEFAULT 0.00,
    token_list JSONB DEFAULT '[]',
    inventory JSONB DEFAULT '[]',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_verified BOOLEAN DEFAULT FALSE
);

-- Table: Suppliers
CREATE TABLE suppliers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    contact_info JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: Stores
CREATE TABLE stores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    products JSONB NOT NULL,
    product_types JSONB NOT NULL,
    status BOOLEAN DEFAULT TRUE,
    supplier_id UUID REFERENCES suppliers(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: Vendors
CREATE TABLE vendors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    phone_number VARCHAR(15),
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    total_plastic_recycled INT DEFAULT 0,
    revenue DECIMAL(10, 2) DEFAULT 0.00,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: Vending Machines
CREATE TABLE vending_machines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    store_id UUID REFERENCES stores(id),
    vendor_id UUID REFERENCES vendors(id),
    type VARCHAR(255),
    capacity INT NOT NULL,
    current_fill INT DEFAULT 0,
    compatible_plastics JSONB NOT NULL,
    last_maintenance TIMESTAMP,
    next_maintenance_due TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: Store Admins
CREATE TABLE store_admins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    store_id UUID REFERENCES stores(id),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    jwt_token TEXT, -- Added JWT Token
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: Vendor Admins
CREATE TABLE vendor_admins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor_id UUID REFERENCES vendors(id),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    jwt_token TEXT, -- Added JWT Token
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: Customer Transactions (e.g., Wallet Top-Ups, Withdrawals)
CREATE TABLE customer_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID REFERENCES customers(id),
    order_id VARCHAR(50) UNIQUE NOT NULL, -- Order ID for Midtrans reference
    transaction_type VARCHAR(50) NOT NULL, -- E.g., "Top-Up", "Withdraw"
    amount DECIMAL(10, 2) NOT NULL,
    status VARCHAR(50) DEFAULT 'Pending', -- E.g., "Pending", "Completed"
    is_processed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: Store Transactions (e.g., Product Purchases)
CREATE TABLE store_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID REFERENCES customers(id),
    store_id UUID REFERENCES stores(id),
    items JSONB NOT NULL, -- JSON array of purchased items with quantity and price
    total_amount DECIMAL(10, 2) NOT NULL,
    status VARCHAR(50) DEFAULT 'Completed', -- E.g., "Completed", "Failed"
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: Tokens
CREATE TABLE tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID REFERENCES customers(id),
    vendor_id UUID REFERENCES vendors(id),
    amount DECIMAL(10, 2) NOT NULL,
    issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: Reports
CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vending_machine_id UUID REFERENCES vending_machines(id),
    vendor_id UUID REFERENCES vendors(id),
    report_data JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: Factory
CREATE TABLE factories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    location VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: Factory Admins
CREATE TABLE factory_admins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    factory_id UUID REFERENCES factories(id),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: Factory Requests
CREATE TABLE factory_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor_id UUID REFERENCES vendors(id),
    factory_id UUID REFERENCES factories(id),
    status VARCHAR(50) DEFAULT 'Pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: Gojek Drivers (Simulated)
CREATE TABLE gojek_drivers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    phone_number VARCHAR(15) NOT NULL,
    vehicle_details JSONB NOT NULL,
    jwt_token TEXT, -- Added JWT Token
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: Gojek Transactions (Simulated)
CREATE TABLE gojek_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID REFERENCES customers(id),
    driver_id UUID REFERENCES gojek_drivers(id),
    total_amount DECIMAL(10, 2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- DML Queries: Sample Data Population
-- Insert sample customers
INSERT INTO customers (name, email, password) VALUES
('Alice', 'alice@example.com', 'password123'),
('Bob', 'bob@example.com', 'password456');

-- Insert sample suppliers
INSERT INTO suppliers (name, contact_info) VALUES
('Global Plastics', '{"email": "supply@globalplastics.com", "phone": "123456789"}'),
('Eco Materials Inc.', '{"email": "contact@ecomaterials.com", "phone": "987654321"}');

-- Insert sample stores
INSERT INTO stores (name, products, product_types, supplier_id) VALUES
('EcoStore', '[{"product":"Plastic Bottle", "price": 15000, "quantity": 100}, {"product":"Metal Can", "price": 12000, "quantity": 50}]', '["Plastic", "Metal"]', (SELECT id FROM suppliers LIMIT 1)),
('GreenShop', '[{"product":"Egg Carton", "price": 7000, "quantity": 50}, {"product":"Glass Bottle", "price": 20000, "quantity": 30}]', '["Cardboard", "Glass"]', (SELECT id FROM suppliers OFFSET 1 LIMIT 1));

-- Insert sample vendors
INSERT INTO vendors (name, phone_number, email, password) VALUES
('Plastic Recycler Co.', '123456789', 'recycler@example.com', 'recyclepass');

-- Insert sample vending machines
INSERT INTO vending_machines (store_id, vendor_id, type, capacity, compatible_plastics) VALUES
((SELECT id FROM stores LIMIT 1), (SELECT id FROM vendors LIMIT 1), 'Plastic', 500, '["PET", "HDPE"]');

-- Insert sample store admins
INSERT INTO store_admins (store_id, name, email, password) VALUES
((SELECT id FROM stores LIMIT 1), 'Store Admin Alice', 'admin.alice@ecostore.com', 'adminpass123'),
((SELECT id FROM stores OFFSET 1 LIMIT 1), 'Store Admin Bob', 'admin.bob@greenshop.com', 'adminpass456');

-- Insert sample vendor admins
INSERT INTO vendor_admins (vendor_id, name, email, password) VALUES
((SELECT id FROM vendors LIMIT 1), 'Vendor Admin Charlie', 'admin.charlie@recycler.com', 'vendorpass123');

-- Insert sample factory admins
INSERT INTO factory_admins (factory_id, name, email, password) VALUES
((SELECT id FROM factories LIMIT 1), 'Factory Admin Dave', 'admin.dave@factory.com', 'factorypass123');