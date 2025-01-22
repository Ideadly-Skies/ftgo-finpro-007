-- DDL Queries: Database Schema Creation
DROP TABLE IF EXISTS gojek_drivers CASCADE;
DROP TABLE IF EXISTS gojek_transactions CASCADE;
DROP TABLE IF EXISTS factory_vendor_requests CASCADE;
DROP TABLE IF EXISTS factories CASCADE;
DROP TABLE IF EXISTS vendor_customer_report CASCADE;
DROP TABLE IF EXISTS customer_tokens CASCADE;
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
DROP TABLE IF EXISTS vending_transactions CASCADE;
DROP TABLE IF EXISTS plastics_pricing CASCADE;

-- Table: Customers
CREATE TABLE customers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    jwt_token TEXT,
    wallet_balance DECIMAL(10, 2) DEFAULT 0.00,
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

-- table: vending machines
create table vending_machines (
    id uuid primary key default gen_random_uuid(),
    store_id uuid references stores(id),
    vendor_id uuid references vendors(id),
    type varchar(255),
    weight_limit float not null, -- maximum weight limit in kg
    current_weight float default 0.0, -- current weight in kg
    current_fill int default 0, -- current number of items
    compatible_plastics jsonb not null,
    last_maintenance timestamp,
    next_maintenance_due timestamp,
    created_at timestamp default current_timestamp,
    updated_at timestamp default current_timestamp
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

-- Table: Customer Tokens
CREATE TABLE customer_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID REFERENCES customers(id),
    vendor_id UUID REFERENCES vendors(id),
    token TEXT NOT NULL, -- The token string encoding the transaction amount
    issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_redeemed BOOLEAN DEFAULT FALSE -- Tracks whether the token has been redeemed
);

-- Table: Reports
CREATE TABLE vendor_customer_report (
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
    jwt_token TEXT, -- Added JWT Token
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: Factory Requests
CREATE TABLE factory_vendor_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor_id UUID REFERENCES vendors(id),
    factory_id UUID REFERENCES factories(id),
    vending_machine_id UUID REFERENCES vending_machines(id),
    status VARCHAR(50) DEFAULT 'Pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE vending_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID REFERENCES customers(id),
    store_admin_id UUID REFERENCES store_admins(id),
    vendor_id UUID REFERENCES vendors(id),
    vending_machine_id UUID REFERENCES vending_machines(id),
    materials JSONB NOT NULL,
    number_of_items INTEGER DEFAULT 0,
    total_weight FLOAT DEFAULT 0,
    is_processed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE plastics_pricing (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(50) NOT NULL UNIQUE, -- e.g., PET, HDPE, LDPE
    price_per_kg_factory DECIMAL(10, 2) NOT NULL, -- Factory selling price per kilogram
    price_per_kg_customer DECIMAL(10, 2) NOT NULL, -- Customer selling price per kilogram
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: Store Coordinates (latitude, longitude)
CREATE TABLE store_coordinates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    store_name VARCHAR(255) NOT NULL,
    coordinates POINT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

-- Insert sample stores with weights added to products
INSERT INTO stores (name, products, product_types, supplier_id) VALUES
(
    'Costco',
    '[
        {"product": "Kirkland Signature Bottled Water.", "price": 25000, "quantity": 100, "weight": 0.5},
        {"product": "Tide Liquid Laundry Detergent", "price": 30000, "quantity": 50, "weight": 2.5}
    ]',
    '["PET", "HDPE"]',
    (SELECT id FROM suppliers LIMIT 1)
),
(
    'Target',
    '[
        {"product": "Ziploc Sandwich Bags", "price": 90000, "quantity": 50, "weight": 0.1},
        {"product": "Mainstays Outdoor Plastic Stacking Chairs", "price": 180000, "quantity": 30, "weight": 5.0}
    ]',
    '["LDPE", "PP"]',
    (SELECT id FROM suppliers OFFSET 1 LIMIT 1)
);

-- Insert sample vendors
INSERT INTO vendors (name, phone_number, email, password) VALUES
('Plastic Recycler Co.', '123456789', 'recycler@example.com', 'recyclepass'),
('Recycle Pro', '0987654321', 'admin@recyclepro.com', 'prorecycle123');

-- Insert sample factories
INSERT INTO factories (name, location) VALUES
('Green Factory Co.', '123 Eco Lane, Eco City'),
('Recycle Plant A', '45 Green Road, Sustainability Town');

-- Insert sample vending machines
INSERT INTO vending_machines (store_id, vendor_id, type, weight_limit, compatible_plastics) VALUES
((SELECT id FROM stores LIMIT 1), (SELECT id FROM vendors LIMIT 1), 'Plastic', 100.0, '["PET", "HDPE"]'),
((SELECT id FROM stores OFFSET 1 LIMIT 1), (SELECT id FROM vendors OFFSET 1 LIMIT 1), 'Plastic', 150.0, '["LDPE", "PP"]');

-- Insert sample store admins
INSERT INTO store_admins (store_id, name, email, password) VALUES
((SELECT id FROM stores LIMIT 1), 'Store Admin Alice', 'admin.alice@ecostore.com', 'adminpass123'),
((SELECT id FROM stores OFFSET 1 LIMIT 1), 'Store Admin Bob', 'admin.bob@greenshop.com', 'adminpass456');

-- Insert sample vendor admins
INSERT INTO vendor_admins (vendor_id, name, email, password) VALUES
((SELECT id FROM vendors LIMIT 1), 'Vendor Admin Charlie', 'admin.charlie@recycler.com', 'vendorpass123');

-- Insert sample factory admins
INSERT INTO factory_admins (factory_id, name, email, password) VALUES
((SELECT id FROM factories LIMIT 1), 'Factory Admin Dave', 'admin.dave@factory.com', 'factorypass123'),
((SELECT id FROM factories OFFSET 1 LIMIT 1), 'Factory Admin Jane', 'admin.jane@factoryb.com', 'factorypass456');

-- Plastics pricing seed
INSERT INTO plastics_pricing (type, price_per_kg_factory, price_per_kg_customer) VALUES
('PET', 11000.00, 9350.00), -- Factory price: 11,000, Customer price: 15% less (11,000 * 0.85)
('HDPE', 11000.00, 9350.00), -- Factory price: 11,000, Customer price: 15% less
('LDPE', 10500.00, 8925.00), -- Factory price: 10,500, Customer price: 15% less (10,500 * 0.85)
('PP', 10500.00, 8925.00); -- Factory price: 10,500, Customer price: 15% less

-- Insert sample store coordinates
INSERT INTO store_coordinates (store_name, coordinates) VALUES
('Costco', '(-6.166694558903548,106.84852183784476)'),
('Target', '(-6.1627157901078435,106.84914410900927)');
