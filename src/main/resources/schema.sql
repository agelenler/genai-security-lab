CREATE TABLE orders (
 reference VARCHAR(30) PRIMARY KEY,
 customer VARCHAR(30) NOT NULL,
 age_days INT NOT NULL,
 amount DECIMAL(10,2) NOT NULL
);
INSERT INTO orders VALUES ('ORD-100', 'alice', 10, 49.00);
INSERT INTO orders VALUES ('ORD-101', 'alice', 45, 89.00);
INSERT INTO orders VALUES ('ORD-200', 'bob', 5, 499.00);
