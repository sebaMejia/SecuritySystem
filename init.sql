CREATE TABLE IF NOT EXISTS security_event (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    event_description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO security_event (event_type, event_description) VALUES
('LOGIN', 'User login successful'),
('LOGOUT', 'User logged out'),
('ALERT', 'Suspicious activity detected');