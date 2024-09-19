CREATE TABLE IF NOT EXISTS `scanners` (
    ip VARCHAR(255) NOT NULL,
    ip_type TINYINT(1) UNSIGNED NOT NULL,
    scanner_name VARCHAR(255) NOT NULL,
    ip_ptr VARCHAR(255) NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NULL,
    last_seen_at DATETIME NULL,
    last_checked_at DATETIME NULL,
    PRIMARY KEY (ip, ip_type)
);
