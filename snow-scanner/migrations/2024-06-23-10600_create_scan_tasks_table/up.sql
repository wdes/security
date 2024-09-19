CREATE TABLE IF NOT EXISTS `scan_tasks` (
    task_group_id VARCHAR(255) NOT NULL,
    cidr VARCHAR(255) NOT NULL,
    created_by_username VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NULL,
    started_at DATETIME NULL,
    still_processing_at DATETIME NULL,
    ended_at DATETIME NULL,
    PRIMARY KEY (task_group_id, cidr)
);
