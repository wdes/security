// @generated automatically by Diesel CLI.

diesel::table! {
    scan_tasks (task_group_id, cidr) {
        #[max_length = 255]
        task_group_id -> Varchar,
        #[max_length = 255]
        cidr -> Varchar,
        #[max_length = 255]
        created_by_username -> Varchar,
        created_at -> Datetime,
        updated_at -> Nullable<Datetime>,
        started_at -> Nullable<Datetime>,
        still_processing_at -> Nullable<Datetime>,
        ended_at -> Nullable<Datetime>,
    }
}

diesel::table! {
    scanners (ip, ip_type) {
        #[max_length = 255]
        ip -> Varchar,
        ip_type -> Unsigned<Tinyint>,
        #[max_length = 255]
        scanner_name -> Varchar,
        #[max_length = 255]
        ip_ptr -> Nullable<Varchar>,
        created_at -> Datetime,
        updated_at -> Nullable<Datetime>,
        last_seen_at -> Nullable<Datetime>,
        last_checked_at -> Nullable<Datetime>,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    scan_tasks,
    scanners,
);
