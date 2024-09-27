use std::net::IpAddr;

use crate::Scanners;
use chrono::{NaiveDateTime, Utc};
use diesel::dsl::insert_into;
use diesel::prelude::*;
use diesel::result::Error as DieselError;
use hickory_resolver::Name;

use crate::schema::scan_tasks::dsl::scan_tasks;
use crate::schema::scanners::dsl::scanners;

#[derive(Queryable, Selectable, Debug)]
#[diesel(table_name = crate::schema::scanners)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub struct Scanner {
    pub ip: String,
    pub ip_type: u8,
    pub scanner_name: Scanners,
    pub ip_ptr: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: Option<NaiveDateTime>,
    pub last_seen_at: Option<NaiveDateTime>,
    pub last_checked_at: Option<NaiveDateTime>,
}

impl Scanner {
    pub fn find_or_new(
        query_address: IpAddr,
        scanner_name: Scanners,
        ptr: Option<Name>,
        conn: &mut MysqlConnection,
    ) -> Result<Scanner, ()> {
        let ip_type = if query_address.is_ipv6() { 6 } else { 4 };
        let scanner_row_result = Scanner::find(query_address.to_string(), ip_type, conn);
        let scanner_row = match scanner_row_result {
            Ok(scanner_row) => scanner_row,
            Err(_) => return Err(()),
        };

        let scanner = if let Some(mut scanner) = scanner_row {
            scanner.last_seen_at = Some(Utc::now().naive_utc());
            scanner.last_checked_at = Some(Utc::now().naive_utc());
            scanner.updated_at = Some(Utc::now().naive_utc());
            scanner
        } else {
            Scanner {
                ip: query_address.to_string(),
                ip_type: ip_type,
                scanner_name: scanner_name.clone(),
                ip_ptr: match ptr {
                    Some(ptr) => Some(ptr.to_string()),
                    None => None,
                },
                created_at: Utc::now().naive_utc(),
                updated_at: None,
                last_seen_at: None,
                last_checked_at: None,
            }
        };
        match scanner.save(conn) {
            Ok(scanner) => Ok(scanner),
            Err(_) => Err(()),
        }
    }

    pub fn find(
        ip_address: String,
        ip_type: u8,
        conn: &mut MysqlConnection,
    ) -> Result<Option<Scanner>, DieselError> {
        use crate::schema::scanners;

        scanners
            .select(Scanner::as_select())
            .filter(scanners::ip.eq(ip_address))
            .filter(scanners::ip_type.eq(ip_type))
            .order((scanners::ip_type.desc(), scanners::created_at.desc()))
            .first(conn)
            .optional()
    }

    pub fn list_names(
        scanner_name: Scanners,
        conn: &mut MysqlConnection,
    ) -> Result<Vec<String>, DieselError> {
        use crate::schema::scanners;
        use crate::schema::scanners::ip;

        scanners
            .select(ip)
            .filter(scanners::scanner_name.eq(scanner_name.to_string()))
            .order((scanners::ip_type.desc(), scanners::created_at.desc()))
            .load::<String>(conn)
    }

    pub fn save(self: Scanner, conn: &mut MysqlConnection) -> Result<Scanner, DieselError> {
        let new_scanner = NewScanner::from_scanner(&self);
        match insert_into(scanners)
            .values(&new_scanner)
            .on_conflict(diesel::dsl::DuplicatedKeys)
            .do_update()
            .set(&new_scanner)
            .execute(conn)
        {
            Ok(_) => Ok(self),
            Err(err) => Err(err),
        }
    }
}

#[derive(Debug, Insertable, AsChangeset)]
#[diesel(table_name = crate::schema::scanners)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub struct NewScanner {
    pub ip: String,
    pub ip_type: u8,
    pub scanner_name: String,
    pub ip_ptr: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: Option<NaiveDateTime>,
    pub last_seen_at: Option<NaiveDateTime>,
    pub last_checked_at: Option<NaiveDateTime>,
}

impl NewScanner {
    pub fn from_scanner<'x>(scanner: &Scanner) -> NewScanner {
        NewScanner {
            ip: scanner.ip.to_string(),
            ip_type: scanner.ip_type,
            scanner_name: scanner.scanner_name.to_string(),
            ip_ptr: scanner.ip_ptr.to_owned(),
            created_at: scanner.created_at,
            updated_at: scanner.updated_at,
            last_seen_at: scanner.last_seen_at,
            last_checked_at: scanner.last_checked_at,
        }
    }
}

#[derive(Queryable, Selectable, Debug)]
#[diesel(table_name = crate::schema::scan_tasks)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub struct ScanTask {
    pub task_group_id: String,
    pub cidr: String,
    pub created_by_username: String,
    pub created_at: NaiveDateTime,
    pub updated_at: Option<NaiveDateTime>,
    pub started_at: Option<NaiveDateTime>,
    pub still_processing_at: Option<NaiveDateTime>,
    pub ended_at: Option<NaiveDateTime>,
}

#[derive(Selectable, Debug, Queryable)]
#[diesel(table_name = crate::schema::scan_tasks)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub struct ScanTaskitem {
    pub task_group_id: String,
    pub cidr: String,
    pub created_by_username: String,
    pub started_at: Option<NaiveDateTime>,
    pub still_processing_at: Option<NaiveDateTime>,
    pub ended_at: Option<NaiveDateTime>,
}

impl ScanTask {
    pub fn list_not_started(conn: &mut MysqlConnection) -> Result<Vec<ScanTaskitem>, DieselError> {
        use crate::schema::scan_tasks;

        let res = scan_tasks
            .select(ScanTaskitem::as_select())
            .filter(scan_tasks::started_at.is_null())
            .order((scan_tasks::created_at.asc(),))
            .load::<ScanTaskitem>(conn);
        match res {
            Ok(rows) => Ok(rows),
            Err(err) => Err(err),
        }
    }

    pub fn list(conn: &mut MysqlConnection) -> Result<Vec<ScanTaskitem>, DieselError> {
        use crate::schema::scan_tasks;

        let res = scan_tasks
            .select(ScanTaskitem::as_select())
            .order((
                scan_tasks::created_at.desc(),
                scan_tasks::task_group_id.asc(),
            ))
            .load::<ScanTaskitem>(conn);
        match res {
            Ok(rows) => Ok(rows),
            Err(err) => Err(err),
        }
    }

    pub fn save(self: &ScanTask, conn: &mut MysqlConnection) -> Result<(), DieselError> {
        let new_scan_task = NewScanTask::from_scan_task(self);
        match insert_into(scan_tasks)
            .values(&new_scan_task)
            .on_conflict(diesel::dsl::DuplicatedKeys)
            .do_update()
            .set(&new_scan_task)
            .execute(conn)
        {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }
}

#[derive(Debug, Insertable, AsChangeset)]
#[diesel(table_name = crate::schema::scan_tasks)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub struct NewScanTask {
    pub task_group_id: String,
    pub cidr: String,
    pub created_by_username: String,
    pub created_at: NaiveDateTime,
    pub updated_at: Option<NaiveDateTime>,
    pub started_at: Option<NaiveDateTime>,
    pub still_processing_at: Option<NaiveDateTime>,
    pub ended_at: Option<NaiveDateTime>,
}

impl NewScanTask {
    pub fn from_scan_task<'x>(scan_task: &ScanTask) -> NewScanTask {
        NewScanTask {
            task_group_id: scan_task.task_group_id.to_string(),
            cidr: scan_task.cidr.to_owned(),
            created_by_username: scan_task.created_by_username.to_owned(),
            created_at: scan_task.created_at,
            updated_at: scan_task.updated_at,
            started_at: scan_task.started_at,
            still_processing_at: scan_task.still_processing_at,
            ended_at: scan_task.ended_at,
        }
    }
}
