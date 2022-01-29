use rusqlite::{Connection, params, NO_PARAMS};
use migrant_lib::Migrator;
use std::error::Error;
use rand::{thread_rng, Rng, distributions::Standard};
use crate::box_err;

#[derive(Debug)]
pub struct UserInfo {
    pub user_id: String,
    pub secret_key: Vec<u8>,
    pub validation_counter: u32,
    pub alea: String,
}

const USERINFO_PATH: &str = "userinfo.db";

pub fn get() -> Result<Settings, Box<dyn Error + Send>> {
    let dir = std::env::current_dir().map_err(box_err)?.join(USERINFO_PATH);
    let settings = migrant_lib::Settings::configure_sqlite()
        .database_path(dir)
        .map_err(box_err)?
        .build()
        .map_err(box_err)?;

    let mut config = migrant_lib::Config::with_settings(&settings);
    config.setup().map_err(box_err)?;
    config.use_migrations(&[
        migrant_lib::EmbeddedMigration::with_tag("initial-create")
            .up(r#"
            CREATE TABLE kvstore (id INTEGER PRIMARY KEY, key TEXT, value TEXT);
            CREATE UNIQUE INDEX kvstore_key_index ON kvstore(key);
            CREATE TABLE user_info (id INTEGER PRIMARY KEY, username TEXT, user_id TEXT, secret_key BLOB, counter INTEGER);
            "#)
            .down(r#"
            DROP TABLE kvstore;
            DROP TABLE user_info;
            "#)
            .boxed(),
        migrant_lib::EmbeddedMigration::with_tag("add-alea")
            .up(r#"
            ALTER TABLE user_info ADD alea TEXT;
            "#)
            .down(r#"
            -- TODO: ALTER TABLE user_info DROP COLUMN alea DEFAULT '';
            "#)
            .boxed(),
    ]).map_err(box_err)?;
    config = config.reload().map_err(box_err)?;

    Migrator::with_config(&config)
        .all(true)
        .show_output(false)
        .swallow_completion(true)
        .apply()
        .map_err(box_err)?;

    let device_id = hex::encode(thread_rng()
        .sample_iter(&Standard)
        .take(16)
        .collect::<Vec<u8>>()) + "null";

    let conn = Connection::open(USERINFO_PATH).map_err(box_err)?;

    conn.execute(r#"INSERT OR IGNORE INTO kvstore (key, value) VALUES ("device_id", ?1)"#, params![device_id])
        .map_err(box_err)?;

    Ok(Settings { conn })
}

pub struct Settings {
    conn: Connection,
}

impl Clone for Settings {
    fn clone(&self) -> Settings {
        let conn = Connection::open(USERINFO_PATH)
            .expect("Database to still be available.");
        Settings { conn }
    }
}

impl Settings {
    pub fn get_device_id(&self) -> Result<String, Box<dyn Error + Send + Sync>> {
        Ok(self.conn.query_row(r#"SELECT value FROM kvstore WHERE key = "device_id""#, NO_PARAMS, |row| row.get(0))?)
    }

    pub fn get_user_info(&self, username: &str, bump_validation_counter: bool) -> Result<Option<UserInfo>, Box<dyn Error + Send + Sync>> {
        match self.conn.query_row(r#"SELECT * FROM user_info WHERE username = ?1"#, params![username], |row| {
            Ok(UserInfo {
                user_id: row.get("user_id")?,
                secret_key: row.get("secret_key")?,
                validation_counter: row.get("counter")?,
                alea: row.get("alea")?,
            })
        }) {
            Ok(v) => {
                if bump_validation_counter {
                    self.conn.execute(r#"UPDATE user_info SET counter = counter + 1 WHERE username = ?1"#, params![username])?;
                }
                Ok(Some(v))
            },
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(err.into())
        }
    }

    pub fn create_user_info(&self, username: &str, user_info: &UserInfo) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.conn.execute(r#"INSERT INTO user_info (username, user_id, secret_key, counter, alea) VALUES (?1, ?2, ?3, 0, ?4)"#, params![
            username, user_info.user_id, &user_info.secret_key, &user_info.alea
        ])?;
        Ok(())
    }
}
