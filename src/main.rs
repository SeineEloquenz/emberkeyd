use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key,
};
use asym_ratchet::PublicKey;
use color_eyre::eyre::Result;
use rand::{thread_rng, Rng};
use rusqlite::{params, Connection, ErrorCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Mutex;
use tracing::{error, info};
use warp::{http::StatusCode, hyper::body::Bytes, Filter};

const EMBER_SECRET: &str = "eithu4ae7uzaer5dahfeiwi5Mohy2sah1IBeinguu5afahng8u";

type AesKey = Key<Aes256Gcm>;
type AesNonce = aes_gcm::aead::Nonce<Aes256Gcm>;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct State {
    challenge_nonce: Vec<u8>,
    pubkey: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct Request {
    pubkey: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Deserialize, Serialize)]
struct Challenge {
    challenge: Vec<u8>,
    state: Vec<u8>,
    nonce: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Deserialize, Serialize)]
struct Response {
    response: Vec<u8>,
    state: Vec<u8>,
    nonce: Vec<u8>,
    name: String,
}

impl Challenge {
    fn new_challenge(my_key: &AesKey, pubkey: &PublicKey) -> Challenge {
        let challenge_nonce: [u8; 32] = thread_rng().gen();
        let cipher = Aes256Gcm::new(my_key);
        let nonce = Aes256Gcm::generate_nonce(thread_rng());
        let state = State {
            challenge_nonce: challenge_nonce.to_vec(),
            pubkey: pubkey.clone(),
        };
        let state = bincode::serialize(&state).unwrap();
        let state = cipher.encrypt(&nonce, state.as_ref()).unwrap();
        Challenge {
            challenge: bincode::serialize(
                &pubkey
                    .encrypt(thread_rng(), challenge_nonce.to_vec())
                    .unwrap(),
            )
            .unwrap(),
            state,
            nonce: nonce.to_vec(),
        }
    }
}

impl Response {
    fn verify(&self, my_key: &AesKey) -> Option<PublicKey> {
        let cipher = Aes256Gcm::new(my_key);
        let nonce: &AesNonce = self.nonce.as_slice().try_into().ok()?;
        let plaintext = cipher.decrypt(&nonce, self.state.as_slice()).ok()?;
        let state: State = bincode::deserialize(&plaintext).ok()?;
        if self.response == state.challenge_nonce {
            Some(state.pubkey)
        } else {
            None
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let db: &_ = Box::leak(Box::new(Mutex::new(Connection::open("keys.sqlite")?)));

    db.lock().unwrap().execute(
        r#"CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    pubkey BLOB
)"#,
        (),
    )?;
    db.lock().unwrap().execute(
        r#"CREATE TABLE IF NOT EXISTS logfiles (
    id INTEGER PRIMARY KEY,
    content BLOB
)"#,
        (),
    )?;
    let my_key = Aes256Gcm::generate_key(thread_rng());

    info!("Starting server...");

    let post_challenge = warp::post()
        .and(warp::path!("challenge"))
        .and(warp::body::json())
        .map(move |request: Request| {
            let Ok(pubkey): Result<PublicKey, _> = bincode::deserialize(&request.pubkey) else {
                return warp::reply::with_status(warp::reply::json(&json!({"error": "invalid pubkey"})), StatusCode::BAD_REQUEST);
            };
            let challenge = Challenge::new_challenge(&my_key, &pubkey);
            warp::reply::with_status(warp::reply::json(&challenge), StatusCode::OK)
        });

    let post_response = warp::post()
        .and(warp::path!("response"))
        .and(warp::body::json())
        .map(move |response: Response| match response.verify(&my_key) {
            Some(pubkey) => {
                let keybytes = bincode::serialize(&pubkey).unwrap();
                let res = db.lock().unwrap().execute(
                    "INSERT INTO keys (name, pubkey) VALUES (?1, ?2);",
                    params![response.name, keybytes],
                );
                match res {
                    Ok(_) => {
                        info!("Inserted key for {}", response.name);
                        warp::reply::with_status(warp::reply::json(&()), StatusCode::CREATED)
                    }
                    Err(e) => {
                        error!("Error inserting key for {}: {}", response.name, e);
                        if e.sqlite_error_code() == Some(ErrorCode::ConstraintViolation) {
                            warp::reply::with_status(
                                warp::reply::json(&json!({"error": "name taken"})),
                                StatusCode::CONFLICT,
                            )
                        } else {
                            warp::reply::with_status(
                                warp::reply::json(&json!({"error": "could not insert"})),
                                StatusCode::INTERNAL_SERVER_ERROR,
                            )
                        }
                    }
                }
            }
            None => warp::reply::with_status(
                warp::reply::json(&json!({"error": "failed challenge"})),
                StatusCode::BAD_REQUEST,
            ),
        });

    let get_key = warp::get().and(warp::path!("key" / String)).map(
        move |name: String| -> Box<dyn warp::reply::Reply> {
            let res = db.lock().unwrap().query_row(
                "SELECT pubkey FROM keys WHERE name = ?1",
                params![&name],
                |row| row.get::<_, Vec<u8>>(0),
            );
            match res {
                Ok(bytes) => Box::new(warp::reply::json(&json!({ "pubkey": bytes }))),
                Err(err) => {
                    info!("Failed to retrieve {}: {}", name, err);
                    Box::new(warp::reply::with_status(
                        warp::reply::json(&json!({"error": "not found"})),
                        StatusCode::NOT_FOUND,
                    ))
                }
            }
        },
    );

    let post_log = warp::post()
        .and(warp::path!("logfile"))
        .and(warp::header::exact("X-Ember-Secret", EMBER_SECRET))
        .and(warp::body::bytes())
        .map(move |body: Bytes| {
            let body = &body as &[u8];
            let res = db
                .lock()
                .unwrap()
                .execute("INSERT INTO logfiles (content) VALUES (?1);", params![body]);
            match res {
                Ok(_) => warp::reply::with_status(warp::reply::json(&()), StatusCode::CREATED),
                Err(e) => {
                    error!("Error saving logfile: {}", e);
                    warp::reply::with_status(
                        warp::reply::json(&json!({"error": "could not insert"})),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    )
                }
            }
        });

    let routes = post_challenge.or(post_response).or(get_key).or(post_log);

    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;

    Ok(())
}
