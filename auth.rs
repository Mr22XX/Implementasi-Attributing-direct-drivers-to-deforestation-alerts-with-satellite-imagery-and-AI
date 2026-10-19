use argon2::{
    password_hash::{rand_core::{OsRng, RngCore}, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{Query, Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Extension, Json,
};
use jsonwebtoken::{decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::{
    collections::HashMap,
    env,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL,
    nama          TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    kredit        INTEGER NOT NULL DEFAULT 0 CHECK (kredit >= 0),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Verifikasi email. User yang sudah ada saat kolom ini pertama kali ditambahkan dianggap terverifikasi
-- (kolom ditambah dengan DEFAULT true, lalu default diganti false untuk pendaftar baru).
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE users ALTER COLUMN email_verified SET DEFAULT false;

-- Login Google via Firebase: uid Firebase yang permanen untuk satu akun Google
ALTER TABLE users ADD COLUMN IF NOT EXISTS firebase_uid TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS users_firebase_uid_key ON users (firebase_uid) WHERE firebase_uid IS NOT NULL;

CREATE TABLE IF NOT EXISTS email_verifications (
    user_id      BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    code_hash    TEXT NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    attempts     INTEGER NOT NULL DEFAULT 0,
    last_sent_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Penghitung pengiriman kode per akun (batas jumlah kirim per jendela waktu)
ALTER TABLE email_verifications ADD COLUMN IF NOT EXISTS send_count   INTEGER NOT NULL DEFAULT 1;
ALTER TABLE email_verifications ADD COLUMN IF NOT EXISTS window_start TIMESTAMPTZ NOT NULL DEFAULT now();

-- Kode reset kata sandi (dipisah dari email_verifications supaya kode verifikasi tidak bisa dipakai untuk reset)
CREATE TABLE IF NOT EXISTS password_resets (
    user_id      BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    code_hash    TEXT NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    attempts     INTEGER NOT NULL DEFAULT 0,
    last_sent_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE password_resets ADD COLUMN IF NOT EXISTS send_count   INTEGER NOT NULL DEFAULT 1;
ALTER TABLE password_resets ADD COLUMN IF NOT EXISTS window_start TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE TABLE IF NOT EXISTS topup_requests (
    id               BIGSERIAL PRIMARY KEY,
    user_id          BIGINT NOT NULL REFERENCES users(id),
    nominal          BIGINT NOT NULL,
    catatan          TEXT,
    bukti            BYTEA NOT NULL,
    bukti_mime       TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending',
    kredit_diberikan INTEGER,
    alasan_admin     TEXT,
    reviewed_by      BIGINT REFERENCES users(id),
    reviewed_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_topup_status ON topup_requests(status, id DESC);

CREATE TABLE IF NOT EXISTS kredit_log (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES users(id),
    delta      INTEGER NOT NULL,
    alasan     TEXT NOT NULL,
    ref        TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS peta_akses (
    user_id    BIGINT NOT NULL REFERENCES users(id),
    kabupaten  TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, kabupaten)
);
"#;

pub async fn ensure_schema(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(SCHEMA).execute(pool).await?;
    Ok(())
}

// ===================== ERROR =====================
pub struct ApiError(pub StatusCode, pub String);

impl ApiError {
    fn bad(msg: &str) -> Self {
        ApiError(StatusCode::BAD_REQUEST, msg.to_string())
    }
    fn unauth() -> Self {
        ApiError(StatusCode::UNAUTHORIZED, "Silakan masuk terlebih dahulu.".into())
    }
    fn server() -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "Terjadi kesalahan server.".into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        eprintln!("DB error: {e}");
        ApiError::server()
    }
}

// ===================== MODEL =====================
#[derive(sqlx::FromRow, Clone)]
pub struct DbUser {
    pub id: i64,
    pub email: String,
    pub nama: String,
    pub password_hash: String,
    pub role: String,
    pub kredit: i32,
}

#[derive(Serialize)]
pub struct UserOut {
    id: i64,
    email: String,
    nama: String,
    role: String,
    kredit: i32,
}

impl From<DbUser> for UserOut {
    fn from(u: DbUser) -> Self {
        UserOut { id: u.id, email: u.email, nama: u.nama, role: u.role, kredit: u.kredit }
    }
}

#[derive(Serialize)]
pub struct AuthResp {
    token: String,
    user: UserOut,
}

// ===================== JWT & PASSWORD =====================
pub fn jwt_secret() -> &'static str {
    static S: OnceLock<String> = OnceLock::new();
    S.get_or_init(|| {
        let s = env::var("JWT_SECRET").expect("JWT_SECRET belum diset di .env");
        assert!(s.len() >= 32, "JWT_SECRET minimal 32 karakter");
        s
    })
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: i64,
    exp: usize,
}

fn make_token(user_id: i64) -> Result<String, ApiError> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| ApiError::server())?.as_secs();
    let claims = Claims { sub: user_id, exp: (now + 7 * 24 * 3600) as usize };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(jwt_secret().as_bytes()))
        .map_err(|_| ApiError::server())
}

async fn hash_pw(pw: String) -> Result<String, ApiError> {
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default().hash_password(pw.as_bytes(), &salt).map(|h| h.to_string())
    })
    .await
    .map_err(|_| ApiError::server())?
    .map_err(|_| ApiError::server())
}

async fn verify_pw(pw: String, hash: String) -> bool {
    tokio::task::spawn_blocking(move || {
        PasswordHash::new(&hash)
            .map(|p| Argon2::default().verify_password(pw.as_bytes(), &p).is_ok())
            .unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

// ===================== MIDDLEWARE =====================
pub async fn require_auth(
    State(pool): State<PgPool>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(ApiError::unauth)?;

    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret().as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| ApiError::unauth())?;

    let user: Option<DbUser> = sqlx::query_as(
        "SELECT id, email, nama, password_hash, role, kredit FROM users WHERE id = $1",
    )
    .bind(data.claims.sub)
    .fetch_optional(&pool)
    .await?;

    let user = user.ok_or_else(ApiError::unauth)?;
    req.extensions_mut().insert(user);
    Ok(next.run(req).await)
}

fn require_admin(user: &DbUser) -> Result<(), ApiError> {
    if user.role == "admin" {
        Ok(())
    } else {
        Err(ApiError(StatusCode::FORBIDDEN, "Khusus admin.".into()))
    }
}

// ===================== REGISTER / LOGIN / VERIFIKASI EMAIL =====================
const CODE_TTL_MIN: i32 = 15; // masa berlaku kode (menit)
const RESEND_COOLDOWN_SEC: f64 = 60.0; // jeda minimal antar pengiriman kode
const MAX_ATTEMPTS: i32 = 5; // salah input maksimal per kode
const MAX_SENDS: i32 = 3; // maksimal pengiriman kode per akun dalam satu jendela
const SEND_WINDOW_MIN: i32 = 15; // lebar jendela pembatas pengiriman (menit)

/// Kode disimpan sebagai hash (bukan teks asli), diikat ke user_id + JWT_SECRET.
fn hash_code(user_id: i64, code: &str) -> String {
    let input = format!("{user_id}:{code}:{}", jwt_secret());
    format!("{:x}", Sha256::digest(input.as_bytes()))
}

/// Kirim kode via SMTP. Env: SMTP_HOST, SMTP_USER, SMTP_PASS, SMTP_FROM (opsional), SMTP_PORT (opsional, default 587).
/// Escape karakter HTML supaya nama user tidak bisa menyisipkan tag ke email.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

const EMAIL_HTML: &str = r##"<!DOCTYPE html>
<html lang="id">
<body style="margin:0;padding:0;background-color:#f1f5f9;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#f1f5f9">
<tr><td align="center" style="padding:32px 12px;">

  <table role="presentation" width="480" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:480px;background-color:#ffffff;border-radius:16px;overflow:hidden;font-family:'Segoe UI',Helvetica,Arial,sans-serif;">

    <!-- Header -->
    <tr><td align="center" bgcolor="#0f172a" style="background-color:#0f172a;padding:28px 24px;">
      <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
        <td align="center" valign="middle" width="48" height="48" bgcolor="#facc15" style="background-color:#facc15;border-radius:12px;width:48px;height:48px;font-size:28px;line-height:48px;text-align:center;">&#9889;</td>
        <td valign="middle" style="padding-left:12px;font-size:28px;font-weight:800;letter-spacing:0.5px;color:#ffffff;">Peta<span style="color:#facc15;">kilat</span></td>
      </tr></table>
      <div style="margin-top:8px;font-size:13px;color:#94a3b8;">Peta cepat, data tepat</div>
    </td></tr>

    <!-- Isi -->
    <tr><td style="padding:32px 28px 8px 28px;color:#0f172a;">
      <div style="font-size:20px;font-weight:700;margin-bottom:12px;">Halo, {{NAMA}} &#128075;</div>
      <div style="font-size:15px;line-height:1.6;color:#334155;">
        {{INTRO}}
      </div>
    </td></tr>

    <!-- Kode -->
    <tr><td align="center" style="padding:20px 28px;">
      <div style="display:inline-block;background-color:#fffbeb;border:2px dashed #facc15;border-radius:12px;padding:16px 28px;font-family:'Courier New',Consolas,monospace;font-size:36px;font-weight:800;letter-spacing:10px;color:#0f172a;">{{KODE}}</div>
    </td></tr>

    <tr><td style="padding:0 28px 28px 28px;">
      <div style="font-size:14px;line-height:1.6;color:#64748b;text-align:center;">
        Kode berlaku <strong style="color:#0f172a;">{{TTL}} menit</strong>.<br>
        Demi keamanan, jangan bagikan kode ini kepada siapa pun.
      </div>
    </td></tr>

    <!-- Footer -->
    <tr><td bgcolor="#f8fafc" style="background-color:#f8fafc;padding:18px 28px;border-top:1px solid #e2e8f0;">
      <div style="font-size:12px;line-height:1.6;color:#94a3b8;text-align:center;">
        {{FOOTER}}<br>
        &copy; Petakilat &#9889;
      </div>
    </td></tr>

  </table>

</td></tr>
</table>
</body>
</html>"##;

/// Kirim kode via SMTP. Env: SMTP_HOST, SMTP_USER, SMTP_PASS, SMTP_FROM (opsional), SMTP_PORT (opsional, default 587).
async fn send_code_email(to: &str, nama: &str, code: &str, reset: bool) -> Result<(), String> {
    use lettre::{
        message::{Mailbox, MultiPart},
        transport::smtp::authentication::Credentials,
        AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    };
    let host = env::var("SMTP_HOST").map_err(|_| "SMTP_HOST belum diset".to_string())?;
    let user = env::var("SMTP_USER").map_err(|_| "SMTP_USER belum diset".to_string())?;
    let pass = env::var("SMTP_PASS").map_err(|_| "SMTP_PASS belum diset".to_string())?;
    let from = env::var("SMTP_FROM").unwrap_or_else(|_| user.clone());
    let port: u16 = env::var("SMTP_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(587);

    // Teks berbeda untuk verifikasi email (daftar) dan reset kata sandi (lupa password)
    let (intro, footer, kind) = if reset {
        (
            "Kami menerima permintaan untuk mengatur ulang kata sandi akun Petakilat Anda. Masukkan kode berikut untuk membuat kata sandi baru:",
            "Tidak merasa meminta reset kata sandi? Abaikan saja email ini, kata sandi Anda tidak berubah.",
            "reset kata sandi",
        )
    } else {
        (
            "Terima kasih sudah mendaftar di Petakilat. Masukkan kode berikut untuk memverifikasi email Anda:",
            "Tidak merasa mendaftar di Petakilat? Abaikan saja email ini.",
            "verifikasi",
        )
    };
    let plain = format!(
        "Halo {nama},\n\n{intro}\n\nKode {kind} Anda: {code}\n\n\
         Kode berlaku {CODE_TTL_MIN} menit. Jangan bagikan kode ini kepada siapa pun.\n\
         {footer}\n"
    );
    let html = EMAIL_HTML
        .replace("{{NAMA}}", &html_escape(nama))
        .replace("{{INTRO}}", intro)
        .replace("{{FOOTER}}", footer)
        .replace("{{KODE}}", code)
        .replace("{{TTL}}", &CODE_TTL_MIN.to_string());

    let msg = Message::builder()
        .from(from.parse::<Mailbox>().map_err(|e| e.to_string())?)
        .to(to.parse::<Mailbox>().map_err(|e| e.to_string())?)
        .subject(format!("⚡ {code} adalah kode {kind} Petakilat Anda"))
        .multipart(MultiPart::alternative_plain_html(plain, html))
        .map_err(|e| e.to_string())?;

    let relay = if port == 465 {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&host)
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
    };
    let mailer = relay
        .map_err(|e| e.to_string())?
        .port(port)
        .credentials(Credentials::new(user, pass))
        .build();
    mailer.send(msg).await.map(|_| ()).map_err(|e| e.to_string())
}

/// Simpan kode baru ke `tabel` ("email_verifications" / "password_resets") secara ATOMIK.
/// Baris hanya diperbarui bila:
///   1) sudah lewat jeda RESEND_COOLDOWN_SEC sejak pengiriman terakhir, dan
///   2) jumlah pengiriman dalam jendela SEND_WINDOW_MIN menit belum mencapai MAX_SENDS.
/// Kalau tidak, ditolak dengan 429 dan kode lama tetap berlaku (tidak tertimpa).
async fn simpan_kode(
    pool: &PgPool,
    tabel: &'static str,
    user_id: i64,
    code_hash: String,
) -> Result<(), ApiError> {
    // `tabel` selalu konstanta dari kode ini (bukan input pengguna), jadi aman disisipkan ke SQL.
    let sql = format!(
        "INSERT INTO {t} (user_id, code_hash, expires_at, attempts, last_sent_at, send_count, window_start)
         VALUES ($1, $2, now() + make_interval(mins => $3), 0, now(), 1, now())
         ON CONFLICT (user_id) DO UPDATE SET
           code_hash    = EXCLUDED.code_hash,
           expires_at   = EXCLUDED.expires_at,
           attempts     = 0,
           last_sent_at = now(),
           send_count   = CASE WHEN {t}.window_start < now() - make_interval(mins => $5)
                               THEN 1 ELSE {t}.send_count + 1 END,
           window_start = CASE WHEN {t}.window_start < now() - make_interval(mins => $5)
                               THEN now() ELSE {t}.window_start END
         WHERE {t}.last_sent_at < now() - make_interval(secs => $4)
           AND ({t}.window_start < now() - make_interval(mins => $5) OR {t}.send_count < $6)",
        t = tabel
    );
    let r = sqlx::query(&sql)
        .bind(user_id)
        .bind(code_hash)
        .bind(CODE_TTL_MIN)
        .bind(RESEND_COOLDOWN_SEC)
        .bind(SEND_WINDOW_MIN)
        .bind(MAX_SENDS)
        .execute(pool)
        .await?;
    if r.rows_affected() > 0 {
        return Ok(());
    }

    // Ditolak: cari tahu apakah karena jeda 60 detik atau karena kuota habis, supaya pesannya tepat.
    let info: Option<(i64, i32, i64)> = sqlx::query_as(&format!(
        "SELECT
           GREATEST(0, CEIL(EXTRACT(EPOCH FROM (last_sent_at + make_interval(secs => $2::float8) - now()))))::bigint,
           send_count,
           GREATEST(0, CEIL(EXTRACT(EPOCH FROM (window_start + make_interval(mins => $3::int) - now()))))::bigint
         FROM {tabel} WHERE user_id = $1"
    ))
    .bind(user_id)
    .bind(RESEND_COOLDOWN_SEC)
    .bind(SEND_WINDOW_MIN)
    .fetch_optional(pool)
    .await?;
    let (cooldown, jumlah, sisa_jendela) = info.unwrap_or((60, 0, 0));

    if jumlah >= MAX_SENDS && sisa_jendela > 0 {
        let menit = (sisa_jendela + 59) / 60;
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            format!(
                "Permintaan kode sudah mencapai batas {MAX_SENDS} kali. Coba lagi sekitar {menit} menit lagi."
            ),
        ));
    }
    Err(ApiError(
        StatusCode::TOO_MANY_REQUESTS,
        format!("Tunggu {} detik sebelum meminta kode baru.", cooldown.max(1)),
    ))
}

/// Buat kode baru lalu kirim ke email. Ditolak (429) jika kena jeda atau kuota kirim habis.
async fn issue_code(pool: &PgPool, user: &DbUser) -> Result<(), ApiError> {
    let code = format!("{:06}", OsRng.next_u32() % 1_000_000);
    simpan_kode(pool, "email_verifications", user.id, hash_code(user.id, &code)).await?;
    send_code_email(&user.email, &user.nama, &code, false).await.map_err(|e| {
        eprintln!("Gagal kirim email verifikasi ke {}: {e}", user.email);
        ApiError(StatusCode::BAD_GATEWAY, "Gagal mengirim email verifikasi. Coba lagi nanti.".into())
    })
}

#[derive(Deserialize)]
pub struct RegisterReq {
    email: String,
    nama: String,
    password: String,
}

/// Mendaftar TIDAK langsung memberi token. User harus verifikasi email dulu.
pub async fn register(
    State(pool): State<PgPool>,
    Json(req): Json<RegisterReq>,
) -> Result<Json<Value>, ApiError> {
    let email = req.email.trim().to_lowercase();
    let nama = req.nama.trim().to_string();
    if !email.contains('@') || email.len() > 120 {
        return Err(ApiError::bad("Email tidak valid."));
    }
    if nama.is_empty() || nama.chars().count() > 80 {
        return Err(ApiError::bad("Nama wajib diisi (maksimal 80 karakter)."));
    }
    if req.password.len() < 8 || req.password.len() > 128 {
        return Err(ApiError::bad("Kata sandi 8-128 karakter."));
    }

    let hash = hash_pw(req.password).await?;
    // Email di ADMIN_EMAIL otomatis menjadi admin (tetap harus verifikasi email dulu sebelum bisa masuk)
    let is_admin = env::var("ADMIN_EMAIL")
        .map(|a| a.trim().to_lowercase() == email)
        .unwrap_or(false);
    let role = if is_admin { "admin" } else { "user" };

    // Email yang sudah terdaftar tapi BELUM terverifikasi boleh mendaftar ulang (data ditimpa),
    // supaya email tidak "terkunci" oleh pendaftaran yang tidak pernah diselesaikan.
    let user: Option<DbUser> = sqlx::query_as(
        "INSERT INTO users (email, nama, password_hash, role) VALUES ($1, $2, $3, $4)
         ON CONFLICT (email) DO UPDATE SET nama = EXCLUDED.nama, password_hash = EXCLUDED.password_hash
         WHERE users.email_verified = false
         RETURNING id, email, nama, password_hash, role, kredit",
    )
    .bind(&email)
    .bind(&nama)
    .bind(&hash)
    .bind(role)
    .fetch_optional(&pool)
    .await?;
    let user = user.ok_or_else(|| ApiError(StatusCode::CONFLICT, "Email sudah terdaftar.".into()))?;

    issue_code(&pool, &user).await?;
    Ok(Json(json!({ "needs_verification": true, "email": user.email })))
}

#[derive(Deserialize)]
pub struct LoginReq {
    email: String,
    password: String,
}

pub async fn login(
    State(pool): State<PgPool>,
    Json(req): Json<LoginReq>,
) -> Result<Response, ApiError> {
    let email = req.email.trim().to_lowercase();
    let user: Option<DbUser> = sqlx::query_as(
        "SELECT id, email, nama, password_hash, role, kredit FROM users WHERE email = $1",
    )
    .bind(&email)
    .fetch_optional(&pool)
    .await?;

    let fail = || ApiError(StatusCode::UNAUTHORIZED, "Email atau kata sandi salah.".into());
    let user = user.ok_or_else(fail)?;
    if !verify_pw(req.password, user.password_hash.clone()).await {
        return Err(fail());
    }

    let (verified,): (bool,) = sqlx::query_as("SELECT email_verified FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&pool)
        .await?;
    if !verified {
        // Kirim kode baru (diabaikan kalau masih masa jeda: kode sebelumnya masih berlaku)
        let _ = issue_code(&pool, &user).await;
        return Ok((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "Email belum diverifikasi. Masukkan kode yang dikirim ke email Anda.",
                "code": "email_not_verified",
                "email": user.email
            })),
        )
            .into_response());
    }
    Ok(Json(AuthResp { token: make_token(user.id)?, user: user.into() }).into_response())
}

#[derive(Deserialize)]
pub struct VerifyReq {
    email: String,
    code: String,
}

pub async fn verify_email(
    State(pool): State<PgPool>,
    Json(req): Json<VerifyReq>,
) -> Result<Json<AuthResp>, ApiError> {
    let email = req.email.trim().to_lowercase();
    let bad = || ApiError::bad("Kode salah.");
    let user: Option<DbUser> = sqlx::query_as(
        "SELECT id, email, nama, password_hash, role, kredit FROM users WHERE email = $1",
    )
    .bind(&email)
    .fetch_optional(&pool)
    .await?;
    let user = user.ok_or_else(bad)?;

    // Setiap percobaan dihitung secara atomik; kode mati setelah MAX_ATTEMPTS salah atau kedaluwarsa.
    let row: Option<(String,)> = sqlx::query_as(
        "UPDATE email_verifications SET attempts = attempts + 1
         WHERE user_id = $1 AND attempts < $2 AND expires_at > now()
         RETURNING code_hash",
    )
    .bind(user.id)
    .bind(MAX_ATTEMPTS)
    .fetch_optional(&pool)
    .await?;
    let (stored,) = row.ok_or_else(|| {
        ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "Kode kedaluwarsa atau terlalu banyak percobaan. Minta kode baru.".into(),
        )
    })?;
    if stored != hash_code(user.id, req.code.trim()) {
        return Err(bad());
    }

    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE users SET email_verified = true WHERE id = $1")
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM email_verifications WHERE user_id = $1")
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(Json(AuthResp { token: make_token(user.id)?, user: user.into() }))
}

#[derive(Deserialize)]
pub struct ResendReq {
    email: String,
}

/// Jawaban selalu sama agar endpoint ini tidak bisa dipakai menebak email yang terdaftar.
pub async fn resend_code(
    State(pool): State<PgPool>,
    Json(req): Json<ResendReq>,
) -> Result<Json<Value>, ApiError> {
    let email = req.email.trim().to_lowercase();
    let user: Option<DbUser> = sqlx::query_as(
        "SELECT id, email, nama, password_hash, role, kredit FROM users WHERE email = $1 AND email_verified = false",
    )
    .bind(&email)
    .fetch_optional(&pool)
    .await?;
    if let Some(u) = user {
        issue_code(&pool, &u).await?;
    }
    Ok(Json(json!({ "success": true })))
}

// ===================== LUPA KATA SANDI =====================
/// Kode reset diikat ke user_id + JWT_SECRET + kata "reset", jadi tidak sama dengan kode verifikasi email.
fn hash_reset_code(user_id: i64, code: &str) -> String {
    let input = format!("reset:{user_id}:{code}:{}", jwt_secret());
    format!("{:x}", Sha256::digest(input.as_bytes()))
}

/// Buat kode reset baru lalu kirim ke email. Ditolak (429) jika kena jeda atau kuota kirim habis.
async fn issue_reset_code(pool: &PgPool, user: &DbUser) -> Result<(), ApiError> {
    let code = format!("{:06}", OsRng.next_u32() % 1_000_000);
    simpan_kode(pool, "password_resets", user.id, hash_reset_code(user.id, &code)).await?;
    send_code_email(&user.email, &user.nama, &code, true).await.map_err(|e| {
        eprintln!("Gagal kirim email reset ke {}: {e}", user.email);
        ApiError(StatusCode::BAD_GATEWAY, "Gagal mengirim email. Coba lagi nanti.".into())
    })
}

#[derive(Deserialize)]
pub struct ForgotReq {
    email: String,
}

/// Minta kode reset. Jawaban SELALU sama (email terdaftar atau tidak, kena jeda atau tidak, SMTP gagal atau tidak).
/// Hasil sebenarnya (terkirim / ditolak jeda / SMTP gagal) hanya dicatat di log server.
pub async fn forgot_password(
    State(pool): State<PgPool>,
    Json(req): Json<ForgotReq>,
) -> Result<Json<Value>, ApiError> {
    let email = req.email.trim().to_lowercase();
    if email.len() <= 120 {
        let user: Option<DbUser> = sqlx::query_as(
            "SELECT id, email, nama, password_hash, role, kredit FROM users WHERE email = $1",
        )
        .bind(&email)
        .fetch_optional(&pool)
        .await?;
        if let Some(u) = user {
            // Dijalankan SEBELUM membalas (bukan tokio::spawn) supaya pengiriman email tidak terputus
            // di hosting yang membatasi CPU setelah respons terkirim, dan supaya jeda 60 detik di server
            // sudah tercatat sebelum hitung mundur di browser dimulai.
            match issue_reset_code(&pool, &u).await {
                Ok(()) => println!("Kode reset terkirim ke {}", u.email),
                Err(ApiError(status, msg)) => eprintln!("Reset password {}: {} {}", u.email, status, msg),
            }
        }
    }
    Ok(Json(json!({ "success": true })))
}

#[derive(Deserialize)]
pub struct ResetReq {
    email: String,
    code: String,
    password: String,
}

/// Atur kata sandi baru memakai kode dari email. Jika berhasil, user langsung masuk (token dikembalikan).
/// Karena kode terbukti sampai ke email tersebut, email otomatis ditandai terverifikasi.
pub async fn reset_password(
    State(pool): State<PgPool>,
    Json(req): Json<ResetReq>,
) -> Result<Json<AuthResp>, ApiError> {
    let email = req.email.trim().to_lowercase();
    // Validasi kata sandi di awal supaya salah ketik tidak menghabiskan jatah percobaan kode
    if req.password.len() < 8 || req.password.len() > 128 {
        return Err(ApiError::bad("Kata sandi 8-128 karakter."));
    }
    let bad = || ApiError::bad("Kode salah.");
    let user: Option<DbUser> = sqlx::query_as(
        "SELECT id, email, nama, password_hash, role, kredit FROM users WHERE email = $1",
    )
    .bind(&email)
    .fetch_optional(&pool)
    .await?;
    let user = user.ok_or_else(bad)?;

    // Setiap percobaan dihitung secara atomik; kode mati setelah MAX_ATTEMPTS salah atau kedaluwarsa.
    let row: Option<(String,)> = sqlx::query_as(
        "UPDATE password_resets SET attempts = attempts + 1
         WHERE user_id = $1 AND attempts < $2 AND expires_at > now()
         RETURNING code_hash",
    )
    .bind(user.id)
    .bind(MAX_ATTEMPTS)
    .fetch_optional(&pool)
    .await?;
    let (stored,) = row.ok_or_else(|| {
        ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "Kode kedaluwarsa atau terlalu banyak percobaan. Minta kode baru.".into(),
        )
    })?;
    if stored != hash_reset_code(user.id, req.code.trim()) {
        return Err(bad());
    }

    let hash = hash_pw(req.password).await?;
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE users SET password_hash = $1, email_verified = true WHERE id = $2")
        .bind(&hash)
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM password_resets WHERE user_id = $1")
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM email_verifications WHERE user_id = $1")
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(Json(AuthResp { token: make_token(user.id)?, user: user.into() }))
}

// ===================== LOGIN GOOGLE (lewat Firebase Authentication) =====================
const FIREBASE_JWK_URL: &str =
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";
const JWK_TTL: Duration = Duration::from_secs(3600);

struct JwkCache {
    fetched: Option<Instant>,
    keys: HashMap<String, (String, String)>, // kid -> (n, e)
}

fn jwk_cache() -> &'static Mutex<JwkCache> {
    static C: OnceLock<Mutex<JwkCache>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(JwkCache { fetched: None, keys: HashMap::new() }))
}

/// Ambil kunci publik Firebase untuk `kid` (di-cache 1 jam; diambil ulang bila kid tidak dikenal).
async fn firebase_key(kid: &str) -> Result<(String, String), ApiError> {
    {
        let c = jwk_cache().lock().unwrap();
        if c.fetched.map_or(false, |t| t.elapsed() < JWK_TTL) {
            if let Some(k) = c.keys.get(kid) {
                return Ok(k.clone());
            }
        }
    }
    let gagal = |e: String| {
        eprintln!("Gagal mengambil kunci Firebase: {e}");
        ApiError(StatusCode::BAD_GATEWAY, "Tidak dapat menghubungi Google. Coba lagi nanti.".into())
    };
    let jwks: Value = crate::http_client()
        .get(FIREBASE_JWK_URL)
        .send()
        .await
        .map_err(|e| gagal(e.to_string()))?
        .json()
        .await
        .map_err(|e| gagal(e.to_string()))?;

    let mut keys = HashMap::new();
    if let Some(arr) = jwks.get("keys").and_then(|k| k.as_array()) {
        for k in arr {
            if let (Some(id), Some(n), Some(e)) = (k["kid"].as_str(), k["n"].as_str(), k["e"].as_str()) {
                keys.insert(id.to_string(), (n.to_string(), e.to_string()));
            }
        }
    }
    let found = keys.get(kid).cloned();
    {
        let mut c = jwk_cache().lock().unwrap();
        c.keys = keys;
        c.fetched = Some(Instant::now());
    }
    found.ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "Token Google tidak valid.".into()))
}

#[derive(Deserialize)]
pub struct GoogleReq {
    id_token: String,
}

#[derive(Deserialize)]
struct FbSignIn {
    sign_in_provider: Option<String>,
}

#[derive(Deserialize)]
struct FbClaims {
    sub: String,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
    firebase: Option<FbSignIn>,
}

/// Terima ID token Firebase, verifikasi tanda tangan + audience + issuer, lalu masuk / buat akun.
pub async fn google_login(
    State(pool): State<PgPool>,
    Json(req): Json<GoogleReq>,
) -> Result<Json<AuthResp>, ApiError> {
    let project_id = env::var("FIREBASE_PROJECT_ID").map_err(|_| {
        eprintln!("FIREBASE_PROJECT_ID belum diset");
        ApiError::server()
    })?;
    let project_id = project_id.trim().to_string();
    let token = req.id_token.trim();
    if token.is_empty() || token.len() > 4096 {
        return Err(ApiError::bad("Token Google tidak valid."));
    }
    let invalid = || ApiError(StatusCode::UNAUTHORIZED, "Token Google tidak valid atau kedaluwarsa.".into());

    // Verifikasi dilakukan SEBELUM menyentuh database, supaya koneksi pool (hanya 2) tidak tertahan.
    let header = decode_header(token).map_err(|_| invalid())?;
    if header.alg != Algorithm::RS256 {
        return Err(invalid());
    }
    let kid = header.kid.ok_or_else(invalid)?;
    let (modulus, exponent) = firebase_key(&kid).await?;

    let mut v = Validation::new(Algorithm::RS256);
    v.set_audience(&[project_id.as_str()]);
    v.set_issuer(&[format!("https://securetoken.google.com/{project_id}")]);
    let key = DecodingKey::from_rsa_components(&modulus, &exponent).map_err(|_| invalid())?;
    let claims = decode::<FbClaims>(token, &key, &v)
        .map_err(|e| {
            eprintln!("Token Firebase ditolak: {e}");
            invalid()
        })?
        .claims;

    // Hanya terima login lewat Google (bukan provider lain bila suatu saat diaktifkan di Firebase)
    if claims.firebase.as_ref().and_then(|f| f.sign_in_provider.as_deref()) != Some("google.com") {
        return Err(invalid());
    }
    if claims.email_verified != Some(true) {
        return Err(ApiError::bad("Email akun Google ini belum terverifikasi."));
    }
    let uid = claims.sub;
    let email = claims.email.unwrap_or_default().trim().to_lowercase();
    if uid.is_empty() || !email.contains('@') || email.len() > 120 {
        return Err(ApiError::bad("Data akun Google tidak lengkap."));
    }
    let name = claims.name.unwrap_or_default();
    let raw = name.trim();
    let raw = if raw.is_empty() { email.split('@').next().unwrap_or("Pengguna") } else { raw };
    let nama: String = raw.chars().take(80).collect();

    // 1) Sudah pernah masuk dengan Google -> cari lewat uid (tahan terhadap perubahan email)
    let by_uid: Option<DbUser> = sqlx::query_as(
        "SELECT id, email, nama, password_hash, role, kredit FROM users WHERE firebase_uid = $1",
    )
    .bind(&uid)
    .fetch_optional(&pool)
    .await?;

    let user = match by_uid {
        Some(u) => u,
        None => {
            let is_admin = env::var("ADMIN_EMAIL")
                .map(|a| a.trim().to_lowercase() == email)
                .unwrap_or(false);
            let role = if is_admin { "admin" } else { "user" };

            // 2) Akun baru, atau email sudah ada -> tautkan (atomik dalam satu query).
            // '!google' bukan hash argon2 yang valid, jadi verify_pw() selalu gagal: akun ini tidak
            // bisa masuk dengan kata sandi sampai user memakai "Lupa kata sandi".
            // Jika akun lama belum terverifikasi, kata sandinya DIBUANG supaya orang yang
            // mendaftarkan email korban lebih dulu tidak tetap memegang akun itu.
            let u: Option<DbUser> = sqlx::query_as(
                "INSERT INTO users (email, nama, password_hash, role, email_verified, firebase_uid)
                 VALUES ($1, $2, '!google', $3, true, $4)
                 ON CONFLICT (email) DO UPDATE SET
                   firebase_uid = EXCLUDED.firebase_uid,
                   email_verified = true,
                   password_hash = CASE WHEN users.email_verified
                                        THEN users.password_hash
                                        ELSE EXCLUDED.password_hash END
                 WHERE users.firebase_uid IS NULL
                 RETURNING id, email, nama, password_hash, role, kredit",
            )
            .bind(&email)
            .bind(&nama)
            .bind(role)
            .bind(&uid)
            .fetch_optional(&pool)
            .await?;
            u.ok_or_else(|| {
                ApiError(StatusCode::CONFLICT, "Email ini sudah tertaut ke akun Google lain.".into())
            })?
        }
    };

    Ok(Json(AuthResp { token: make_token(user.id)?, user: user.into() }))
}

pub async fn me(Extension(user): Extension<DbUser>) -> Json<UserOut> {
    Json(user.into())
}

// ===================== PEMAKAIAN KREDIT =====================
// Aturan:
//  - Membuka provinsi / kabupaten / desa : cukup punya kredit > 0 (TIDAK dipotong).
//  - Ekspor PNG / PDF                    : kredit dipotong saat ekspor (lihat `cek_ekspor`).
//  - Admin                               : tidak dicek dan tidak dipotong.
fn cost_per_export() -> i32 {
    env::var("CREDIT_PER_EXPORT")
        .or_else(|_| env::var("CREDIT_PER_MAP")) // kompatibel dengan .env lama
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(1)
}

fn kredit_habis() -> ApiError {
    ApiError(
        StatusCode::PAYMENT_REQUIRED,
        "Kredit Anda habis. Silakan beli kredit lewat admin terlebih dahulu untuk mengakses peta.".into(),
    )
}

/// Gerbang akses: lolos jika admin atau kredit > 0. Tidak memotong kredit.
/// `user.kredit` selalu segar karena dibaca ulang dari DB oleh `require_auth` di setiap request.
fn cek_punya_kredit(user: &DbUser) -> Result<(), ApiError> {
    if user.role == "admin" || user.kredit > 0 {
        Ok(())
    } else {
        Err(kredit_habis())
    }
}

/// Dipanggil oleh handler get-desa (main.rs). Nama dipertahankan supaya main.rs tidak perlu diubah,
/// tetapi sekarang HANYA memeriksa kredit > 0 dan tidak memotong apa pun.
pub async fn charge_peta(_pool: &PgPool, user: &DbUser, _kabupaten: &str) -> Result<(), ApiError> {
    cek_punya_kredit(user)
}

// ===================== ADMIN =====================
/// Cari akun user (nama atau email) agar admin memilih akun dari database, bukan mengetik email manual.
/// Tanpa kata kunci: tampilkan 10 akun terbaru. Hanya akun yang emailnya sudah terverifikasi.
pub async fn admin_users_search(
    State(pool): State<PgPool>,
    Extension(admin): Extension<DbUser>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Vec<UserOut>>, ApiError> {
    require_admin(&admin)?;
    let q: String = params.get("q").map(|s| s.trim()).unwrap_or("").chars().take(80).collect();

    let rows: Vec<(i64, String, String, String, i32)> = if q.is_empty() {
        sqlx::query_as(
            "SELECT id, email, nama, role, kredit FROM users
             WHERE email_verified = true ORDER BY id DESC LIMIT 10",
        )
        .fetch_all(&pool)
        .await?
    } else {
        // Karakter khusus LIKE di-escape supaya "%" atau "_" dicari apa adanya
        let esc = q.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
        sqlx::query_as(
            "SELECT id, email, nama, role, kredit FROM users
             WHERE email_verified = true AND (email ILIKE $1 OR nama ILIKE $1)
             ORDER BY nama ASC, id ASC LIMIT 10",
        )
        .bind(format!("%{esc}%"))
        .fetch_all(&pool)
        .await?
    };

    Ok(Json(
        rows.into_iter()
            .map(|(id, email, nama, role, kredit)| UserOut { id, email, nama, role, kredit })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct AddKreditReq {
    user_id: i64,
    jumlah: i32,
    alasan: Option<String>,
}

/// Tambah/kurangi kredit berdasarkan id akun yang dipilih admin lewat pencarian (mis. setelah pembayaran lewat WhatsApp).
pub async fn admin_add_kredit(
    State(pool): State<PgPool>,
    Extension(admin): Extension<DbUser>,
    Json(req): Json<AddKreditReq>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&admin)?;
    if req.jumlah == 0 || req.jumlah.abs() > 100_000 {
        return Err(ApiError::bad("Jumlah tidak valid."));
    }
    let mut tx = pool.begin().await?;
    let row: Option<(i64, String, String, i32)> = sqlx::query_as(
        "UPDATE users SET kredit = kredit + $1 WHERE id = $2 AND kredit + $1 >= 0 RETURNING id, email, nama, kredit",
    )
    .bind(req.jumlah)
    .bind(req.user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let (uid, email, nama, saldo) =
        row.ok_or_else(|| ApiError::bad("User tidak ditemukan atau saldo akan menjadi negatif."))?;
    let alasan: String = req.alasan.unwrap_or_else(|| "manual".into()).chars().take(100).collect();
    sqlx::query("INSERT INTO kredit_log (user_id, delta, alasan, ref) VALUES ($1, $2, $3, $4)")
        .bind(uid)
        .bind(req.jumlah)
        .bind(alasan)
        .bind(format!("admin#{}", admin.id))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({ "success": true, "saldo": saldo, "email": email, "nama": nama })))
}

#[derive(Deserialize)]
pub struct EksporReq {
    kabupaten: String,
}

/// Dipanggil tepat sebelum ekspor PNG/PDF. Di sinilah kredit dipotong (-1).
/// UPDATE bersyarat (kredit >= biaya) bersifat atomik, jadi request bersamaan tidak bisa
/// membuat saldo negatif maupun memotong dua kali untuk satu klik.
pub async fn cek_ekspor(
    State(pool): State<PgPool>,
    Extension(user): Extension<DbUser>,
    Json(req): Json<EksporReq>,
) -> Result<Json<Value>, ApiError> {
    if user.role == "admin" {
        return Ok(Json(json!({ "ok": true, "kredit": null })));
    }
    let biaya = cost_per_export();
    let mut tx = pool.begin().await?;

    let row: Option<(i32,)> = sqlx::query_as(
        "UPDATE users SET kredit = kredit - $1 WHERE id = $2 AND kredit >= $1 RETURNING kredit",
    )
    .bind(biaya)
    .bind(user.id)
    .fetch_optional(&mut *tx)
    .await?;
    let (sisa,) = row.ok_or_else(|| {
        ApiError(
            StatusCode::PAYMENT_REQUIRED,
            format!("Kredit tidak cukup. Ekspor membutuhkan {biaya} kredit, silakan beli kredit lewat admin terlebih dahulu."),
        )
    })?;

    let ref_kab: String = req.kabupaten.chars().take(100).collect();
    sqlx::query("INSERT INTO kredit_log (user_id, delta, alasan, ref) VALUES ($1, $2, 'ekspor', $3)")
        .bind(user.id)
        .bind(-biaya)
        .bind(ref_kab)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({ "ok": true, "kredit": sisa })))
}