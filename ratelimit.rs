use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use sqlx::PgPool;

use crate::auth;

// ---- Pengaturan (ubah sesuai selera) ----
// Maksimal 5 request kirim email per IP dalam 15 menit (semua rute pengirim email dihitung bersama).
const BATAS_PER_IP: i32 = 5;
const JENDELA_DETIK: f64 = 15.0 * 60.0;

pub async fn ensure_schema(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS rate_limit (
            kunci  TEXT PRIMARY KEY,
            jumlah INT NOT NULL,
            mulai  TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Bersihkan baris lama (dijalankan saat start)
    sqlx::query("DELETE FROM rate_limit WHERE mulai < now() - interval '1 day'")
        .execute(pool)
        .await?;

    Ok(())
}

/// Menambah hitungan untuk `kunci` secara atomik.
/// Ok(()) bila masih di bawah batas, Err(detik_tunggu) bila sudah melewati batas.
pub async fn cek(
    pool: &PgPool,
    kunci: &str,
    batas: i32,
    jendela_detik: f64,
) -> Result<Result<(), i64>, sqlx::Error> {
    let (jumlah, sisa): (i32, i64) = sqlx::query_as(
        r#"
        INSERT INTO rate_limit (kunci, jumlah, mulai)
        VALUES ($1, 1, now())
        ON CONFLICT (kunci) DO UPDATE SET
            jumlah = CASE
                WHEN rate_limit.mulai < now() - make_interval(secs => $2::float8) THEN 1
                ELSE rate_limit.jumlah + 1
            END,
            mulai = CASE
                WHEN rate_limit.mulai < now() - make_interval(secs => $2::float8) THEN now()
                ELSE rate_limit.mulai
            END
        RETURNING
            jumlah,
            GREATEST(0, CEIL(EXTRACT(EPOCH FROM (mulai + make_interval(secs => $2::float8) - now()))))::bigint
        "#,
    )
    .bind(kunci)
    .bind(jendela_detik)
    .fetch_one(pool)
    .await?;

    if jumlah > batas {
        Ok(Err(sisa.max(1)))
    } else {
        Ok(Ok(()))
    }
}

/// IP klien. Di belakang Vercel/Cloudflare, IP asli ada di header, bukan di koneksi langsung.
pub fn ip_klien(h: &HeaderMap) -> String {
    for nama in ["cf-connecting-ip", "x-real-ip"] {
        if let Some(v) = h.get(nama).and_then(|v| v.to_str().ok()) {
            let v = v.trim();
            if !v.is_empty() {
                return v.to_string();
            }
        }
    }
    if let Some(v) = h.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(pertama) = v.split(',').next() {
            let p = pertama.trim();
            if !p.is_empty() {
                return p.to_string();
            }
        }
    }
    "tidak-diketahui".to_string()
}

pub fn respons_429(detik: i64, pesan: &str) -> Response {
    let mut resp = auth::ApiError(
        StatusCode::TOO_MANY_REQUESTS,
        format!("{pesan} Coba lagi dalam {detik} detik."),
    )
    .into_response();
    if let Ok(v) = HeaderValue::from_str(&detik.to_string()) {
        resp.headers_mut().insert(header::RETRY_AFTER, v);
    }
    resp
}

/// Middleware: batasi request per IP pada rute pengirim email.
pub async fn limit_email(State(pool): State<PgPool>, req: Request, next: Next) -> Response {
    let ip = ip_klien(req.headers());
    let kunci = format!("email-ip:{ip}");

    match cek(&pool, &kunci, BATAS_PER_IP, JENDELA_DETIK).await {
        Ok(Ok(())) => next.run(req).await,
        Ok(Err(detik)) => respons_429(detik, "Terlalu banyak permintaan kode verifikasi."),
        Err(e) => {
            // Gagal membuka akses (fail-open) agar pengguna sah tidak ikut terblokir bila DB bermasalah.
            eprintln!("rate limit error: {e}");
            next.run(req).await
        }
    }
}