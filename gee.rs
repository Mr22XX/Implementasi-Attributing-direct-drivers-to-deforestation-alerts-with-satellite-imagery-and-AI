use axum::{extract::Query, http::StatusCode, Json};
use gcp_auth::{CustomServiceAccount, TokenProvider};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
pub struct GeeQuery {
    pub layer: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct GeeBody {
    /// GeoJSON geometry (Polygon / MultiPolygon) desa terpilih. Kosong = tanpa clip.
    #[serde(default)]
    pub geometry: Option<Value>,
}

pub async fn gee_tiles(
    Query(q): Query<GeeQuery>,
    Json(body): Json<GeeBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let layer = q.layer.unwrap_or_else(|| "elevation".to_string());

    let graph = match layer.as_str() {
        "elevation" => include_str!("../gee/elevation.json"),
        "ndwi" => include_str!("../gee/ndwi.json"),
        "ndvi" => include_str!("../gee/ndvi.json"),
        "bangunan" => include_str!("../gee/bangunan.json"),
        "sungai" => include_str!("../gee/sungai.json"),
        "jalan" => include_str!("../gee/jalan.json"),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "layer tidak dikenal" })),
            ))
        }
    };

    match build_tile_url(graph, body.geometry.as_ref()).await {
        Ok(url) => Ok(Json(json!({ "tileUrl": url }))),
        Err(e) => {
            eprintln!("GEE error ({layer}): {e:#}");
            Err((
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": "gagal membuat tile Earth Engine" })),
            ))
        }
    }
}

/// Membungkus ekspresi GEE dengan Image.clip(geometri desa).
/// Membungkus ekspresi GEE dengan Image.clip(geometri desa).
fn clip_expression(mut expr: Value, geometry: &Value) -> anyhow::Result<Value> {
    let fname = match geometry.get("type").and_then(|t| t.as_str()) {
        Some("Polygon") => "GeometryConstructors.Polygon",
        Some("MultiPolygon") => "GeometryConstructors.MultiPolygon",
        other => anyhow::bail!("tipe geometri tidak didukung: {other:?}"),
    };
    let coords = geometry
        .get("coordinates")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("geometri tanpa coordinates"))?;

    let old_result = expr
        .get("result")
        .and_then(|r| r.as_str())
        .ok_or_else(|| anyhow::anyhow!("ekspresi tanpa field result"))?
        .to_string();

    let clip_id = "__clip_desa";
    let geom_id = "__geom_desa";
    let values = expr
        .get_mut("values")
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| anyhow::anyhow!("ekspresi tanpa field values"))?;

    // Node geometri dibuat lewat konstruktor resmi Earth Engine
    values.insert(
        geom_id.to_string(),
        json!({
            "functionInvocationValue": {
                "functionName": fname,
                "arguments": {
                    "coordinates": { "constantValue": coords },
                    "geodesic": { "constantValue": false },
                    "evenOdd": { "constantValue": true }
                }
            }
        }),
    );

    values.insert(
        clip_id.to_string(),
        json!({
            "functionInvocationValue": {
                "functionName": "Image.clip",
                "arguments": {
                    "input": { "valueReference": old_result },
                    "geometry": { "valueReference": geom_id }
                }
            }
        }),
    );

    expr["result"] = json!(clip_id);
    Ok(expr)
}

async fn build_tile_url(graph_json: &str, clip: Option<&Value>) -> anyhow::Result<String> {
    let key_json = match std::env::var("GEE_SERVICE_ACCOUNT_JSON") {
        Ok(v) => v,
        Err(_) => std::fs::read_to_string("gee-key.json")?,
    };
    let project = std::env::var("GEE_PROJECT_ID")
        .unwrap_or_else(|_| "project-gis-494114".to_string());

    let sa = CustomServiceAccount::from_json(&key_json)?;
    let token = sa
        .token(&["https://www.googleapis.com/auth/earthengine"])
        .await?;
    let mut expression: Value = match serde_json::from_str::<Value>(graph_json.trim())? {
        Value::String(inner) => serde_json::from_str(&inner)?,
        other => other,
    };

    if let Some(geom) = clip {
        if !geom.is_null() {
            expression = clip_expression(expression, geom)?;
        }
    }

    let resp = reqwest::Client::new()
        .post(format!(
            "https://earthengine.googleapis.com/v1/projects/{project}/maps"
        ))
        .bearer_auth(token.as_str())
        .json(&json!({ "expression": expression, "fileFormat": "PNG" }))
        .send()
        .await?;

    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("Earth Engine {status}: {text}");
    }

    let v: Value = serde_json::from_str(&text)?;
    let name = v["name"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("respons tanpa field name: {text}"))?;

    Ok(format!(
        "https://earthengine.googleapis.com/v1/{name}/tiles/{{z}}/{{x}}/{{y}}"
    ))
}