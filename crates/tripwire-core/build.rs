//! napi build glue for the node addon.
fn main() {
    // Only wire up Node-API linking when building the native addon (the `node`
    // feature). Plain `cargo test` builds skip this so the test binary links
    // without Node symbols present.
    if std::env::var("CARGO_FEATURE_NODE").is_ok() {
        napi_build::setup();
    }
}
