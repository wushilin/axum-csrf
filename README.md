# axum-csrf
Simple, automatic CSRF handling for Axum

# Concept
All requests that has no CSRF cookie will get set-cookie header automatically.

All state changing requests (PUT,DELETE,POST,PATCH) will request `x-csrf-header` with a valid header.

The `x-csrf-header` is compared with the request cookie of CSRF header. If not matched, request will be rejected with `401`.

No need to do any other change

# Key feature
1. Fully automated. PUT, DELETE, POST, PATCH requests always has CSRF protection.
2. Resilient. Requests that does not have CSRF cookie will get a new token automatically
3. Easy to use. No need to touch your html. You can use `GET /api/get_csrf_token` to retrieve the token programmatically, and use it forever. It won't change

# How to use
```rust
axum_csrf::set_csrf_token_sign_key("key").await; // default is 32 char auto generated signed key
let app1 = Router::new()
        .route("/admin/endpoint1", get(handle1).post(handle1).put(handle1))
        .route("/api/get_csrf_token", get(axum_csrf::get_csrf_token))
        .layer(session_layer) //optional
        .layer(CookieManagerLayer::new()) //optional
        .route_layer(middleware::from_fn(axum_csrf::csrf_protect));
```

# Your code to verify CSRF code?
Not required. All requests that reaches your code is CSRF validated.


