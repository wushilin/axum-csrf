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

## dependency
Add the dependency:
```bash
$ cargo add axum-csrf-simple

```

## server side
```rust
/// import as alias (optional)
use axum_csrf_simple as csrf;

/// Set your preferred token signing key. All token is <uuid>-<hmac_signature> format. Invalid tokens won't be trusted.
csrf::set_csrf_token_sign_key("my-signing-key").await; // if not set, the default signing key is 32 char auto generated signed key

let app = Router::new()
        .route("/admin/endpoint1", get(handle1).post(handle1).put(handle1))
        .route("/api/get_csrf_token", get(csrf::get_csrf_token)) // expose the API for your client to retrieve CSRF token. One time only, and it can be cached.
        .route_layer(middleware::from_fn(csrf::csrf_protect));

/// Test accessing /admin/endpoint1 with post, it will require CSRF validation.
```

## client side
Client has to submit request with `x-csrf-token` value to be able to submit successfully.

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fetch CSRF Token</title>
</head>
<body>

    <button onclick="fetchCsrfToken()">Get CSRF Token</button>
    <p id="tokenDisplay">Token will appear here</p>

    <script>
        function fetchCsrfToken() {
            fetch("/api/csrf")
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`HTTP error! Status: ${response.status}`);
                    }
                    return response.json(); // Convert response to JSON
                })
                .then(data => {
                    console.log("CSRF Token:", data.token);
                    document.getElementById("tokenDisplay").innerText = `Token: ${data.token}`;
                })
                .catch(error => console.error("Error fetching CSRF token:", error));
        }
    </script>
    <form action="/admin/endpoint1" method="post">
      <input name="test1"/>
      <button name="submit" value="submit"/>
    </form>
</body>
</html>

```

# Your code to verify CSRF code?
Not required. All requests that reaches your code is CSRF validated.


