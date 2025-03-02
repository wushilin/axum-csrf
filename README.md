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
Client has to submit request with `x-csrf-token` header value to be able to submit successfully.

### Retrieving CSRF token:
```html
<script>
        var CSRF_TOKEN = "";
        (function() {
            fetch("/api/csrf")
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`HTTP error! Status: ${response.status}`);
                    }
                    return response.json(); // Convert response to JSON
                })
                .then(data => {
                    console.log("CSRF Token:", data.token);
                    CSRF_TOKEN = data.token;
                    document.getElementById("tokenDisplay").innerText = CSRF_TOKEN;
                })
                .catch(error => console.error("Error fetching CSRF token:", error));
        })();
        /// CSRF_TOKEN can be used
</script>
```

### Submitting the form
```html
        async function submitMyForm(event) {
            event.preventDefault();
            console.log("Submit called");

            const form = event.target;
            const formData = new FormData(form); // Collect form data

            try {
                const response = await fetch(form.action, {
                    method: "POST",
                    headers: {
                        "x-csrf-token": CSRF_TOKEN
                    },
                    body: formData // Send form data
                });

                const result = await response.json(); // Assuming server returns JSON
            } catch (error) {
                console.error("Error:", error);
            }
        }
```

# Your code to verify CSRF code?
Not required. All requests that reaches your code is CSRF validated.


