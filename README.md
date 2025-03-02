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
csrf::set_csrf_secure_cookie_enable(true); // set to true to only transfer cookie over https (for dev, set to false - which is the default)

let app = Router::new()
        .route("/admin/endpoint1", get(handle1).post(handle1).put(handle1))
        .route("/api/get_csrf_token", get(csrf::get_csrf_token)) // expose the API for your client to retrieve CSRF token. One time only, and it can be cached.
        .route_layer(middleware::from_fn(csrf::csrf_protect));

/// Test accessing /admin/endpoint1 with post, it will require CSRF validation.
```

Note the exposing of `/api/get_csrf_token` API uri can be customized based on your need.

## client side
Client has to submit request with `x-csrf-token` header value to be able to submit successfully.

### Retrieving CSRF token
Example using plain javascript. 

It is pretty easy to write for react, angular, nodejs.

The result payload of the `/api/get_csrf_token` is like

```json
{"token":"xzP14JrA9qHFaLwKHpFYYj-a209dda82c379b55542b4ed2f977e5464be79b8b7f2009ecb08d36b92599b13f","is_new":false}
```

token: The token
is_new: Tells if the server did create a new token for client

The token can't be used across servers with different signature key.

When requesting the token, server automatically set a cookie csrf_token.

```html
<script>
        var CSRF_TOKEN = "";
        (function() {
            fetch("/api/get_csrf_token")
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`HTTP error! Status: ${response.status}`);
                    }
                    return response.json(); // Convert response to JSON
                })
                .then(data => {
                    console.log("CSRF Token:", data.token);
                    CSRF_TOKEN = data.token; /// now we can reuse the token
                })
                .catch(error => console.error("Error fetching CSRF token:", error));
        })();
        /// CSRF_TOKEN can be used
</script>
```

### Submitting the form using fetch or other AJAX library
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
                        "x-csrf-token": CSRF_TOKEN // set the token
                    },
                    body: formData // Send form data
                });

                const result = await response.json(); // Assuming server returns JSON
            } catch (error) {
                console.error("Error:", error);
            }
        }
```

Note that this is very suitable for AJAX based submission. For normal submission, you will need to append a query string `csrf_token=xxx` to the POST URL.

### Normal submit via query string
This is not preferred as it is less secure in general, but you can use if you have no choice.

```html
<script>
async function submitMyForm(event) {
            event.target.action = event.target.action + "?csrf_token=" + CSRF_TOKEN + "&other=aaa"; /// Append the CSRF token
            return;
</script>
```

# Your code to verify CSRF code?
Not required. All requests that reaches your code is CSRF validated.


