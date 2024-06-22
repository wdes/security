#[macro_use]
extern crate rouille;

use rouille::Response;
use std::io;

use hmac::{Hmac, Mac};
use sha2::Sha256;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

// The HTML document of the home page.
static FORM: &str = r#"
<html>
    <head>
        <title>Wdes - snow scanner</title>
    </head>
    <body>
        <form action="/register" method="POST">
            <p><input type="email" name="email" placeholder="Your email" /></p>
            <p><button>Get an API key</button></p>
        </form>
    </body>
</html>
"#;

fn main() {
    println!("Now listening on localhost:8000");

    rouille::start_server("localhost:8000", move |request| {
        router!(request,
            (GET) (/) => {
                rouille::Response::html(FORM)
            },

            (GET) (/ping) => {
                rouille::Response::text("pong")
            },

            (POST) (/register) => {
                let data = try_or_400!(post_input!(request, {
                    email: String,
                }));

                // We just print what was received on stdout. Of course in a real application
                // you probably want to process the data, eg. store it in a database.
                println!("Received data: {:?}", data);


                let mut mac = HmacSha256::new_from_slice(b"my secret and secure key")
                    .expect("HMAC can take key of any size");
                mac.update(data.email.as_bytes());

                // `result` has type `CtOutput` which is a thin wrapper around array of
                // bytes for providing constant time equality check
                let result = mac.finalize();
                // To get underlying array use `into_bytes`, but be careful, since
                // incorrect use of the code value may permit timing attacks which defeats
                // the security provided by the `CtOutput`
                let code_bytes = result.into_bytes();
                rouille::Response::html(format!("Success! <b>{}</a>.", hex::encode(code_bytes)))
            },

            (GET) (/{api_key: String}/scanners/{scanner_name: String}) => {
                let mut mac = HmacSha256::new_from_slice(b"my secret and secure key")
                    .expect("HMAC can take key of any size");

                mac.update(b"williamdes@wdes.fr");

                println!("{}", api_key);
                let hex_key = hex::decode(&api_key).unwrap();
                // `verify_slice` will return `Ok(())` if code is correct, `Err(MacError)` otherwise
                mac.verify_slice(&hex_key).unwrap();

                if let Some(request) = request.remove_prefix(format!("/{}", api_key).as_str()) {
                    // The `match_assets` function tries to find a file whose name corresponds to the URL
                    // of the request. The second parameter (`"."`) tells where the files to look for are
                    // located.
                    // In order to avoid potential security threats, `match_assets` will never return any
                    // file outside of this directory even if the URL is for example `/../../foo.txt`.
                    let response = rouille::match_assets(&request, "../data/");

                    // If a file is found, the `match_assets` function will return a response with a 200
                    // status code and the content of the file. If no file is found, it will instead return
                    // an empty 404 response.
                    // Here we check whether if a file is found, and if so we return the response.
                    if response.is_success() {
                        return response;
                    }
                }
                rouille::Response::empty_404()
            },
            // The code block is called if none of the other blocks matches the request.
            // We return an empty response with a 404 status code.
            _ => rouille::Response::empty_404()
        )
    });
}
