use clap::arg_enum;
use structopt::StructOpt;

fn make_xoauth2_token(username: &str, access_token: &str) -> String {
    let value = format!("user={user}{ctrla}auth=Bearer {at}{ctrla}{ctrla}",
        user = username,
        at = access_token,
        ctrla = "\u{0001}",
    );

    let result = base64::encode(value);
    return result;
}

arg_enum! {
    #[derive(Debug)]
    enum AuthMethod {
        Redirect,
        Interactive,
    }
}

arg_enum! {
    #[derive(Debug)]
    enum AuthProvider {
        Google,
        Microsoft,
    }
}

#[derive(Debug, structopt::StructOpt)]
#[structopt(name = "gxt", about = "gxt")]
struct Args {
    #[structopt(short = "u", long = "username")]
    username: String,

    #[structopt(short = "m", long = "auth-method", default_value = "interactive", possible_values = &AuthMethod::variants(), case_insensitive = true)]
    auth_method: AuthMethod,

    #[structopt(short = "s", long = "client-secret-path")]
    client_secret_path: String,

    #[structopt(short = "p", long = "provider", default_value = "google", possible_values = &AuthMethod::variants(), case_insensitive = true)]
    provider: AuthProvider,

    #[structopt(long = "login")]
    login_mode: bool,
}

async fn get_google_access_token(client_secret_path: &str, username: &str, auth_method: AuthMethod, login_mode: bool, xdg_dirs: xdg::BaseDirectories) -> Result<yup_oauth2::AccessToken, ()> {
    let app_secret = yup_oauth2::read_application_secret(client_secret_path)
        .await
        .expect(&format!("failed to read app secret from {}", client_secret_path));

    let alphabet = base32::Alphabet::Crockford{};
    let safe_client_id = base32::encode(alphabet, app_secret.client_id.clone().as_bytes());
    let safe_username = base32::encode(alphabet,username.as_bytes());

    let mut cache_path = xdg_dirs.get_cache_home();
    cache_path.push("token-cache");
    cache_path.push(safe_client_id);
    tokio::fs::create_dir_all(cache_path.as_path()).await.unwrap();
    cache_path.push(safe_username);
    let token_cache_path = cache_path.as_path();

    if tokio::fs::metadata(token_cache_path).await.is_err() && !login_mode {
        println!("You have not authenticated. You need to run this:\n");
        let mut cmd: Vec<String> = std::env::args().collect();
        cmd.push("--login".to_string());
        println!("   {}", cmd.join(" "));
        std::process::exit(-1);
    }

    let method = match auth_method {
        AuthMethod::Redirect =>  yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
        AuthMethod::Interactive =>  yup_oauth2::InstalledFlowReturnMethod::Interactive,
    };
    let authenticator = yup_oauth2::InstalledFlowAuthenticator::builder(app_secret, method)
        .persist_tokens_to_disk(token_cache_path)
        .build()
        .await
        .expect("failed to create authenticator");

    let access_token = authenticator
        .token(&["https://mail.google.com"])
        .await
        .expect("failed to get access_token from cached refresh_token");

    return Ok(access_token);
}

async fn get_microsoft_access_token(client_secret_path: &str, username: &str, auth_method: AuthMethod, login_mode: bool, xdg_dirs: xdg::BaseDirectories) -> Result<yup_oauth2::AccessToken, ()> {
    let app_secret = yup_oauth2::read_application_secret(client_secret_path)
        .await
        .expect(&format!("failed to read app secret from {}", client_secret_path));

    let alphabet = base32::Alphabet::Crockford{};
    let safe_client_id = base32::encode(alphabet, app_secret.client_id.clone().as_bytes());
    let safe_username = base32::encode(alphabet,username.as_bytes());

    let mut cache_path = xdg_dirs.get_cache_home();
    cache_path.push("token-cache");
    cache_path.push(safe_client_id);
    tokio::fs::create_dir_all(cache_path.as_path()).await.unwrap();
    cache_path.push(safe_username);
    let token_cache_path = cache_path.as_path();

    if tokio::fs::metadata(token_cache_path).await.is_err() && !login_mode {
        println!("You have not authenticated. You need to run this:\n");
        let mut cmd: Vec<String> = std::env::args().collect();
        cmd.push("--login".to_string());
        println!("   {}", cmd.join(" "));
        std::process::exit(-1);
    }

    let method = match auth_method {
        AuthMethod::Redirect =>  yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
        AuthMethod::Interactive =>  yup_oauth2::InstalledFlowReturnMethod::Interactive,
    };
    let authenticator = yup_oauth2::InstalledFlowAuthenticator::builder(app_secret, method)
        .persist_tokens_to_disk(token_cache_path)
        .build()
        .await
        .expect("failed to create authenticator");

    let access_token = authenticator
        .token(&["https://mail.google.com"])
        .await
        .expect("failed to get access_token from cached refresh_token");

    return Ok(access_token);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::from_args();
    let xdg_dirs = xdg::BaseDirectories::with_prefix("get-xoauth2-token").unwrap();

    let access_token = match &args.provider {
        AuthProvider::Google => { 
            let token = get_google_access_token(&args.client_secret_path, &args.username, args.auth_method, args.login_mode, xdg_dirs);
            token.await.unwrap().as_str().to_string()
        },
        AuthProvider::Microsoft => { 
            let token = get_microsoft_access_token(&args.client_secret_path, &args.username, args.auth_method, args.login_mode, xdg_dirs);
            token.await.unwrap().as_str().to_string()
        },
    };
    let xoauth_token = make_xoauth2_token(&args.username, &access_token);
    print!("{}", xoauth_token);
    Ok(())
}

#[test]
fn test_xoauth2_one() {
    // go-xoauth2
    let expected = "dXNlcj1hbGljZQFhdXRoPUJlYXJlciBzb21lLWFjY2Vzcy10b2tlbgEB";
    let actual = make_xoauth2_token("alice", "some-access-token");
    assert_eq!(expected, actual);
}
#[test]
fn test_xoauth2_two() {
    // https://developers.google.com/gmail/imap/xoauth2-protocol
    let access_token = "ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg";
    let username = "someuser@example.com";
    let actual = make_xoauth2_token(username, access_token);
    let expected = "dXNlcj1zb21ldXNlckBleGFtcGxlLmNvbQFhdXRoPUJlYXJlciB5YTI5LnZGOWRmdDRxbVRjMk52YjNSbGNrQmhkSFJoZG1semRHRXVZMjl0Q2cBAQ==";
    assert_eq!(expected, actual);
}