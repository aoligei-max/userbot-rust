use grammers_client::{Client, Config, SignInError, Update, UpdateIter};
use grammers_session::Session;
use std::io::{self, BufRead as _, Write as _};
use tokio::{runtime, task};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const SESSION_FILE: &str = "ubot.session";

fn prompt(message: &str) -> Result<String> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    stdout.write_all(message.as_bytes())?;
    stdout.flush()?;

    let stdin = io::stdin();
    let mut stdin = stdin.lock();

    let mut line = String::new();
    stdin.read_line(&mut line)?;
    Ok(line)
}

async fn async_main() -> Result<()> {
    let api_id = 1054981;
    let api_hash = "341e29114e1bb38d1fda9f1a22b59b28".to_string();
    println!("Connecting to Telegram...");
    let mut client = Client::connect(Config {
        session: Session::load_file_or_create(SESSION_FILE)?,
        api_id,
        api_hash: api_hash.clone(),
        params: Default::default(),
    })
    .await?;
    println!("Connected!!!");

    if !client.is_authorized().await? {
        println!("Signing in...");
        let phone = prompt("Enter your phone number (international format): ")?;
        let token = client.request_login_code(&phone, api_id, &api_hash).await?;
        let code = prompt("Enter the code you received: ")?;
        let signed_in = client.sign_in(&token, &code).await;
        match signed_in {
            Err(SignInError::PasswordRequired(password_token)) => {
                println!("Hint: {:?}", password_token.hint());
                let prompt_message = format!("Enter the password: ");
                let password = prompt(prompt_message.as_str())?;
                client
                    .check_password(password_token, password.trim())
                    .await?;
            }
            Ok(_) => (),
            Err(e) => panic!("{}", e),
        };
        println!("Signed in!");
        
        match client.session().save_to_file(SESSION_FILE) {
            Ok(_) => {}
            Err(e) => {
                println!(
                    "NOTE: failed to save the session, will sign out when done: {}",
                    e
                );
            }
        }
    }

    async fn handle_update(
        _client: Client,
        updates: UpdateIter,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        for update in updates {
            match update {
                Update::NewMessage(message) if !message.outgoing() => {
                    println!(
                        "{:?} says {:?}",
                        message.sender().unwrap().id(),
                        message.text()
                    );
                }
                _ => {}
            }
        }
        Ok(())
    }

    while let Some(updates) = tokio::select! {
        _ = tokio::signal::ctrl_c() => Ok(None),
        result = client.next_updates() => result,
    }? {
        let handle = client.clone();
        task::spawn(async move {
            match handle_update(handle, updates).await {
                Ok(_) => {}
                Err(e) => eprintln!("Error handling updates!: {}", e),
            }
        });
    }

    Ok(())
}

fn main() -> Result<()> {
    runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async_main())
}
