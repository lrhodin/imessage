#[cfg(test)]
mod tests {
    use std::{collections::HashMap, path::PathBuf, str::FromStr};

    use icloud_auth::*;

    #[tokio::test]
    async fn gsa_auth() {
        println!("gsa auth test");
        let email = std::env::var("apple_email").unwrap_or_else(|_| {
            println!("Enter Apple email: ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            input.trim().to_string()
        });

        let password = std::env::var("apple_password").unwrap_or_else(|_| {
            println!("Enter Apple password: ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            input.trim().to_string()
        });

        let appleid_closure = move || (email.clone(), password.clone());
        // ask console for 2fa code, make sure it is only 6 digits, no extra characters
        let tfa_closure = || {
            println!("Enter 2FA code: ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            input.trim().to_string()
        };
        let info = LoginClientInfo {
            ak_context_type: "imessage".to_string(),
            client_app_name: "Messages".to_string(),
            client_bundle_id: "com.apple.MobileSMS".to_string(),
            mme_client_info: "<iPhone7,2> <iPhone OS;12.5.5;16H62> <com.apple.akd/1.0 (com.apple.akd/1.0)>".to_string(),
            mme_client_info_akd: "<iPhone7,2> <iPhone OS;12.5.5;16H62> <com.apple.AuthKit/1 (com.apple.akd/1.0)>".to_string(),
            akd_user_agent: "akd/1.0 CFNetwork/1494.0.7 Darwin/23.4.0".to_string(),
            browser_user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)".to_string(),
            hardware_headers: HashMap::from_iter([]),
            push_token: None,
            update_account_bundle_id: "<iMac13,1> <macOS;13.6.4;22G513> <com.apple.AppleAccount/1.0 (com.apple.systempreferences.AppleIDSettings/1)>".to_string(),
        };
        let acc = AppleAccount::login(appleid_closure, tfa_closure, info.clone(), 
            default_provider(info, PathBuf::from_str("anisette_test").unwrap())).await;

        let account = acc.unwrap();
        println!("data {:?}", account.get_name());
        println!("PET: {}", account.get_pet().unwrap());
        return;
    }
}
