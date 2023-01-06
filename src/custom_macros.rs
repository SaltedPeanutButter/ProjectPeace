#[macro_export]
macro_rules! error_with_code {
    ($c: expr) => {
        {
            error!("Error code: {}. See https://thaibinh.me/ProjectPeace/help?code={}", $c, $c);
            exit($c);
        }
    };
}

#[macro_export]
macro_rules! clear {
    () => {
        {
            print!("\x1B[2J\x1B[1;1H");
        };
    };
}

#[macro_export]
macro_rules! input {
    () => {
        {
            let mut temp_str = String::new();
            std::io::stdin().read_line(&mut temp_str).expect("Failed to read lines!");
            temp_str.trim().to_owned()
        }
    };

    ($c: expr) => {
        {
            print!($c);
            std::io::stdout().flush().unwrap();
            let mut temp_str = String::new();
            std::io::stdin().read_line(&mut temp_str).expect("Failed to read lines!");
            temp_str.trim().to_owned()
        }
    };
}