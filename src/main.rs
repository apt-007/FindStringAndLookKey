use clap::{Arg, Command};
use openssl::x509::X509;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufRead};
use std::path::Path;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

fn main() {
    let matches = Command::new("1.exe")
        .version("1.0")
        // .author("Your Name <your.email@example.com>")
        .about("集合 find 和 pem 功能的程序")
        .subcommand(
            Command::new("find")
                .about("在指定目录中查找包含关键词的文件")
                .arg(Arg::new("directory").required(true).help("要搜索的目录"))
                .arg(Arg::new("keyword").required(true).help("要搜索的关键词")),
        )
        .subcommand(
            Command::new("pem")
                .about("检查目录中的 .key 和 .pem 文件是否需要密码")
                .arg(Arg::new("directory").required(true).help("要检查的目录")),
        )
        .subcommand(
            Command::new("verify")
                .about("验证目录中的 .pem 和 .key 文件是否匹配")
                .arg(Arg::new("directory").required(true).help("要验证的目录")),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("find") {
        let directory = matches.get_one::<String>("directory").unwrap();
        let keyword = matches.get_one::<String>("keyword").unwrap();
        find(directory, keyword);
    } else if let Some(matches) = matches.subcommand_matches("pem") {
        let directory = matches.get_one::<String>("directory").unwrap();
        check_pem(directory);
    } else if let Some(matches) = matches.subcommand_matches("verify") {
        let directory = matches.get_one::<String>("directory").unwrap();
        verify_keys_and_certs(directory);
    }
}

fn find(directory: &str, keyword: &str) {
    let path = Path::new(directory);
    let mut keyword_paths = HashMap::new();
    if path.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                let files = fs::read_dir(path).unwrap();
                for file in files {
                    let file = file.unwrap();
                    let path = file.path();
                    if path.is_file() {
                        if let Ok(file) = File::open(&path) {
                            let reader = io::BufReader::new(file);
                            for line in reader.lines() {
                                match line {
                                    Ok(line) => {
                                        if line.contains(keyword) {
                                            keyword_paths.insert(path.clone(), line);
                                        }
                                    }
                                    Err(_) => {
                                        // 忽略无法读取的行
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    for (path, line) in keyword_paths {
        println!("Path: {:?}, Line: {}", path.display(), line);
    }
}

fn check_pem(directory: &str) {
    let path = Path::new(directory);
    if path.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_file() {
                if let Some(extension) = path.extension() {
                    if extension == "key" || extension == "pem" {
                        let content = fs::read(&path).expect("Failed to read file");
                        let needs_password = match PKey::private_key_from_pem(&content) {
                            Ok(_) => false,
                            Err(_) => match Rsa::private_key_from_pem(&content) {
                                Ok(_) => false,
                                Err(_) => true,
                            },
                        };
                        if needs_password {
                            println!("需要密码的文件: {:?}", path);
                        }
                    }
                }
            }
        }
    }
}

fn verify_keys_and_certs(directory: &str) {
    let path = Path::new(directory);
    let mut keys = Vec::new();
    let mut certs = Vec::new();

    if path.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_file() {
                if let Some(extension) = path.extension() {
                    if extension == "key" {
                        keys.push(path.clone());
                    } else if extension == "pem" {
                        certs.push(path.clone());
                    }
                }
            }
        }
    }

    for key_path in &keys {
        let key_content = match fs::read(key_path) {
            Ok(content) => content,
            Err(e) => {
                eprintln!("Failed to read key file {:?}: {:?}", key_path, e);
                continue;
            }
        };

        let private_key = match PKey::private_key_from_pem(&key_content) {
            Ok(key) => key,
            Err(_) => match Rsa::private_key_from_pem(&key_content) {
                Ok(rsa) => PKey::from_rsa(rsa).expect("Failed to parse RSA private key"),
                Err(e) => {
                    eprintln!("Failed to parse RSA private key {:?}: {:?}", key_path, e);
                    continue;
                }
            },
        };

        for cert_path in &certs {
            let cert_content = match fs::read(cert_path) {
                Ok(content) => content,
                Err(e) => {
                    eprintln!("Failed to read cert file {:?}: {:?}", cert_path, e);
                    continue;
                }
            };

            match X509::from_pem(&cert_content) {
                Ok(cert) => {
                    if cert.public_key().unwrap().public_eq(&private_key) {
                        println!("匹配成功: 私钥文件: {:?}, 证书文件: {:?}", key_path, cert_path);
                    }
                }
                Err(_) => {
                    // 忽略解析失败的证书
                }
            }
        }
    }
}