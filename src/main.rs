use clap::{Arg, Command};
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
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("find") {
        let directory = matches.get_one::<String>("directory").unwrap();
        let keyword = matches.get_one::<String>("keyword").unwrap();
        find(directory, keyword);
    } else if let Some(matches) = matches.subcommand_matches("pem") {
        let directory = matches.get_one::<String>("directory").unwrap();
        check_pem(directory);
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