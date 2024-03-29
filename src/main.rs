use std::{
    fs::read_to_string,
    process::exit,
    str::from_utf8,
};

use base64::decode;
use clap::{App, Arg};
use pbkdf2::pbkdf2_simple;

fn main() {
    let matches = App::new("Feather Password Manager")
        .version("1.0")
        .author("Xaeroxe <kieseljake@gmail.com>")
        .about("A CLI interface for Feather Password Files")
        .arg(Arg::with_name("file")
            .short("f")
            .long("file")
            .value_name("FILE")
            .help("The file containing the encrypted passwords")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("password")
            .short("p")
            .long("password")
            .help("The password that was used to encrypt the file given")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("service")
            .short("s")
            .long("service")
            .help("If this argument is present, the program will only print the password for this service.")
            .requires("file")
            .requires("password")
            .takes_value(true))
        .get_matches();
    let file = matches.value_of("file").unwrap(); // Required arg
    let password = matches.value_of("password").unwrap(); // Required arg
    let service = matches.value_of("service");
    match read_to_string(file) {
        Ok(base64_data) => {
            println!("{:?}", pbkdf2_simple(password, 1));
        },
        Err(e) => {
            eprintln!("Error opening file: {}", e);
        }
    }
    println!("File: {:?}, Password: {:?}, Service {:?}", file, password, service);
}
