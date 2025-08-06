
use cryptoscan::config::Config;
use cryptoscan::scanner::scan_directory;
use clap::Parser;

fn main() {
    let config = Config::parse();
    scan_directory(&config);
}

