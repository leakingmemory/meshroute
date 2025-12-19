mod daemon;
mod opts;
mod controlproto;
mod ping;
mod control;
mod config;
mod keyex;
mod filedes;
mod forkedworker;
mod eventproto;
mod ethernet;
mod ethertable;
mod capture;
mod listen;
mod handshake;
mod pair;

use std::env;
use std::process::ExitCode;
use getopts::Options;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optopt("d", "config-dir", "config directory", "DIR");
    opts.optopt("s", "socket-dir", "control socket directory", "DIR");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(_) => {
            print_usage(&program, opts);
            return ExitCode::from(1);
        }
    };
    let mut meshopts = opts::Opts {
        config_dir: "/var/lib/meshroute".to_string(),
        socket_dir: "/var/run/meshroute".to_string()
    };
    if matches.opt_present("d") {
        meshopts.config_dir = matches.opt_str("d").unwrap();
    }
    if matches.opt_present("s") {
        meshopts.socket_dir = matches.opt_str("s").unwrap();
    }
    if matches.free.len() >= 1 {
        if matches.free[0] == "daemon" {
            if matches.free.len() == 2 {
                return daemon::run_daemon(&meshopts, &matches.free[1]);
            }
        } else if matches.free[0] == "ping" {
            return ping::run_ping(&meshopts, &matches.free[1]);
        } else if matches.free[0] == "capture" {
            return capture::run_capture(&meshopts, &matches.free[1]);
        } else if matches.free[0] == "listen" {
            if matches.free.len() == 3 {
                return listen::run_listen(&meshopts, &matches.free[1], &matches.free[2]);
            } else {
                print_usage(&program, opts);
                return ExitCode::from(1);
            }
        } else if matches.free[0] == "pair" {
            if matches.free.len() == 3 {
                return pair::run_pair(&meshopts, &matches.free[1], &matches.free[2]);
            } else {
                print_usage(&program, opts);
                return ExitCode::from(1);
            }
        } else {
            print_usage(&program, opts);
            return ExitCode::from(1);
        }
    } else {
        print_usage(&program, opts);
        return ExitCode::from(1);
    }
    ExitCode::from(0)
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage:\n {} [options] daemon <name>\n", program);
    print!("{}", opts.usage(&brief));
    let brief = format!("Usage:\n {} [options] listen <name> <addr:port>\n", program);
    print!("{}", opts.usage(&brief));
    let brief = format!("Usage:\n {} [options] pair <name> <addr:port>\n", program);
    print!("{}", opts.usage(&brief));
}
