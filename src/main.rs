mod capture;
mod config;
mod control;
mod controlproto;
mod daemon;
mod encryption;
mod endpoint;
mod ethernet;
mod ethertable;
mod eventproto;
mod filedes;
mod forkedworker;
mod handshake;
mod info;
mod keyex;
mod licenses;
mod link;
mod listen;
mod opts;
mod pair;
mod ping;
mod serialwindow;
mod uplink;

use getopts::Options;
use std::env;
use std::process::ExitCode;

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
        socket_dir: "/var/run/meshroute".to_string(),
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
        } else if matches.free[0] == "list-pairing-requests" {
            if matches.free.len() == 2 {
                return pair::run_list_pairing_requests(&meshopts, &matches.free[1]);
            } else {
                print_usage(&program, opts);
                return ExitCode::from(1);
            }
        } else if matches.free[0] == "list-paired" {
            if matches.free.len() == 2 {
                return pair::run_list_paired(&meshopts, &matches.free[1]);
            } else {
                print_usage(&program, opts);
                return ExitCode::from(1);
            }
        } else if matches.free[0] == "accept" {
            if matches.free.len() == 3 {
                return pair::run_accept(&meshopts, &matches.free[1], &matches.free[2]);
            } else {
                print_usage(&program, opts);
                return ExitCode::from(1);
            }
        } else if matches.free[0] == "finish" {
            if matches.free.len() == 3 {
                return pair::run_finish(&meshopts, &matches.free[1], &matches.free[2]);
            } else {
                print_usage(&program, opts);
                return ExitCode::from(1);
            }
        } else if matches.free[0] == "info" {
            if matches.free.len() == 2 {
                return info::run_info(&meshopts, &matches.free[1]);
            } else {
                print_usage(&program, opts);
                return ExitCode::from(1);
            }
        } else if matches.free[0] == "list-links" {
            if matches.free.len() == 2 {
                return link::run_list_links(&meshopts, &matches.free[1]);
            } else {
                print_usage(&program, opts);
                return ExitCode::from(1);
            }
        } else if matches.free[0] == "add-link" {
            if matches.free.len() == 3 {
                return link::run_add_link(&meshopts, &matches.free[1], &matches.free[2]);
            } else {
                print_usage(&program, opts);
                return ExitCode::from(1);
            }
        } else if matches.free[0] == "remove-link" {
            if matches.free.len() == 3 {
                return link::run_remove_link(&meshopts, &matches.free[1], &matches.free[2]);
            } else {
                print_usage(&program, opts);
                return ExitCode::from(1);
            }
        } else if matches.free[0] == "licenses" {
            return licenses::run_licenses();
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
    print!("{}", &brief);
    let brief = format!(" {} [options] listen <name> <addr:port>\n", program);
    print!("{}", &brief);
    let brief = format!(" {} [options] pair <name> <addr:port>\n", program);
    print!("{}", &brief);
    let brief = format!(" {} [options] list-pairing-requests <name>\n", program);
    print!("{}", &brief);
    let brief = format!(" {} [options] list-paired <name>\n", program);
    print!("{}", &brief);
    let brief = format!(" {} [options] pair <name> <addr:port>\n", program);
    print!("{}", &brief);
    let brief = format!(" {} [options] accept <name> <master-key>\n", program);
    print!("{}", &brief);
    let brief = format!(" {} [options] finish <name> <master-key>\n", program);
    print!("{}", &brief);
    let brief = format!(" {} [options] add-link <name> <addr:port>\n", program);
    print!("{}", &brief);
    let brief = format!(" {} [options] remove-link <name> <addr:port>\n", program);
    print!("{}", &brief);
    let brief = format!(" {} [options] list-links <name>\n", program);
    print!("{}", &brief);
    let brief = format!(" {} licenses\n", program);
    print!("{}", opts.usage(&brief));
}
