use clap::Parser;
use proptest::prelude::*;
use proptest::test_runner::Config;
use sed_key::args::Cli;

// helper function instead of static
fn quiet_cfg() -> Config {
    Config {
        failure_persistence: None,
        ..Config::default()
    }
}

proptest! {
    #![proptest_config(quiet_cfg())]
    #[test]
    fn clap_never_panics_on_random_args(args in proptest::collection::vec(".*", 0..6)) {
        let _ = Cli::try_parse_from(args);
        // We just care that it never panics or segfaults.
    }
}
