use clap::Parser;
use proptest::prelude::*;
use sed_key::args::Cli;

proptest! {
    #[test]
    fn clap_never_panics_on_random_args(args in proptest::collection::vec(".*", 0..6)) {
        let _ = Cli::try_parse_from(args);
        // We just care that it never panics or segfaults.
    }
}
