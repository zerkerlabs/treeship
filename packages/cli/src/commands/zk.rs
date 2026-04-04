use crate::printer::Printer;

/// Show full ZK configuration status.
pub fn setup(printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    printer.blank();
    printer.info("ZK configuration");
    printer.blank();

    // Circom circuits
    #[cfg(feature = "zk")]
    {
        printer.info(&format!("  {} Circom (Groth16)", printer.green("+")));
        printer.info("  circuits:");

        for (name, vk_content) in [
            ("policy-checker", include_bytes!("../../../zk-circom/zkeys/pc_vk.json").as_slice()),
            ("spend-limit-checker", include_bytes!("../../../zk-circom/zkeys/slc_vk.json").as_slice()),
            ("input-output-binding", include_bytes!("../../../zk-circom/zkeys/iob_vk.json").as_slice()),
            ("prompt-template", include_bytes!("../../../zk-circom/zkeys/pt_vk.json").as_slice()),
        ] {
            use sha2::{Sha256, Digest};
            let hash = hex::encode(Sha256::digest(vk_content));
            printer.info(&format!("    {}  vk:{}", name, &hash[..16]));
        }

        // snarkjs check
        let snarkjs_ok = std::process::Command::new("snarkjs")
            .arg("--version")
            .output()
            .is_ok();
        printer.blank();
        if snarkjs_ok {
            printer.info(&format!("  {} snarkjs (proving runtime)", printer.green("+")));
        } else {
            printer.dim_info("  - snarkjs not found (install: npm install -g snarkjs)");
        }

        // RISC Zero
        printer.blank();
        printer.info(&format!("  {} RISC Zero", printer.green("+")));
        printer.info("    guest: compiled");
        printer.info("    prover: local CPU (default)");
        if std::env::var("BONSAI_API_KEY").map_or(false, |k| !k.is_empty()) {
            printer.info("    bonsai: API key detected (fast proving available)");
        } else {
            printer.dim_info("    bonsai: not configured (set BONSAI_API_KEY for fast proving)");
        }
    }

    #[cfg(not(feature = "zk"))]
    {
        printer.dim_info("  ZK features not enabled in this build");
        printer.hint("rebuild with: cargo build -p treeship-cli --features zk");
    }

    // TLSNotary
    printer.blank();
    printer.info("  TLSNotary:");
    if let Ok(notary) = std::env::var("TREESHIP_NOTARY") {
        printer.info(&format!("    notary: {} (configured)", notary));
    } else {
        printer.dim_info("    notary: not configured");
        printer.hint("treeship zk-tls notary setup");
    }

    printer.blank();
    Ok(())
}

/// Print self-hosted TLSNotary setup instructions.
pub fn tls_notary_setup(printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    printer.blank();
    printer.info("Self-hosted TLS notary setup");
    printer.blank();
    printer.info("  Run your own notary (removes PSE trust dependency):");
    printer.blank();
    printer.info("    docker run -p 7047:7047 \\");
    printer.info("      ghcr.io/tlsnotary/tlsn-notary:0.1.0-alpha.14");
    printer.blank();
    printer.info("  Configure Treeship to use it:");
    printer.blank();
    printer.info("    export TREESHIP_NOTARY=localhost:7047");
    printer.blank();
    printer.info("  Or in .treeship/config.yaml:");
    printer.info("    zk_tls:");
    printer.info("      notary: \"localhost:7047\"");
    printer.blank();
    printer.dim_info("  PSE public notary (default): notary.pse.dev:7047");
    printer.dim_info("  Your notary key is used instead of PSE's.");
    printer.dim_info("  Verifiers trust your notary, not a third party.");
    printer.blank();
    Ok(())
}
