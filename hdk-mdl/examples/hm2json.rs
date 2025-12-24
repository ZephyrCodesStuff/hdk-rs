fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(not(feature = "export"))]
    {
        panic!("The 'export' feature is not enabled for hdk-mdl. Please enable it in Cargo.toml.");
    }

    #[cfg(feature = "export")]
    {
        use std::env;
        use std::fs::File;
        use std::io::{BufWriter, Write};

        use binrw::BinRead;
        use hdk_mdl::Model;

        let mut args = env::args().skip(1);
        let input = args
            .next()
            .expect("Usage: hm2json <input.mdl> [output.json]");
        let output = args.next().unwrap_or_else(|| format!("{}.json", input));

        let mut f = File::open(&input)?;

        // 1. One-shot read: Parses headers, follows pointers, and loads buffers automatically.
        let model: Model = Model::read_be(&mut f)?;

        // 2. Convert to friendly JSON format (decoding raw buffers to floats/u16s)
        let export = model.to_export();

        let outf = File::create(&output)?;
        let mut writer = BufWriter::new(outf);
        serde_json::to_writer_pretty(&mut writer, &export)?;
        writer.flush()?;

        println!("Wrote JSON to {}", output);

        Ok(())
    }
}
