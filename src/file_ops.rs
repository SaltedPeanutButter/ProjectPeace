use flate2::{
    Compression,
    write::GzEncoder,
};
use std::{path::PathBuf, fs::{File, self}, io::Write};
use tar::Archive;
use walkdir;

use crate::crypto;

const COMPRESSED_TARBALL_NAME: &str = "storage.tar.gz";
const ENCRYPTED_FILE_SUFFIX: &str = "enc";

pub fn commit(repo_dir: &PathBuf, storage_dir: &PathBuf, cipher: &mut crypto::CryptoMachine)  {
    // Calculate prefix
    let prefix = repo_dir.parent().unwrap();
    assert_eq!(prefix, storage_dir.parent().unwrap());

    // Wall through individual files in the storage dir
    for entry in walkdir::WalkDir::new(storage_dir).into_iter().filter_map(|e| e.ok()) {
        let mut entry = entry.into_path();

        // Skip all non-files
        if !entry.is_file() { continue; }

        // Skip files with encrypted suffix
        if entry.extension().unwrap().to_str().unwrap() == ENCRYPTED_FILE_SUFFIX { continue; }

        // Read content of file into buffer
        let buffer = fs::read(entry.clone()).unwrap();

        // Encrypt the buffer
        let buffer = cipher.encrypt(&buffer).unwrap();

        // Delete file
        fs::remove_file(entry.clone()).unwrap();

        // Change filename
        let filename = entry.file_name().unwrap().to_str().unwrap();
        let filename = filename.to_string() + "." + ENCRYPTED_FILE_SUFFIX;
        entry.set_file_name(filename);

        // Write buffer back to file
        fs::write(entry, buffer).unwrap();
   }

   // Add the entire storage dir into archive
   let mut tarball = tar::Builder::new(Vec::new());
   tarball.append_dir_all(storage_dir.file_name().unwrap(), storage_dir).unwrap();
   
   // Compress tar ball
   let encoder = repo_dir.join(COMPRESSED_TARBALL_NAME);
   let encoder = File::open(encoder).unwrap();
   let mut encoder = GzEncoder::new(encoder, Compression::default());
   encoder.write_all(&tarball.into_inner().unwrap()[..]).unwrap();
   encoder.try_finish().unwrap()
}