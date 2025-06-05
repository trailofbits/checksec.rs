use std::process;
use std::path::Path;
use std::fs;

use checksec::{elf, shared, checksec_core, BinResults};

// util function to convert file contents to buffer of bytes
fn file_to_buf(filename: String) -> Vec<u8>{
    let path = Path::new(&filename);
    if let Ok(buf) = fs::read(path){
        return buf;
    }
    else{
        println!("reading of provided file path failed, test suite is misconfigured");
        process::exit(1)
    }
}


// Elf-related tests
#[test]
fn test_is_elf(){
    let buf = file_to_buf("./tests/binaries/elf/fszero".into());
    if let Ok(BinResults::Elf(_elf_result)) = checksec_core(&buf) {
    }
    else{
        panic!("Expected Binary to be classified as Elf");
    }
}

#[test]
fn test_w_canary(){
    let buf = file_to_buf("./tests/binaries/elf/all_cl".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        assert_eq!(elf_result.canary, true);
    }
}

#[test]
fn test_w_no_canary(){
    let buf = file_to_buf("./tests/binaries/elf/cfi".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        assert_eq!(elf_result.canary, false);
    }
}

#[test]
fn test_partial_relro(){
    let buf = file_to_buf("./tests/binaries/elf/cfi".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        assert_eq!(elf_result.relro, elf::Relro::Partial);
    }
}

#[test]
fn test_no_relro(){
    let buf = file_to_buf("./tests/binaries/elf/nolibc_cl".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        assert_eq!(elf_result.relro, elf::Relro::None);
    }
}

#[test]
fn test_full_relro(){
    let buf = file_to_buf("./tests/binaries/elf/rpath".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        assert_eq!(elf_result.relro, elf::Relro::Full);
    }
}

#[test]
fn test_PIE_enabled(){
    let buf = file_to_buf("./tests/binaries/elf/partial".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        assert_eq!(elf_result.pie, elf::PIE::PIE);
    }
}

#[test]
fn test_PIE_DSO(){
    let buf = file_to_buf("./tests/binaries/elf/dso.so".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        assert_eq!(elf_result.pie, elf::PIE::DSO);
    }
}

#[test]
fn test_PIE_REL(){
    let buf = file_to_buf("./tests/binaries/elf/rel.o".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        assert_eq!(elf_result.pie, elf::PIE::REL);
    }
}

#[test]
fn test_PIE_none(){
    let buf = file_to_buf("./tests/binaries/elf/nolibc".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        assert_eq!(elf_result.pie, elf::PIE::None);
    }
}

#[test]
fn test_fortify_na(){
    let buf = file_to_buf("./tests/binaries/elf/nolibc".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        assert_eq!(elf_result.fortify, elf::Fortify::Undecidable);
        assert_eq!(elf_result.fortified, 0);
        assert_eq!(elf_result.fortifiable, 0);
    }
}

#[test]
fn test_fortify_no(){
    let buf = file_to_buf("./tests/binaries/elf/sstack".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        assert_eq!(elf_result.fortify, elf::Fortify::None);
        assert_eq!(elf_result.fortified, 0);
        assert_eq!(elf_result.fortifiable, 3);
    }
}

#[test]
fn test_fortify_partial(){
    let buf = file_to_buf("./tests/binaries/elf/partial".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        assert_eq!(elf_result.fortify, elf::Fortify::Partial);
        assert_eq!(elf_result.fortified, 1);
        assert_eq!(elf_result.fortifiable, 2);
    }
}

#[test]
fn test_fortify_full(){
    let buf = file_to_buf("./tests/binaries/elf/rpath".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        assert_eq!(elf_result.fortify, elf::Fortify::Full);
        assert_eq!(elf_result.fortified, 2);
        assert_eq!(elf_result.fortifiable, 2);
    }
}

#[test]
fn test_nx_Na(){
    let buf = file_to_buf("./tests/binaries/elf/rel.o".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        assert_eq!(elf_result.nx, elf::Nx::Na);
    }
}

#[test]
fn test_nx_disabled(){
    let buf = file_to_buf("./tests/binaries/elf/none".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        assert_eq!(elf_result.nx, elf::Nx::Disabled);
    }
}

#[test]
fn test_nx_enabled(){
    let buf = file_to_buf("./tests/binaries/elf/fszero".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        assert_eq!(elf_result.nx, elf::Nx::Enabled);
    }
}

#[test]
fn test_rpath_exists(){
    let buf = file_to_buf("./tests/binaries/elf/rpath".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        let rpath_val = shared::Rpath::Yes("./".into());
        let rpath_vec = shared::VecRpath::new(vec![rpath_val.clone()]);
        assert_eq!(elf_result.rpath.len(), rpath_vec.len());
        assert_eq!(elf_result.rpath[0], rpath_val);
    }
}

#[test]
fn test_rpath_none(){
    let buf = file_to_buf("./tests/binaries/elf/fszero".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        let rpath_val = shared::Rpath::None;
        let rpath_vec = shared::VecRpath::new(vec![rpath_val.clone()]);
        assert_eq!(elf_result.rpath.len(), rpath_vec.len());
        assert_eq!(elf_result.rpath[0], rpath_val);
    }
}

#[test]
fn test_runpath_exists(){
    let buf = file_to_buf("./tests/binaries/elf/runpath".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        let runpath_val = shared::Rpath::Yes("./".into());
        let runpath_vec = shared::VecRpath::new(vec![runpath_val.clone()]);
        assert_eq!(elf_result.rpath.len(), runpath_vec.len());
        assert_eq!(elf_result.runpath[0], runpath_val);
    }
}

#[test]
fn test_runpath_none(){
    let buf = file_to_buf("./tests/binaries/elf/sstack".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        let runpath_val = shared::Rpath::None;
        let runpath_vec = shared::VecRpath::new(vec![runpath_val.clone()]);
        assert_eq!(elf_result.rpath.len(), runpath_vec.len());
        assert_eq!(elf_result.runpath[0], runpath_val);
    }
}

#[test]
fn test_symbol_count(){
    let buf = file_to_buf("./tests/binaries/elf/sstack".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        assert_eq!(*elf_result.symbol_count, 87);
    }
}

#[test]
fn test_no_symbols(){
    let buf = file_to_buf("./tests/binaries/elf/all".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        assert_eq!(*elf_result.symbol_count, 0);
    }
}

#[test]
fn test_clang_cfi_exists(){
    let buf = file_to_buf("./tests/binaries/elf/cfi".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        assert_eq!(elf_result.clang_cfi, true);
    }
}

#[test]
fn test_no_clang_cfi(){
    let buf = file_to_buf("./tests/binaries/elf/dso.so".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        assert_eq!(elf_result.clang_cfi, false);
    }
}

#[test]
fn test_clang_safestack_exists(){
    let buf = file_to_buf("./tests/binaries/elf/sstack".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        assert_eq!(elf_result.clang_safestack, true);
    }
}

#[test]
fn test_no_clang_safestack(){
    let buf = file_to_buf("./tests/binaries/elf/partial".into());
    if let Ok(BinResults::Elf(elf_result)) = checksec_core(&buf){
        assert_eq!(elf_result.clang_safestack, false);
    }
}

//TODO: Add further testing for stack clash?




