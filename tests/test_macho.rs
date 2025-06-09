use std::process;
use std::path::Path;
use std::fs;

use checksec::{macho, shared, checksec_core, BinResults};

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


// Mach-O related tests
#[test]
fn test_is_macho(){
    let buf = file_to_buf("./tests/binaries/Mach-O/basic".into());
    if let Ok(BinResults::Macho(_)) = checksec_core(&buf) {
    }
    else{
        panic!("Expected Binary to be classified as PE32+");
    }
}

#[test]
fn test_has_PIE(){
    let buf = file_to_buf("./tests/binaries/Mach-O/basic".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.pie, true);
    }
}

#[test]
fn test_no_PIE(){
    let buf = file_to_buf("./tests/binaries/Mach-O/rel_cl.o".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.pie, false);
    }
}

#[test]
fn test_has_arc(){
    let buf = file_to_buf("./tests/binaries/Mach-O/arc_enabled".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.arc, true);
    }
}

#[test]
fn test_no_arc(){
    let buf = file_to_buf("./tests/binaries/Mach-O/no_canary".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.arc, false);
    }
}

#[test]
fn test_has_canary(){
    let buf = file_to_buf("./tests/binaries/Mach-O/basic".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.canary, true);
    }
}

#[test]
fn test_no_canary(){
    let buf = file_to_buf("./tests/binaries/Mach-O/no_canary".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.canary, false);
    }
}

#[test]
fn test_has_codesig(){
    let buf = file_to_buf("./tests/binaries/Mach-O/arc_enabled".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.code_signature, true);
    }
}

#[test]
fn test_no_codesig(){
    let buf = file_to_buf("./tests/binaries/Mach-O/nosig".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.code_signature, false);
    }
}

// TODO: Find a binary that has encryption

#[test]
fn test_not_encrypted(){
    let buf = file_to_buf("./tests/binaries/Mach-O/nosig".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.code_signature, false);
    }
}

#[test]
fn test_has_fortify(){
    let buf = file_to_buf("./tests/binaries/Mach-O/basic".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.fortify, true);
    }
}

#[test]
fn test_fortified_count(){
    let buf = file_to_buf("./tests/binaries/Mach-O/basic".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.fortified, 1);
    }
}


#[test]
fn test_not_fortified(){
    let buf = file_to_buf("./tests/binaries/Mach-O/no_fortify".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.fortify, false);
    }
}


#[test]
fn test_NX_stack(){
    let buf = file_to_buf("./tests/binaries/Mach-O/basic".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.nx_stack, true);
    }
}

// TODO: Find a binary with executable stack

#[test]
fn test_X_heap(){
    let buf = file_to_buf("./tests/binaries/Mach-O/basic".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.nx_heap, false);
    }
}

// TODO: Find a binary with non-executable heap

#[test]
fn test_no_restrict(){
    let buf = file_to_buf("./tests/binaries/Mach-O/basic".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.restrict, false);
    }
}

#[test]
fn test_restricted(){
    let buf = file_to_buf("./tests/binaries/Mach-O/restrict".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        assert_eq!(macho_result.restrict, true);
    }
}

#[test]
fn test_no_rpath(){
    let buf = file_to_buf("./tests/binaries/Mach-O/restrict".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        let runpath_vec = shared::VecRpath::new(vec![shared::Rpath::None]);
        assert_eq!(macho_result.rpath.len(), runpath_vec.len());
        assert_eq!(macho_result.rpath[0], shared::Rpath::None);
    }
}

#[test]
fn test_rpath(){
    let buf = file_to_buf("./tests/binaries/Mach-O/runpaths".into());
    if let Ok(BinResults::Macho(macho_result)) = checksec_core(&buf){
        let runpath_vec = shared::VecRpath::new(vec![shared::Rpath::Yes("@executable_path/lib".into()), shared::Rpath::Yes("./src".into())]);
        assert_eq!(macho_result.rpath.len(), runpath_vec.len());
        assert_eq!(macho_result.rpath[0], shared::Rpath::Yes("@executable_path/lib".into()));
        assert_eq!(macho_result.rpath[1], shared::Rpath::Yes("./src".into()));
    }
}













