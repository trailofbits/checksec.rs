use std::process;
use std::path::Path;
use std::fs;

use checksec::{pe, shared, checksec_core, BinResults};

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


// pe32+-related tests
#[test]
fn test_is_pe(){
    let buf = file_to_buf("./tests/binaries/pe/debug_directories-clang_lld.exe.bin".into());
    if let Ok(BinResults::Pe(_)) = checksec_core(&buf) {
    }
    else{
        panic!("Expected Binary to be classified as PE32+");
    }
}

#[test]
fn test_dynamic_base_present(){
    let buf = file_to_buf("./tests/binaries/pe/debug_directories-clang_lld.exe.bin".into());
    if let Ok(BinResults::Pe(pe_result)) = checksec_core(&buf){
        assert_eq!(pe_result.dynamic_base, true);
    }
}

#[test]
fn test_no_dynamic_base(){
    let buf = file_to_buf("./tests/binaries/pe/lld_tls_slot_virtonly.exe.bin".into());
    if let Ok(BinResults::Pe(pe_result)) = checksec_core(&buf){
        assert_eq!(pe_result.dynamic_base, false);
    }
}

#[test]
fn test_aslr_high_entropy(){
    let buf = file_to_buf("./tests/binaries/pe/pegoat-no-cetcompat.exe".into());
    if let Ok(BinResults::Pe(pe_result)) = checksec_core(&buf){
        assert_eq!(pe_result.aslr, pe::ASLR::HighEntropyVa);
    }
}

#[test]
fn test_aslr_wo_high_entropy(){
    let buf = file_to_buf("./tests/binaries/pe/pegoat-no-highentropyva.exe".into());
    if let Ok(BinResults::Pe(pe_result)) = checksec_core(&buf){
        assert_eq!(pe_result.aslr, pe::ASLR::DynamicBase);
    }
}


#[test]
fn test_no_aslr(){
    let buf = file_to_buf("./tests/binaries/pe/pegoat-ineffective-cfg-no-dynamicbase.exe".into());
    if let Ok(BinResults::Pe(pe_result)) = checksec_core(&buf){
        assert_eq!(pe_result.aslr, pe::ASLR::None);
    }
}

#[test]
fn test_high_entropy_present(){
    let buf = file_to_buf("./tests/binaries/pe/pegoat-no-nxcompat.exe".into());
    if let Ok(BinResults::Pe(pe_result)) = checksec_core(&buf){
        assert_eq!(pe_result.high_entropy_va, true);
    }
}

#[test]
fn test_no_high_entropy(){
    let buf = file_to_buf("./tests/binaries/pe/pegoat-no-dynamicbase.exe".into());
    if let Ok(BinResults::Pe(pe_result)) = checksec_core(&buf){
        assert_eq!(pe_result.high_entropy_va, true);
    }
}

#[test]
fn test_no_force_integrity(){
    let buf = file_to_buf("./tests/binaries/pe/pegoat-no-gs.exe".into());
    if let Ok(BinResults::Pe(pe_result)) = checksec_core(&buf){
        assert_eq!(pe_result.force_integrity, false);
    }
}

// TODO: Find a PE that does force integrity

#[test]
fn test_has_isolation(){
    let buf = file_to_buf("./tests/binaries/pe/pegoat-no-gs.exe".into());
    if let Ok(BinResults::Pe(pe_result)) = checksec_core(&buf){
        assert_eq!(pe_result.isolation, true);
    }
}

// TODO: Find a PE that does not have isolation

#[test]
fn test_Nx_present(){
    let buf = file_to_buf("./tests/binaries/pe/well_formed_import.exe.bin".into());
    if let Ok(BinResults::Pe(pe_result)) = checksec_core(&buf){
        assert_eq!(pe_result.nx, true);
    }
}

#[test]
fn test_no_Nx(){
    let buf = file_to_buf("./tests/binaries/pe/pegoat-no-nxcompat.exe".into());
    if let Ok(BinResults::Pe(pe_result)) = checksec_core(&buf){
        assert_eq!(pe_result.nx, false);
    }
}

#[test]
fn test_Seh_present(){
    let buf = file_to_buf("./tests/binaries/pe/pegoat-no-cetcompat.exe".into());
    if let Ok(BinResults::Pe(pe_result)) = checksec_core(&buf){
        assert_eq!(pe_result.seh, true);
    }
}

// TODO: Find a PE that does not have SEH

#[test]
fn test_cfg_present(){
    let buf = file_to_buf("./tests/binaries/pe/pegoat-yes-cfg.exe".into());
    if let Ok(BinResults::Pe(pe_result)) = checksec_core(&buf){
        assert_eq!(pe_result.cfg, true);
    }
}

#[test]
fn test_no_cfg(){
    let buf = file_to_buf("./tests/binaries/pe/pegoat.exe".into());
    if let Ok(BinResults::Pe(pe_result)) = checksec_core(&buf){
        assert_eq!(pe_result.cfg, false);
    }
}

// TODO: Find a PE that has rfg

#[test]
fn test_no_rfg(){
    let buf = file_to_buf("./tests/binaries/pe/pegoat.exe".into());
    if let Ok(BinResults::Pe(pe_result)) = checksec_core(&buf){
        assert_eq!(pe_result.rfg, false);
    }
}

// TODO: Find a PE that has safeseh

#[test]
fn test_no_safeseh(){
    let buf = file_to_buf("./tests/binaries/pe/pegoat.exe".into());
    if let Ok(BinResults::Pe(pe_result)) = checksec_core(&buf){
        assert_eq!(pe_result.safeseh, false);
    }
}

#[test]
fn test_gs_present(){
    let buf = file_to_buf("./tests/binaries/pe/pegoat-yes-cfg.exe".into());
    if let Ok(BinResults::Pe(pe_result)) = checksec_core(&buf){
        assert_eq!(pe_result.gs, true);
    }
}

#[test]
fn test_no_gs(){
    let buf = file_to_buf("./tests/binaries/pe/debug_directories-clang_lld.exe.bin".into());
    if let Ok(BinResults::Pe(pe_result)) = checksec_core(&buf){
        assert_eq!(pe_result.gs, false);
    }
}

#[test]
fn test_authenticode_present(){
    let buf = file_to_buf("./tests/binaries/pe/pegoat-authenticode.exe".into());
    if let Ok(BinResults::Pe(pe_result)) = checksec_core(&buf){
        assert_eq!(pe_result.gs, true);
    }
}

#[test]
fn test_no_authenticode(){
    let buf = file_to_buf("./tests/binaries/pe/pegoat-no-highentropyva.exe".into());
    if let Ok(BinResults::Pe(pe_result)) = checksec_core(&buf){
        assert_eq!(pe_result.gs, true);
    }
}

// TODO: Find a PE that has .NET

#[test]
fn test_no_dotnet(){
    let buf = file_to_buf("./tests/binaries/pe/pegoat.exe".into());
    if let Ok(BinResults::Pe(pe_result)) = checksec_core(&buf){
        assert_eq!(pe_result.dotnet, false);
    }
}

#[test]
fn test_is_cet_compat(){
    let buf = file_to_buf("./tests/binaries/pe/pegoat-cetcompat.exe".into());
    if let Ok(BinResults::Pe(pe_result)) = checksec_core(&buf){
        assert_eq!(pe_result.cet, true);
    }
}

#[test]
fn test_not_cet_compat(){
    let buf = file_to_buf("./tests/binaries/pe/pegoat-ineffective-cfg-no-dynamicbase.exe".into());
    if let Ok(BinResults::Pe(pe_result)) = checksec_core(&buf){
        assert_eq!(pe_result.cet, false);
    }
}




