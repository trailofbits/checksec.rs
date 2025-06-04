#![warn(clippy::pedantic)]
//! ![checksec](https://raw.githubusercontent.com/etke/checksec.rs/master/resources/checksec.svg?sanitize=true)
//!
//! Checksec is a standalone command line utility and library that provides
//! binary executable security-oriented property checks for `ELF`, `PE`, and
//! `MachO`executables.
//!
//! **Structures**
//!
//! The full checksec results can be retrieved from the implemented
//! `*CheckSecResult` structures for a given binary by passing a
//! [`goblin::Object`](https://docs.rs/goblin/latest/goblin/enum.Object.html)
//! object to the parse method.
//!
//! * [`checksec::elf::CheckSecResults`](crate::elf::CheckSecResults)
//! * [`checksec::macho::CheckSecResults`](crate::macho::CheckSecResults)
//! * [`checksec::pe::CheckSecResults`](crate::pe::CheckSecResults)
//!
//! ```rust
//! use checksec::elf::CheckSecResults as ElfCheckSecResults;
//! use checksec::macho::CheckSecResults as MachOCheckSecResults;
//! use checksec::pe::CheckSecResults as PECheckSecResults;
//! ```
//!
//! **Traits**
//!
//! Add the associated `*Properties` trait to the imports as shown below to
//! have direct access to the security property check functions for a given
//! binary executable format.
//!
//! * [`checksec::elf::Properties`](crate::elf::Properties)
//! * [`checksec::macho::Properties`](crate::macho::Properties)
//! * [`checksec::pe::Properties`](crate::pe::Properties)
//!
//! ```rust
//! use checksec::elf::Properties as ElfProperties;
//! use checksec::macho::Properties as MachOProperties;
//! use checksec::pe::Properties as PEProperties;
//! ```
//!
//! Refer to the generated docs or the examples directory
//! [examples/](https://github.com/etke/checksec.rs/tree/master/examples)
//! for examples of working with both `*Properties` traits and
//! `*CheckSecResults` structs.
//!

use goblin::{error, Object};
use goblin::mach::Mach;

#[cfg(feature = "disassembly")]
pub mod disassembly;
#[cfg(feature = "elf")]
pub mod elf;
#[cfg(target_os = "linux")]
pub mod ldso;
#[cfg(feature = "macho")]
pub mod macho;
pub mod macros;
pub mod output;
#[cfg(feature = "pe")]
pub mod pe;
#[cfg(feature = "shared")]
#[macro_use]
pub mod shared;

pub enum BinResults {
    Elf(elf::CheckSecResults),
    Pe(pe::CheckSecResults),
    Macho(macho::CheckSecResults),
}

pub fn checksec (buffer: &Vec<u8>) -> error::Result<BinResults> {
    match Object::parse(&buffer)? {
        Object::Elf(elf) => {
            let result = elf::CheckSecResults::parse(&elf, &buffer);
            Ok(BinResults::Elf(result))
        },
        Object::PE(pe) => {
            let result = pe::CheckSecResults::parse(&pe, &buffer);
            Ok(BinResults::Pe(result))
        },
        Object::Mach(mach) => match mach {
            Mach::Binary(mach) => {
                let result = macho::CheckSecResults::parse(&mach); 
                Ok(BinResults::Macho(result))
            }
            _ => { Err(error::Error::Malformed("fat binaries currently not supported".into())) }
        },
        _ => {  Err(error::Error::Malformed("unsupported file type".into())) }
    }
}
