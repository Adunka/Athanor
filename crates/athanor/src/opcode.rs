//! The Cancun opcode set: mnemonics, static gas, and push metadata.
//!
//! Gas here is only the *static* component charged uniformly before an
//! instruction runs (the `W_verylow`-style tiers of Yellow Paper appendix G).
//! Everything data-dependent — memory expansion, cold access, copy words —
//! is computed by the instruction itself.

// 0x00s: stop and arithmetic
pub const STOP: u8 = 0x00;
pub const ADD: u8 = 0x01;
pub const MUL: u8 = 0x02;
pub const SUB: u8 = 0x03;
pub const DIV: u8 = 0x04;
pub const SDIV: u8 = 0x05;
pub const MOD: u8 = 0x06;
pub const SMOD: u8 = 0x07;
pub const ADDMOD: u8 = 0x08;
pub const MULMOD: u8 = 0x09;
pub const EXP: u8 = 0x0a;
pub const SIGNEXTEND: u8 = 0x0b;

// 0x10s: comparison and bitwise
pub const LT: u8 = 0x10;
pub const GT: u8 = 0x11;
pub const SLT: u8 = 0x12;
pub const SGT: u8 = 0x13;
pub const EQ: u8 = 0x14;
pub const ISZERO: u8 = 0x15;
pub const AND: u8 = 0x16;
pub const OR: u8 = 0x17;
pub const XOR: u8 = 0x18;
pub const NOT: u8 = 0x19;
pub const BYTE: u8 = 0x1a;
pub const SHL: u8 = 0x1b;
pub const SHR: u8 = 0x1c;
pub const SAR: u8 = 0x1d;

// 0x20s
pub const KECCAK256: u8 = 0x20;

// 0x30s: environment
pub const ADDRESS: u8 = 0x30;
pub const BALANCE: u8 = 0x31;
pub const ORIGIN: u8 = 0x32;
pub const CALLER: u8 = 0x33;
pub const CALLVALUE: u8 = 0x34;
pub const CALLDATALOAD: u8 = 0x35;
pub const CALLDATASIZE: u8 = 0x36;
pub const CALLDATACOPY: u8 = 0x37;
pub const CODESIZE: u8 = 0x38;
pub const CODECOPY: u8 = 0x39;
pub const GASPRICE: u8 = 0x3a;
pub const EXTCODESIZE: u8 = 0x3b;
pub const EXTCODECOPY: u8 = 0x3c;
pub const RETURNDATASIZE: u8 = 0x3d;
pub const RETURNDATACOPY: u8 = 0x3e;
pub const EXTCODEHASH: u8 = 0x3f;

// 0x40s: block
pub const BLOCKHASH: u8 = 0x40;
pub const COINBASE: u8 = 0x41;
pub const TIMESTAMP: u8 = 0x42;
pub const NUMBER: u8 = 0x43;
pub const PREVRANDAO: u8 = 0x44; // DIFFICULTY before the Merge (EIP-4399)
pub const GASLIMIT: u8 = 0x45;
pub const CHAINID: u8 = 0x46;
pub const SELFBALANCE: u8 = 0x47;
pub const BASEFEE: u8 = 0x48;
pub const BLOBHASH: u8 = 0x49;
pub const BLOBBASEFEE: u8 = 0x4a;

// 0x50s: stack, memory, storage, flow
pub const POP: u8 = 0x50;
pub const MLOAD: u8 = 0x51;
pub const MSTORE: u8 = 0x52;
pub const MSTORE8: u8 = 0x53;
pub const SLOAD: u8 = 0x54;
pub const SSTORE: u8 = 0x55;
pub const JUMP: u8 = 0x56;
pub const JUMPI: u8 = 0x57;
pub const PC: u8 = 0x58;
pub const MSIZE: u8 = 0x59;
pub const GAS: u8 = 0x5a;
pub const JUMPDEST: u8 = 0x5b;
pub const TLOAD: u8 = 0x5c;
pub const TSTORE: u8 = 0x5d;
pub const MCOPY: u8 = 0x5e;

// 0x5f..0x7f: pushes
pub const PUSH0: u8 = 0x5f;
pub const PUSH1: u8 = 0x60;
pub const PUSH32: u8 = 0x7f;

// 0x80s / 0x90s
pub const DUP1: u8 = 0x80;
pub const DUP16: u8 = 0x8f;
pub const SWAP1: u8 = 0x90;
pub const SWAP16: u8 = 0x9f;

// 0xa0s: logging
pub const LOG0: u8 = 0xa0;
pub const LOG1: u8 = 0xa1;
pub const LOG2: u8 = 0xa2;
pub const LOG3: u8 = 0xa3;
pub const LOG4: u8 = 0xa4;

// 0xf0s: system
pub const CREATE: u8 = 0xf0;
pub const CALL: u8 = 0xf1;
pub const CALLCODE: u8 = 0xf2;
pub const RETURN: u8 = 0xf3;
pub const DELEGATECALL: u8 = 0xf4;
pub const CREATE2: u8 = 0xf5;
pub const STATICCALL: u8 = 0xfa;
pub const REVERT: u8 = 0xfd;
pub const INVALID: u8 = 0xfe;
pub const SELFDESTRUCT: u8 = 0xff;

/// Number of immediate bytes following a push, 0 for everything else.
#[inline]
pub const fn push_size(op: u8) -> usize {
    if op >= PUSH1 && op <= PUSH32 {
        (op - PUSH1 + 1) as usize
    } else {
        0
    }
}

/// Static gas tiers, YP appendix G. `0` means the cost is entirely dynamic
/// (or the opcode is undefined — undefined opcodes never reach the charge).
const fn static_gas(op: u8) -> u16 {
    match op {
        STOP | RETURN | REVERT | INVALID => 0,
        // W_base
        ADDRESS | ORIGIN | CALLER | CALLVALUE | CALLDATASIZE | CODESIZE | GASPRICE | COINBASE
        | TIMESTAMP | NUMBER | PREVRANDAO | GASLIMIT | CHAINID | BASEFEE | BLOBBASEFEE
        | RETURNDATASIZE | POP | PC | MSIZE | GAS | PUSH0 => 2,
        // W_verylow
        ADD | SUB | LT | GT | SLT | SGT | EQ | ISZERO | AND | OR | XOR | NOT | BYTE | SHL | SHR
        | SAR | CALLDATALOAD | MLOAD | MSTORE | MSTORE8 | BLOBHASH => 3,
        // W_low
        MUL | DIV | SDIV | MOD | SMOD | SIGNEXTEND | SELFBALANCE => 5,
        // W_mid
        ADDMOD | MULMOD | JUMP => 8,
        // W_high
        JUMPI | EXP => 10,
        JUMPDEST => 1,
        KECCAK256 => 30,
        BLOCKHASH => 20,
        TLOAD | TSTORE => 100, // EIP-1153
        MCOPY | CALLDATACOPY | CODECOPY | RETURNDATACOPY => 3,
        CREATE | CREATE2 => 32000,
        SELFDESTRUCT => 5000,
        _ => {
            if op >= PUSH1 && op <= SWAP16 {
                3 // pushes, dups, swaps
            } else if op >= LOG0 && op <= LOG4 {
                375
            } else {
                0 // fully dynamic (SLOAD, SSTORE, BALANCE, EXTCODE*, calls) or undefined
            }
        }
    }
}

const fn is_defined(op: u8) -> bool {
    matches!(
        op,
        0x00..=0x0b
            | 0x10..=0x1d
            | 0x20
            | 0x30..=0x4a
            | 0x50..=0x9f
            | 0xa0..=0xa4
            | 0xf0..=0xf5
            | 0xfa
            | 0xfd..=0xff
    )
}

const fn build_gas_table() -> [u16; 256] {
    let mut t = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = static_gas(i as u8);
        i += 1;
    }
    t
}

const fn build_defined_table() -> [bool; 256] {
    let mut t = [false; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = is_defined(i as u8);
        i += 1;
    }
    t
}

pub static STATIC_GAS: [u16; 256] = build_gas_table();
pub static DEFINED: [bool; 256] = build_defined_table();

/// Mnemonic for tracing and error messages.
pub fn name(op: u8) -> &'static str {
    match op {
        STOP => "STOP",
        ADD => "ADD",
        MUL => "MUL",
        SUB => "SUB",
        DIV => "DIV",
        SDIV => "SDIV",
        MOD => "MOD",
        SMOD => "SMOD",
        ADDMOD => "ADDMOD",
        MULMOD => "MULMOD",
        EXP => "EXP",
        SIGNEXTEND => "SIGNEXTEND",
        LT => "LT",
        GT => "GT",
        SLT => "SLT",
        SGT => "SGT",
        EQ => "EQ",
        ISZERO => "ISZERO",
        AND => "AND",
        OR => "OR",
        XOR => "XOR",
        NOT => "NOT",
        BYTE => "BYTE",
        SHL => "SHL",
        SHR => "SHR",
        SAR => "SAR",
        KECCAK256 => "KECCAK256",
        ADDRESS => "ADDRESS",
        BALANCE => "BALANCE",
        ORIGIN => "ORIGIN",
        CALLER => "CALLER",
        CALLVALUE => "CALLVALUE",
        CALLDATALOAD => "CALLDATALOAD",
        CALLDATASIZE => "CALLDATASIZE",
        CALLDATACOPY => "CALLDATACOPY",
        CODESIZE => "CODESIZE",
        CODECOPY => "CODECOPY",
        GASPRICE => "GASPRICE",
        EXTCODESIZE => "EXTCODESIZE",
        EXTCODECOPY => "EXTCODECOPY",
        RETURNDATASIZE => "RETURNDATASIZE",
        RETURNDATACOPY => "RETURNDATACOPY",
        EXTCODEHASH => "EXTCODEHASH",
        BLOCKHASH => "BLOCKHASH",
        COINBASE => "COINBASE",
        TIMESTAMP => "TIMESTAMP",
        NUMBER => "NUMBER",
        PREVRANDAO => "PREVRANDAO",
        GASLIMIT => "GASLIMIT",
        CHAINID => "CHAINID",
        SELFBALANCE => "SELFBALANCE",
        BASEFEE => "BASEFEE",
        BLOBHASH => "BLOBHASH",
        BLOBBASEFEE => "BLOBBASEFEE",
        POP => "POP",
        MLOAD => "MLOAD",
        MSTORE => "MSTORE",
        MSTORE8 => "MSTORE8",
        SLOAD => "SLOAD",
        SSTORE => "SSTORE",
        JUMP => "JUMP",
        JUMPI => "JUMPI",
        PC => "PC",
        MSIZE => "MSIZE",
        GAS => "GAS",
        JUMPDEST => "JUMPDEST",
        TLOAD => "TLOAD",
        TSTORE => "TSTORE",
        MCOPY => "MCOPY",
        PUSH0 => "PUSH0",
        CREATE => "CREATE",
        CALL => "CALL",
        CALLCODE => "CALLCODE",
        RETURN => "RETURN",
        DELEGATECALL => "DELEGATECALL",
        CREATE2 => "CREATE2",
        STATICCALL => "STATICCALL",
        REVERT => "REVERT",
        INVALID => "INVALID",
        SELFDESTRUCT => "SELFDESTRUCT",
        op if (PUSH1..=PUSH32).contains(&op) => "PUSH",
        op if (DUP1..=DUP16).contains(&op) => "DUP",
        op if (SWAP1..=SWAP16).contains(&op) => "SWAP",
        op if (LOG0..=LOG4).contains(&op) => "LOG",
        _ => "UNDEFINED",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_sizes() {
        assert_eq!(push_size(PUSH0), 0);
        assert_eq!(push_size(PUSH1), 1);
        assert_eq!(push_size(PUSH32), 32);
        assert_eq!(push_size(ADD), 0);
    }

    #[test]
    fn table_spot_checks() {
        assert_eq!(STATIC_GAS[ADD as usize], 3);
        assert_eq!(STATIC_GAS[MUL as usize], 5);
        assert_eq!(STATIC_GAS[JUMPDEST as usize], 1);
        assert_eq!(STATIC_GAS[KECCAK256 as usize], 30);
        assert_eq!(STATIC_GAS[CREATE as usize], 32000);
        assert_eq!(STATIC_GAS[LOG0 as usize], 375);
        assert_eq!(STATIC_GAS[DUP1 as usize], 3);
        assert!(DEFINED[PUSH32 as usize]);
        assert!(!DEFINED[0x0c]);
        assert!(!DEFINED[0xf6]);
    }
}
