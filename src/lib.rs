// https://webassembly.github.io/spec

use nom::bytes::streaming::tag;
use nom::combinator::map;
use nom::multi::count;
use nom::number::streaming::{le_u32, le_u8};
use nom::sequence::pair;
use nom::*;

type ParseResult<'a, T> =
    std::result::Result<(T, WasmModule<'a>), nom::Err<(T, nom::error::ErrorKind)>>;

pub fn parse(bytes: &[u8]) -> ParseResult<&[u8]> {
    let (s, _) = magic_number(bytes)?;
    let (s, version) = version(s)?;
    println!("did version");
    let (s, types) = type_section(s)?;
    println!("did type section");
    let (s, functions) = function_section(s)?;
    println!("did function section");
    let (s, tables) = table_section(s)?;
    println!("did table section");
    let (s, memories) = memory_section(s)?;
    println!("did memory section");
    let (s, exports) = export_section(s)?;

    Ok((
        s,
        WasmModule {
            version,
            types,
            functions,
            tables,
            memories,
            exports,
        },
    ))
}

#[derive(Clone, Debug)]
pub struct WasmModule<'a> {
    version: u32,
    types: TypeSection,
    functions: FunctionSection,
    tables: TableSection,
    memories: MemorySection,
    exports: ExportSection<'a>,
}

#[derive(Clone, Debug)]
pub struct TypeSection {
    function_types: Vec<FunctionType>,
}

#[derive(Clone, Debug)]
pub struct FunctionSection {
    functions: Vec<u32>,
}

#[derive(Clone, Debug)]
pub struct FunctionType {
    parameter_types: Vec<ValType>,
    result_types: Vec<ValType>,
}

#[derive(Clone, Debug)]
pub struct TableSection {
    tables: Vec<Table>,
}

#[derive(Clone, Debug)]
pub struct Table {
    r#type: FuncRef,
    limits: Limits,
}

#[derive(Clone, Debug)]
pub struct Limits {
    min: u32,
    max: Max,
}

#[derive(Clone, Debug)]
pub enum Max {
    Number(u32),
    E,
}

#[derive(Clone, Debug, PartialEq)]
enum ValType {
    I32,
    I64,
    F32,
    F64,
}

#[derive(Clone, Debug)]
struct FuncRef();

#[derive(Clone, Debug)]
pub struct MemorySection {
    memories: Vec<Memory>,
}

#[derive(Clone, Debug)]
pub struct Memory {
    limits: Limits,
}

#[derive(Clone, Debug)]
pub struct ExportSection<'a> {
    exports: Vec<Export<'a>>,
}

#[derive(Clone, Debug)]
pub struct Export<'a> {
    name: &'a str,
    desc: ExportDesc,
}

#[derive(Clone, Debug)]
pub enum ExportDesc {
    FuncIdx(u32),
    TableIdx(u32),
    MemIdx(u32),
    GlobalIdx(u32),
}

fn byte_to_type(byte: u8) -> ValType {
    match byte {
        0x7F => ValType::I32,
        0x7E => ValType::I64,
        0x7D => ValType::F32,
        0x7C => ValType::F64,
        _ => panic!("Invalid type"),
    }
}

fn magic_number(s: &[u8]) -> IResult<&[u8], ()> {
    let magic_bytes = b"\0asm";
    let (s, _) = tag(magic_bytes)(s)?;
    Ok((s, ()))
}

fn version(s: &[u8]) -> IResult<&[u8], u32> {
    let (s, version) = le_u32(s)?;
    Ok((s, version))
}

fn type_section(s: &[u8]) -> IResult<&[u8], TypeSection> {
    let (s, _section_id) = le_u8(s)?;
    let (s, _section_length_bytes) = leb_128_u32(s)?;
    let (s, vec_length) = leb_128_u32(s)?;
    // followed by encoding of the element sequence
    let (s, function_types) = count(function_type, vec_length as usize)(s)?;
    let type_section = TypeSection { function_types };
    println!("TS: {:?}", type_section);
    Ok((s, type_section))
}

fn function_type(s: &[u8]) -> IResult<&[u8], FunctionType> {
    let (s, b) = le_u8(s)?;
    assert_eq!(b, 0x60);
    let (s, parameter_type_length) = leb_128_u32(s)?;
    let (s, parameter_types) = count(map(le_u8, byte_to_type), parameter_type_length as usize)(s)?;
    let (s, result_type_length) = leb_128_u32(s)?;
    let (s, result_types) = count(map(le_u8, byte_to_type), result_type_length as usize)(s)?;
    Ok((
        s,
        FunctionType {
            parameter_types,
            result_types,
        },
    ))
}

fn function_section(s: &[u8]) -> IResult<&[u8], FunctionSection> {
    let (s, _section_id) = le_u8(s)?;
    let (s, _section_length_bytes) = leb_128_u32(s)?;
    let (s, vec_length) = leb_128_u32(s)?;
    let mut type_indices = vec![];
    let mut s_and_index: (&[u8], u32) = (s, 0);

    for _i in 0..vec_length {
        s_and_index = leb_128_u32(s)?;
        let (_, this_index) = s_and_index;
        type_indices.push(this_index);
    }

    Ok((
        s_and_index.0,
        FunctionSection {
            functions: type_indices,
        },
    ))
}

fn table_section(s: &[u8]) -> IResult<&[u8], TableSection> {
    let (s, section_id) = le_u8(s)?;
    assert_eq!(section_id, 4);
    let (s, _section_length_bytes) = leb_128_u32(s)?;
    let (s, vec_length) = leb_128_u32(s)?;

    let (s, tables) = count(
        map(pair(le_u8, limits), |(funcref, limits)| {
            assert_eq!(funcref, 0x70);
            Table {
                r#type: FuncRef(),
                limits,
            }
        }),
        vec_length as usize,
    )(s)?;

    Ok((s, TableSection { tables }))
}

fn memory_section(s: &[u8]) -> IResult<&[u8], MemorySection> {
    let (s, section_id) = le_u8(s)?;
    assert_eq!(section_id, 5);
    let (s, _section_length_bytes) = leb_128_u32(s)?;
    let (s, vec_length) = leb_128_u32(s)?;

    let (s, memories) = count(map(limits, |limits| Memory { limits }), vec_length as usize)(s)?;

    Ok((s, MemorySection { memories }))
}

fn export_section(s: &[u8]) -> IResult<&[u8], ExportSection> {
    let (s, section_id) = le_u8(s)?;
    assert_eq!(section_id, 7);
    let (s, _section_length_bytes) = leb_128_u32(s)?;
    let (s, vec_length) = leb_128_u32(s)?;
    let (s, exports) = count(export, vec_length as usize)(s)?;

    Ok((s, ExportSection { exports }))
}

fn export(s: &[u8]) -> IResult<&[u8], Export> {
    let (s, name) = name(s)?;
    let (s, desc_kind_byte) = le_u8(s)?;
    let (s, idx) = leb_128_u32(s)?;
    let desc = desc(desc_kind_byte, idx);
    Ok((s, Export { name, desc }))
}

fn desc(desc_kind_byte: u8, idx: u32) -> ExportDesc {
    match desc_kind_byte {
        0x00 => ExportDesc::FuncIdx(idx),
        0x01 => ExportDesc::TableIdx(idx),
        0x02 => ExportDesc::MemIdx(idx),
        0x03 => ExportDesc::GlobalIdx(idx),
        _ => panic!("Export desc byte must be between 0x00 and 0x03 inclusive."),
    }
}

fn name(s: &[u8]) -> IResult<&[u8], &str> {
    let (s, vec_length) = leb_128_u32(s)?;
    let (s, name) = nom::bytes::streaming::take(vec_length)(s)?;
    let name = std::str::from_utf8(name).unwrap();

    Ok((s, name))
}

fn limits(s: &[u8]) -> IResult<&[u8], Limits> {
    let (s, kind_byte) = le_u8(s)?;
    match kind_byte {
        0x00 => {
            let (s, min) = leb_128_u32(s)?;
            let max = Max::E;
            Ok((s, Limits { min, max }))
        }
        0x01 => {
            let (s, min) = leb_128_u32(s)?;
            let (s, max) = leb_128_u32(s)?;
            let max = Max::Number(max);
            Ok((s, Limits { min, max }))
        }
        _ => panic!("Limits kind byte must be 0x00 or 0x01"),
    }
}

/// https://en.wikipedia.org/wiki/LEB128 and
/// https://stackoverflow.com/questions/43230917/extract-7-bits-signed-integer-from-u8-byte
fn leb_128_u32(s: &[u8]) -> IResult<&[u8], u32> {
    let mut result = 0;
    let mut shift = 0;
    loop {
        let (s, byte) = le_u8(s)?;
        let lowest_7 = byte & 0b0111_1111;
        result |= lowest_7 << shift;
        let highest = byte & 0b1000_0000;
        if highest == 0 {
            return Ok((s, result.into()));
        } else {
            shift += 7;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::parse;
    use crate::ValType;
    use std::fs::File;
    use std::io::prelude::*;

    #[test]
    fn it_does_a_simple_module() {
        let mut f = File::open("fixtures/main.wasm").unwrap();

        let mut buffer = Vec::new();
        // read the whole file
        f.read_to_end(&mut buffer).unwrap();

        let (remaining, wasm) = parse(&buffer).unwrap();

        println!("{:?}", wasm);
        println!("{:?}", remaining);

        assert_eq!(wasm.version, 1);
        assert_eq!(wasm.types.function_types[0].parameter_types.len(), 1);
        assert_eq!(
            wasm.types.function_types[0].parameter_types[0],
            ValType::I32
        );
        assert_eq!(wasm.types.function_types[0].result_types.len(), 1);
        assert_eq!(wasm.types.function_types[0].result_types[0], ValType::I32);
    }
}
