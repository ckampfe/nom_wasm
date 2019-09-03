// https://webassembly.github.io/spec

use nom::branch::alt;
use nom::bytes::streaming::{tag, take};
use nom::character::streaming::char;
use nom::combinator::{complete, map};
use nom::multi::{count, many0};
use nom::number::streaming::{le_u32, le_u8};
use nom::sequence::pair;
use nom::*;

type ParseResult<'a, T> =
    std::result::Result<(T, WasmModule<'a>), nom::Err<(T, nom::error::ErrorKind)>>;

pub fn parse(bytes: &[u8]) -> ParseResult<&[u8]> {
    let (s, _) = magic(bytes)?;
    let (s, version) = version(s)?;
    let (s, mut customs) = many0(complete(custom_section))(s)?;
    let (s, types) = type_section(s)?;
    let (s, customs2) = many0(complete(custom_section))(s)?;
    // import section
    // custom section
    let (s, functions) = function_section(s)?;
    let (s, customs3) = many0(complete(custom_section))(s)?;
    let (s, tables) = table_section(s)?;
    let (s, customs4) = many0(complete(custom_section))(s)?;
    let (s, memories) = memory_section(s)?;
    let (s, customs5) = many0(complete(custom_section))(s)?;
    // global section
    // custom section
    let (s, exports) = export_section(s)?;
    let (s, customs6) = many0(complete(custom_section))(s)?;
    // start section
    // custom section
    // elem section
    // custom section
    let (s, code) = code_section(s)?;
    let (s, customs7) = many0(complete(custom_section))(s)?;
    // data section
    // custom section

    customs.extend(customs2);
    customs.extend(customs3);
    customs.extend(customs4);
    customs.extend(customs5);
    customs.extend(customs6);
    customs.extend(customs7);

    Ok((
        s,
        WasmModule {
            version,
            types,
            functions,
            tables,
            memories,
            exports,
            code,
            customs,
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
    code: CodeSection,
    customs: Vec<CustomSection<'a>>,
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

#[derive(Clone, Debug, PartialEq)]
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

#[derive(Clone, Debug, PartialEq)]
pub enum ExportDesc {
    FuncIdx(u32),
    TableIdx(u32),
    MemIdx(u32),
    GlobalIdx(u32),
}

#[derive(Clone, Debug)]
pub struct CodeSection {
    codes: Vec<Code>,
}

#[derive(Clone, Debug)]
pub struct Code {
    size: u32,
    function: Function,
}

#[derive(Clone, Debug)]
pub struct Function {
    locals: Vec<LocalDeclaration>,
    expression: Expression,
}

#[derive(Clone, Debug)]
pub struct LocalDeclaration {
    entry_count: u32,
    value_type: ValType,
}

#[derive(Clone, Debug)]
pub struct Expression {
    instructions: Vec<Instruction>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Instruction {
    LocalGet(u32),
    I32Const(i32),
    I32Add,
}

#[derive(Clone, Debug)]
pub struct CustomSection<'a> {
    name: &'a str,
    bytes: &'a [u8],
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

fn magic(s: &[u8]) -> IResult<&[u8], ()> {
    let magic_bytes = b"\0asm";
    let (s, _) = tag(magic_bytes)(s)?;
    Ok((s, ()))
}

fn version(s: &[u8]) -> IResult<&[u8], u32> {
    let (s, version) = le_u32(s)?;
    Ok((s, version))
}

fn type_section(s: &[u8]) -> IResult<&[u8], TypeSection> {
    let (s, _section_id) = char(1 as char)(s)?;
    let (s, _section_length_bytes) = leb_128_u32(s)?;
    let (s, (vec_length, _)) = leb_128_u32(s)?;
    let (s, function_types) = count(function_type, vec_length as usize)(s)?;
    let type_section = TypeSection { function_types };
    println!("TS: {:?}", type_section);
    Ok((s, type_section))
}

fn function_type(s: &[u8]) -> IResult<&[u8], FunctionType> {
    let (s, _function_type_id) = char(0x60 as char)(s)?;
    let (s, (parameter_type_length, _)) = leb_128_u32(s)?;
    let (s, parameter_types) = count(map(le_u8, byte_to_type), parameter_type_length as usize)(s)?;
    let (s, (result_type_length, _)) = leb_128_u32(s)?;
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
    let (s, _section_id) = char(3 as char)(s)?;
    let (s, _section_length_bytes) = leb_128_u32(s)?;
    let (s, (vec_length, _)) = leb_128_u32(s)?;
    let mut type_indices = vec![];
    let mut s_and_index: (&[u8], (u32, u32)) = (s, (0, 0));

    for _i in 0..vec_length {
        s_and_index = leb_128_u32(s)?;
        let (_, (this_index, _)) = s_and_index;
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
    let (s, _section_id) = char(4 as char)(s)?;
    let (s, _section_length_bytes) = leb_128_u32(s)?;
    let (s, (vec_length, _)) = leb_128_u32(s)?;

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
    let (s, _section_id) = char(5 as char)(s)?;
    let (s, _section_length_bytes) = leb_128_u32(s)?;
    let (s, (vec_length, _)) = leb_128_u32(s)?;

    let (s, memories) = count(map(limits, |limits| Memory { limits }), vec_length as usize)(s)?;

    Ok((s, MemorySection { memories }))
}

fn export_section(s: &[u8]) -> IResult<&[u8], ExportSection> {
    let (s, _section_id) = char(7 as char)(s)?;
    let (s, _section_length_bytes) = leb_128_u32(s)?;
    let (s, (vec_length, _)) = leb_128_u32(s)?;
    let (s, exports) = count(export, vec_length as usize)(s)?;

    Ok((s, ExportSection { exports }))
}

fn export(s: &[u8]) -> IResult<&[u8], Export> {
    let (s, (name, _)) = name(s)?;
    let (s, desc_kind_byte) = le_u8(s)?;
    let (s, (idx, _)) = leb_128_u32(s)?;
    let desc = desc(desc_kind_byte, idx);
    Ok((s, Export { name, desc }))
}

fn code_section(s: &[u8]) -> IResult<&[u8], CodeSection> {
    let (s, _section_id) = char(10 as char)(s)?;
    let (s, _section_length_bytes) = leb_128_u32(s)?;
    let (s, (vec_length, _)) = leb_128_u32(s)?;

    let (s, codes) = count(code, vec_length as usize)(s)?;

    Ok((s, CodeSection { codes }))
}

fn code(s: &[u8]) -> IResult<&[u8], Code> {
    let (s, (size, _)) = leb_128_u32(s)?;
    let (s, function) = function(s)?;

    Ok((s, Code { size, function }))
}

fn function(s: &[u8]) -> IResult<&[u8], Function> {
    let (s, locals) = local_declarations(s)?;
    let (s, expression) = expression(s)?;
    Ok((s, Function { locals, expression }))
}

fn local_declarations(s: &[u8]) -> IResult<&[u8], Vec<LocalDeclaration>> {
    let (s, (vec_length, _)) = leb_128_u32(s)?;
    let (s, locals) = count(local, vec_length as usize)(s)?;
    Ok((s, locals))
}

fn local(s: &[u8]) -> IResult<&[u8], LocalDeclaration> {
    let (s, (entry_count, _)) = leb_128_u32(s)?;
    let (s, value_type) = map(le_u8, byte_to_type)(s)?;
    Ok((
        s,
        LocalDeclaration {
            entry_count,
            value_type,
        },
    ))
}

fn expression(s: &[u8]) -> IResult<&[u8], Expression> {
    let (s, instructions) = many0(instruction)(s)?;
    let (s, _) = char(0x0B.into())(s)?;
    Ok((s, Expression { instructions }))
}

fn instruction(s: &[u8]) -> IResult<&[u8], Instruction> {
    let (s, instruction) = alt((
        map(
            pair(char(0x20.into()), leb_128_u32),
            |(_bytecode, (idx, _))| Instruction::LocalGet(idx),
        ),
        map(pair(char(0x41.into()), leb_128_i32), |(_bytecode, n)| {
            Instruction::I32Const(n)
        }),
        map(char(0x6A.into()), |_bytecode| Instruction::I32Add),
    ))(s)?;

    Ok((s, instruction))
}

fn custom_section(s: &[u8]) -> IResult<&[u8], CustomSection> {
    let (s, _section_id) = char(0 as char)(s)?;
    let (s, (section_length_bytes, consumed)) = leb_128_u32(s)?;
    let (s, (name, name_bytes_taken)) = name(s)?;
    let to_take = section_length_bytes - name_bytes_taken - consumed;
    let (s, bytes) = take(to_take)(s)?;

    Ok((s, CustomSection { name, bytes }))
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

fn name(s: &[u8]) -> IResult<&[u8], (&str, u32)> {
    let (s, (vec_length, _)) = leb_128_u32(s)?;
    println!("NAME LENGTH {}", vec_length);
    let (s, name) = take(vec_length)(s)?;
    let name = std::str::from_utf8(name).unwrap();

    let total_taken = vec_length;

    Ok((s, (name, total_taken)))
}

fn limits(s: &[u8]) -> IResult<&[u8], Limits> {
    let (s, kind_byte) = le_u8(s)?;
    match kind_byte {
        0x00 => {
            let (s, (min, _)) = leb_128_u32(s)?;
            let max = Max::E;
            Ok((s, Limits { min, max }))
        }
        0x01 => {
            let (s, (min, _)) = leb_128_u32(s)?;
            let (s, (max, _)) = leb_128_u32(s)?;
            let max = Max::Number(max);
            Ok((s, Limits { min, max }))
        }
        _ => panic!("Limits kind byte must be 0x00 or 0x01"),
    }
}

/// https://en.wikipedia.org/wiki/LEB128 and
/// https://stackoverflow.com/questions/43230917/extract-7-bits-signed-integer-from-u8-byte
fn leb_128_u32(s: &[u8]) -> IResult<&[u8], (u32, u32)> {
    let mut bytes_consumed = 0;
    let mut result = 0;
    let mut shift = 0;
    loop {
        let (s, byte) = le_u8(s)?;
        bytes_consumed += 1;
        let lowest_7 = byte & 0b0111_1111;
        result |= lowest_7 << shift;
        let highest = byte & 0b1000_0000;
        if highest == 0 {
            return Ok((s, (result.into(), bytes_consumed)));
        } else {
            shift += 7;
        }
    }
}

/// https://en.wikipedia.org/wiki/LEB128 and
/// https://stackoverflow.com/questions/43230917/extract-7-bits-signed-integer-from-u8-byte
fn leb_128_i32(s: &[u8]) -> IResult<&[u8], i32> {
    let mut result = 0;
    let mut shift = 0;
    let size = 32;

    let (s, mut result, byte) = loop {
        let (s, byte) = le_u8(s)?;
        let lowest_7 = byte & 0b0111_1111;
        result |= lowest_7 << shift;
        shift += 7;

        let highest = byte & 0b1000_0000;
        if highest == 0 {
            break (s, result, byte);
        }
    };

    let sign_bit = byte & 0b0100_0000;
    if shift < size && sign_bit == 1 {
        result |= !0 << shift;
    }

    Ok((s, result.into()))
}

#[cfg(test)]
mod tests {
    use crate::parse;
    use crate::ExportDesc;
    use crate::Instruction;
    use crate::Max;
    use crate::ValType;
    use std::fs::File;
    use std::io::prelude::*;

    #[test]
    fn it_does_a_simple_module() {
        let mut f = File::open("fixtures/main.wasm").unwrap();

        let mut buffer = Vec::new();
        f.read_to_end(&mut buffer).unwrap();

        let (remaining, wasm) = parse(&buffer).unwrap();

        println!("{:#?}", wasm);
        println!("remaining: {:#?}", remaining);

        // version
        assert_eq!(wasm.version, 1);

        // types section
        assert_eq!(wasm.types.function_types[0].parameter_types.len(), 1);
        assert_eq!(
            wasm.types.function_types[0].parameter_types[0],
            ValType::I32
        );
        assert_eq!(wasm.types.function_types[0].result_types.len(), 1);
        assert_eq!(wasm.types.function_types[0].result_types[0], ValType::I32);

        // function section
        assert_eq!(wasm.functions.functions[0], 0);

        // table section
        assert_eq!(wasm.tables.tables[0].limits.min, 1);
        assert_eq!(wasm.tables.tables[0].limits.max, Max::Number(1));

        // memory section
        assert_eq!(wasm.memories.memories[0].limits.min, 17);
        assert_eq!(wasm.memories.memories[0].limits.max, Max::E);

        // export section
        assert_eq!(wasm.exports.exports[0].name, "memory");
        assert_eq!(wasm.exports.exports[0].desc, ExportDesc::MemIdx(0));
        assert_eq!(wasm.exports.exports[1].name, "add_one");
        assert_eq!(wasm.exports.exports[1].desc, ExportDesc::FuncIdx(0));

        // code section
        assert_eq!(wasm.code.codes[0].size, 7);
        assert!(wasm.code.codes[0].function.locals.is_empty());
        assert_eq!(
            wasm.code.codes[0].function.expression.instructions[0],
            Instruction::LocalGet(0)
        );
        assert_eq!(
            wasm.code.codes[0].function.expression.instructions[1],
            Instruction::I32Const(1)
        );
        assert_eq!(
            wasm.code.codes[0].function.expression.instructions[2],
            Instruction::I32Add
        );

        // custom sections
        assert_eq!(wasm.customs.len(), 2);
        assert_eq!(wasm.customs[0].name, "linking");
        assert_eq!(wasm.customs[0].bytes.len(), 3);
        assert_eq!(wasm.customs[1].name, "name");
        assert_eq!(wasm.customs[1].bytes.len(), 12);

        // remaining
        assert!(remaining.is_empty())
    }
}
