// https://webassembly.github.io/spec

use nom::branch::alt;
use nom::bytes::streaming::{tag, take};
use nom::character::streaming::char;
use nom::combinator::{complete, map, opt};
use nom::multi::{count, many0};
use nom::number::streaming::{le_u32, le_u8};
use nom::sequence::pair;
use nom::*;

type ParseResult<'a, T> =
    std::result::Result<(T, WasmModule<'a>), nom::Err<(T, nom::error::ErrorKind)>>;

const CUSTOM_SECTION_ID: char = 0 as char;
const TYPE_SECTION_ID: char = 1 as char;
const IMPORT_SECTION_ID: char = 2 as char;
const FUNCTION_SECTION_ID: char = 3 as char;
const TABLE_SECTION_ID: char = 4 as char;
const MEMORY_SECTION_ID: char = 5 as char;
const GLOBAL_SECTION_ID: char = 6 as char;
const EXPORT_SECTION_ID: char = 7 as char;
const START_SECTION_ID: char = 8 as char;
const ELEMENT_SECTION_ID: char = 9 as char;
const CODE_SECTION_ID: char = 10 as char;

const FUNCTION_TYPE: char = 0x60 as char;
const FUNC_REF_TYPE: char = 0x70 as char;

const END_OPCODE: char = 0x0B as char;

pub fn parse(bytes: &[u8]) -> ParseResult<&[u8]> {
    let (s, _) = magic(bytes)?;
    let (s, version) = version(s)?;
    let (s, mut customs) = many0(complete(custom_section))(s)?;
    let (s, types) = opt(type_section)(s)?;
    let (s, customs2) = many0(complete(custom_section))(s)?;
    let (s, imports) = opt(import_section)(s)?;
    let (s, customs3) = many0(complete(custom_section))(s)?;
    let (s, functions) = opt(function_section)(s)?;
    let (s, customs4) = many0(complete(custom_section))(s)?;
    let (s, tables) = opt(table_section)(s)?;
    let (s, customs5) = many0(complete(custom_section))(s)?;
    let (s, memories) = opt(memory_section)(s)?;
    let (s, customs6) = many0(complete(custom_section))(s)?;
    let (s, globals) = opt(global_section)(s)?;
    let (s, customs7) = many0(complete(custom_section))(s)?;
    let (s, exports) = opt(export_section)(s)?;
    let (s, customs8) = many0(complete(custom_section))(s)?;
    let (s, start) = opt(start_section)(s)?;
    let (s, customs9) = many0(complete(custom_section))(s)?;
    let (s, elements) = opt(element_section)(s)?;
    let (s, customs10) = many0(complete(custom_section))(s)?;
    let (s, code) = opt(code_section)(s)?;
    let (s, customs11) = many0(complete(custom_section))(s)?;
    // TODO: data section
    // TODO: custom section

    customs.extend(customs2);
    customs.extend(customs3);
    customs.extend(customs4);
    customs.extend(customs5);
    customs.extend(customs6);
    customs.extend(customs7);
    customs.extend(customs8);
    customs.extend(customs9);
    customs.extend(customs10);
    customs.extend(customs11);

    Ok((
        s,
        WasmModule {
            version,
            types,
            imports,
            functions,
            tables,
            memories,
            globals,
            exports,
            start,
            elements,
            code,
            customs,
        },
    ))
}

#[derive(Clone, Debug)]
pub struct WasmModule<'a> {
    version: u32,
    types: Option<TypeSection>,
    imports: Option<ImportSection<'a>>,
    functions: Option<FunctionSection>,
    tables: Option<TableSection>,
    memories: Option<MemorySection>,
    globals: Option<GlobalSection>,
    exports: Option<ExportSection<'a>>,
    start: Option<StartSection>,
    elements: Option<ElementSection>,
    code: Option<CodeSection>,
    customs: Vec<CustomSection<'a>>,
}

#[derive(Clone, Debug)]
pub struct TypeSection {
    function_types: Vec<FunctionType>,
}

#[derive(Clone, Debug)]
pub struct ImportSection<'a> {
    imports: Vec<Import<'a>>,
}

#[derive(Clone, Debug)]
pub struct Import<'a> {
    module: &'a str,
    name: &'a str,
    import_description: ImportDesc,
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
pub struct StartSection {
    start: u32,
}

#[derive(Clone, Debug)]
pub struct ElementSection {
    elements: Vec<Element>,
}

#[derive(Clone, Debug)]
pub struct Element {
    table_index: u32,
    offset: Expression,
    init: Vec<u32>,
}

#[derive(Clone, Debug)]
pub struct GlobalSection {
    globals: Vec<Global>,
}

#[derive(Clone, Debug)]
pub struct Global {
    global_type: GlobalType,
    expression: Expression,
}

#[derive(Clone, Debug)]
pub struct GlobalType {
    value_type: ValType,
    is_mutable: bool,
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

trait Description {
    fn function_index(idx: u32) -> Self;
    fn table_index(idx: u32) -> Self;
    fn memory_index(idx: u32) -> Self;
    fn global_index(idx: u32) -> Self;
}

#[derive(Clone, Debug, PartialEq)]
pub enum ExportDesc {
    FuncIdx(u32),
    TableIdx(u32),
    MemIdx(u32),
    GlobalIdx(u32),
}

impl Description for ExportDesc {
    fn function_index(idx: u32) -> Self {
        Self::FuncIdx(idx)
    }
    fn table_index(idx: u32) -> Self {
        Self::TableIdx(idx)
    }
    fn memory_index(idx: u32) -> Self {
        Self::MemIdx(idx)
    }
    fn global_index(idx: u32) -> Self {
        Self::GlobalIdx(idx)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ImportDesc {
    FuncIdx(u32),
    TableIdx(u32),
    MemIdx(u32),
    GlobalIdx(u32),
}

impl Description for ImportDesc {
    fn function_index(idx: u32) -> Self {
        Self::FuncIdx(idx)
    }
    fn table_index(idx: u32) -> Self {
        Self::TableIdx(idx)
    }
    fn memory_index(idx: u32) -> Self {
        Self::MemIdx(idx)
    }
    fn global_index(idx: u32) -> Self {
        Self::GlobalIdx(idx)
    }
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
    let (s, _section_id) = char(TYPE_SECTION_ID)(s)?;
    let (s, _section_length_bytes) = leb_128_u32(s)?;
    let (s, (vec_length, _)) = leb_128_u32(s)?;
    let (s, function_types) = count(function_type, vec_length as usize)(s)?;
    let type_section = TypeSection { function_types };
    Ok((s, type_section))
}

fn function_type(s: &[u8]) -> IResult<&[u8], FunctionType> {
    let (s, _function_type_id) = char(FUNCTION_TYPE)(s)?;
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

fn import_section(s: &[u8]) -> IResult<&[u8], ImportSection> {
    let (s, _section_id) = char(IMPORT_SECTION_ID)(s)?;
    let (s, _section_length_bytes) = leb_128_u32(s)?;
    let (s, (vec_length, _)) = leb_128_u32(s)?;
    let (s, imports) = count(import, vec_length as usize)(s)?;

    Ok((s, ImportSection { imports }))
}

fn import(s: &[u8]) -> IResult<&[u8], Import> {
    let (s, (module, _)) = name(s)?;
    let (s, (name, _)) = name(s)?;
    let (s, desc_kind_byte) = le_u8(s)?;
    let (s, (idx, _)) = leb_128_u32(s)?;
    let import_description = desc(desc_kind_byte, idx);

    Ok((
        s,
        Import {
            module,
            name,
            import_description,
        },
    ))
}

fn function_section(s: &[u8]) -> IResult<&[u8], FunctionSection> {
    let (s, _section_id) = char(FUNCTION_SECTION_ID)(s)?;
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
    let (s, _section_id) = char(TABLE_SECTION_ID)(s)?;
    let (s, _section_length_bytes) = leb_128_u32(s)?;
    let (s, (vec_length, _)) = leb_128_u32(s)?;

    let (s, tables) = count(
        map(pair(func_ref, limits), |(_funcref, limits)| Table {
            r#type: FuncRef(),
            limits,
        }),
        vec_length as usize,
    )(s)?;

    Ok((s, TableSection { tables }))
}

fn memory_section(s: &[u8]) -> IResult<&[u8], MemorySection> {
    let (s, _section_id) = char(MEMORY_SECTION_ID)(s)?;
    let (s, _section_length_bytes) = leb_128_u32(s)?;
    let (s, (vec_length, _)) = leb_128_u32(s)?;

    let (s, memories) = count(map(limits, |limits| Memory { limits }), vec_length as usize)(s)?;

    Ok((s, MemorySection { memories }))
}

fn global_section(s: &[u8]) -> IResult<&[u8], GlobalSection> {
    let (s, _section_id) = char(GLOBAL_SECTION_ID)(s)?;
    let (s, _section_length_bytes) = leb_128_u32(s)?;
    let (s, (vec_length, _)) = leb_128_u32(s)?;
    let (s, globals) = count(global, vec_length as usize)(s)?;

    Ok((s, GlobalSection { globals }))
}

fn global(s: &[u8]) -> IResult<&[u8], Global> {
    let (s, global_type) = global_type(s)?;
    let (s, expression) = expression(s)?;

    Ok((
        s,
        Global {
            global_type,
            expression,
        },
    ))
}

fn global_type(s: &[u8]) -> IResult<&[u8], GlobalType> {
    let (s, value_type) = map(le_u8, byte_to_type)(s)?;
    let (s, is_mutable) = boolean_byte(s)?;

    Ok((
        s,
        GlobalType {
            value_type,
            is_mutable,
        },
    ))
}

fn boolean_byte(s: &[u8]) -> IResult<&[u8], bool> {
    let (s, byte) = le_u8(s)?;
    Ok((
        s,
        match byte {
            0x00 => false,
            0x01 => true,
            _ => panic!("Boolean byte must be either 0x00 for false of 0x01 for true"),
        },
    ))
}

fn export_section(s: &[u8]) -> IResult<&[u8], ExportSection> {
    let (s, _section_id) = char(EXPORT_SECTION_ID)(s)?;
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

fn start_section(s: &[u8]) -> IResult<&[u8], StartSection> {
    let (s, _section_id) = char(START_SECTION_ID)(s)?;
    let (s, _section_length_bytes) = leb_128_u32(s)?;
    let (s, (idx, _)) = leb_128_u32(s)?;

    Ok((s, StartSection { start: idx }))
}

fn element_section(s: &[u8]) -> IResult<&[u8], ElementSection> {
    let (s, _section_id) = char(ELEMENT_SECTION_ID)(s)?;
    let (s, _section_length_bytes) = leb_128_u32(s)?;
    let (s, (vec_length, _)) = leb_128_u32(s)?;
    let (s, elements) = count(element, vec_length as usize)(s)?;

    Ok((s, ElementSection { elements }))
}

fn element(s: &[u8]) -> IResult<&[u8], Element> {
    let (s, (table_index, _)) = leb_128_u32(s)?;
    let (s, offset) = expression(s)?;
    let (s, (init_vec_length, _)) = leb_128_u32(s)?;
    let (s, init) = count(leb_128_u32, init_vec_length as usize)(s)?;

    Ok((
        s,
        Element {
            table_index,
            offset,
            init: init.into_iter().map(|t| t.0).collect(),
        },
    ))
}

fn code_section(s: &[u8]) -> IResult<&[u8], CodeSection> {
    let (s, _section_id) = char(CODE_SECTION_ID)(s)?;
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
    let (s, _) = char(END_OPCODE)(s)?;
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
    let (s, _section_id) = char(CUSTOM_SECTION_ID)(s)?;
    let (s, (section_length_bytes, consumed)) = leb_128_u32(s)?;
    let (s, (name, name_bytes_taken)) = name(s)?;
    let to_take = section_length_bytes - name_bytes_taken - consumed;
    let (s, bytes) = take(to_take)(s)?;

    Ok((s, CustomSection { name, bytes }))
}

fn desc<T: Description>(desc_kind_byte: u8, idx: u32) -> T {
    match desc_kind_byte {
        0x00 => T::function_index(idx),
        0x01 => T::table_index(idx),
        0x02 => T::memory_index(idx),
        0x03 => T::global_index(idx),
        _ => panic!("Export desc byte must be between 0x00 and 0x03 inclusive."),
    }
}

fn name(s: &[u8]) -> IResult<&[u8], (&str, u32)> {
    let (s, (vec_length, _)) = leb_128_u32(s)?;
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

fn func_ref(s: &[u8]) -> IResult<&[u8], ()> {
    let (s, _) = char(FUNC_REF_TYPE)(s)?;
    Ok((s, ()))
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
        let types = wasm.types.unwrap();
        assert_eq!(types.function_types[0].parameter_types.len(), 1);
        assert_eq!(types.function_types[0].parameter_types[0], ValType::I32);
        assert_eq!(types.function_types[0].result_types.len(), 1);
        assert_eq!(types.function_types[0].result_types[0], ValType::I32);

        // function section
        assert_eq!(wasm.functions.unwrap().functions[0], 0);

        // table section
        let tables = wasm.tables.unwrap();
        assert_eq!(tables.tables[0].limits.min, 1);
        assert_eq!(tables.tables[0].limits.max, Max::Number(1));

        // memory section
        let memories = wasm.memories.unwrap();
        assert_eq!(memories.memories[0].limits.min, 17);
        assert_eq!(memories.memories[0].limits.max, Max::E);

        // export section
        let exports = wasm.exports.unwrap();
        assert_eq!(exports.exports[0].name, "memory");
        assert_eq!(exports.exports[0].desc, ExportDesc::MemIdx(0));
        assert_eq!(exports.exports[1].name, "add_one");
        assert_eq!(exports.exports[1].desc, ExportDesc::FuncIdx(0));

        // code section
        let code = wasm.code.unwrap();
        assert_eq!(code.codes[0].size, 7);
        assert!(code.codes[0].function.locals.is_empty());
        assert_eq!(
            code.codes[0].function.expression.instructions[0],
            Instruction::LocalGet(0)
        );
        assert_eq!(
            code.codes[0].function.expression.instructions[1],
            Instruction::I32Const(1)
        );
        assert_eq!(
            code.codes[0].function.expression.instructions[2],
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
