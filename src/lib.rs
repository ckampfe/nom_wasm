// https://webassembly.github.io/spec

use nom::branch::alt;
use nom::bytes::streaming::{tag, take};
use nom::character::streaming::char;
use nom::combinator::{complete, map, opt};
use nom::multi::{count, many0};
use nom::number::streaming::{le_u32, le_u8};
use nom::sequence::pair;
use nom::*;
use std::convert::TryInto;

type ParseResult<'a, T> =
    std::result::Result<(T, WasmModule<'a>), nom::Err<(T, nom::error::ErrorKind)>>;

const CUSTOM_SECTION_ID: &[u8] = &[0];
const TYPE_SECTION_ID: &[u8] = &[1];
const IMPORT_SECTION_ID: &[u8] = &[2];
const FUNCTION_SECTION_ID: &[u8] = &[3];
const TABLE_SECTION_ID: &[u8] = &[4];
const MEMORY_SECTION_ID: &[u8] = &[5];
const GLOBAL_SECTION_ID: &[u8] = &[6];
const EXPORT_SECTION_ID: &[u8] = &[7];
const START_SECTION_ID: &[u8] = &[8];
const ELEMENT_SECTION_ID: &[u8] = &[9];
const CODE_SECTION_ID: &[u8] = &[10];
const DATA_SECTION_ID: &[u8] = &[11];

const FUNCTION_TYPE: &[u8] = &[0x60];
const FUNC_REF_TYPE: &[u8] = &[0x70];

const END_OPCODE: &[u8] = &[0x0B];

/// https://webassembly.github.io/spec/
pub fn parse(bytes: &[u8]) -> ParseResult<&[u8]> {
    let (s, _) = magic(bytes)?;
    let (s, version) = version(s)?;
    let (s, mut customs) = many0(complete(custom_section))(s)?;
    let (s, types) = opt(type_section)(s)?;
    let (s, custom2) = many0(complete(custom_section))(s)?;
    let (s, imports) = opt(import_section)(s)?;
    let (s, custom3) = many0(complete(custom_section))(s)?;
    let (s, functions) = opt(function_section)(s)?;
    let (s, custom4) = many0(complete(custom_section))(s)?;
    let (s, tables) = opt(table_section)(s)?;
    let (s, custom5) = many0(complete(custom_section))(s)?;
    let (s, memories) = opt(memory_section)(s)?;
    let (s, custom6) = many0(complete(custom_section))(s)?;
    let (s, globals) = opt(global_section)(s)?;
    let (s, custom7) = many0(complete(custom_section))(s)?;
    let (s, exports) = opt(export_section)(s)?;
    let (s, custom8) = many0(complete(custom_section))(s)?;
    let (s, start) = opt(start_section)(s)?;
    let (s, custom9) = many0(complete(custom_section))(s)?;
    let (s, elements) = opt(element_section)(s)?;
    let (s, custom10) = many0(complete(custom_section))(s)?;
    let (s, code) = opt(complete(code_section))(s)?;
    let (s, custom11) = many0(complete(custom_section))(s)?;
    // note that `data_section` has to be `complete`
    // in order for `opt` to fail correctly on empty input
    let (s, data) = opt(complete(data_section))(s)?;
    let (s, custom12) = many0(complete(custom_section))(s)?;

    customs.extend(custom2);
    customs.extend(custom3);
    customs.extend(custom4);
    customs.extend(custom5);
    customs.extend(custom6);
    customs.extend(custom7);
    customs.extend(custom8);
    customs.extend(custom9);
    customs.extend(custom10);
    customs.extend(custom11);
    customs.extend(custom12);

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
            data,
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
    data: Option<DataSection>,
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
    functions: Vec<u64>,
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
    min: u64,
    max: Max,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Max {
    Number(u64),
    E,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ValType {
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
    start: u64,
}

#[derive(Clone, Debug)]
pub struct ElementSection {
    elements: Vec<Element>,
}

#[derive(Clone, Debug)]
pub struct Element {
    table_index: u64,
    offset: Expression,
    init: Vec<u64>,
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
    fn function_index(idx: u64) -> Self;
    fn table_index(idx: u64) -> Self;
    fn memory_index(idx: u64) -> Self;
    fn global_index(idx: u64) -> Self;
}

#[derive(Clone, Debug, PartialEq)]
pub enum ExportDesc {
    FuncIdx(u64),
    TableIdx(u64),
    MemIdx(u64),
    GlobalIdx(u64),
}

impl Description for ExportDesc {
    fn function_index(idx: u64) -> Self {
        Self::FuncIdx(idx)
    }
    fn table_index(idx: u64) -> Self {
        Self::TableIdx(idx)
    }
    fn memory_index(idx: u64) -> Self {
        Self::MemIdx(idx)
    }
    fn global_index(idx: u64) -> Self {
        Self::GlobalIdx(idx)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ImportDesc {
    FuncIdx(u64),
    TableIdx(u64),
    MemIdx(u64),
    GlobalIdx(u64),
}

impl Description for ImportDesc {
    fn function_index(idx: u64) -> Self {
        Self::FuncIdx(idx)
    }
    fn table_index(idx: u64) -> Self {
        Self::TableIdx(idx)
    }
    fn memory_index(idx: u64) -> Self {
        Self::MemIdx(idx)
    }
    fn global_index(idx: u64) -> Self {
        Self::GlobalIdx(idx)
    }
}

#[derive(Clone, Debug)]
pub struct CodeSection {
    codes: Vec<Code>,
}

#[derive(Clone, Debug)]
pub struct Code {
    size: u64,
    function: Function,
}

#[derive(Clone, Debug)]
pub struct Function {
    locals: Vec<LocalDeclaration>,
    expression: Expression,
}

#[derive(Clone, Debug)]
pub struct LocalDeclaration {
    entry_count: u64,
    value_type: ValType,
}

#[derive(Clone, Debug)]
pub struct DataSection {
    data: Vec<Data>,
}

#[derive(Clone, Debug)]
pub struct Data {
    memory_index: u64,
    expression: Expression,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Expression {
    instructions: Vec<Instruction>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Instruction {
    // control instructions
    Unreachable,
    Nop,
    Block(BlockType, Vec<Instruction>),
    Loop(BlockType, Vec<Instruction>),
    Br(u32),
    BrIf(u32),
    BrTable(Vec<u32>, Vec<u32>),
    Return,
    Call(u32),
    CallIndirect(u32),

    // parametric instructions
    Drop,
    Select,

    // variable instructions
    LocalGet(u32),
    LocalSet(u32),
    LocalTee(u32),
    GlobalGet(u32),
    GlobalSet(u32),

    // memory instructions
    I32Load(u32, u32),
    I64Load(u32, u32),
    I32Load8u(u32, u32),
    I32Load16u(u32, u32),
    I32Store(u32, u32),
    I64Store(u32, u32),
    I32Store8(u32, u32),
    I32Store16(u32, u32),
    MemoryGrow,

    // numeric instructions
    I32Const(i32),
    I64Const(i64),
    I32Eqz,
    I32Eq,
    I32Ne,
    I32Ltu,
    I32Gts,
    I32Lts,
    I32Gtu,
    I32Les,
    I32Leu,
    I32Geu,
    I32Clz,
    I32Ctz,
    I32Add,
    I32Sub,
    I32And,
    I32Or,
    I32Xor,
    I32Shl,
    I32ShrU,
    I32RotL,
    I64Eq,
    I64Add,
    I64DivS,
    I64Shl,
    I64ShrU,
    F32Max,
    I32WrapI64,
    I64ExtendI32u,

    // weird/wrong instructions?
    DwarfOpWasmLocation(DwarfLocation, u32),
}

#[derive(Clone, Debug, PartialEq)]
pub enum DwarfLocation {
    WasmLocal,
    WasmGlobal,
    WasmOperandStack,
}

#[derive(Clone, Debug, PartialEq)]
pub enum BlockType {
    Empty,
    ValType(ValType),
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
    let (s, _section_id) = tag(TYPE_SECTION_ID)(s)?;
    let (s, _section_length_bytes) = leb_128(s)?;
    let (s, vec_length) = leb_128(s)?;
    let (s, function_types) = count(function_type, vec_length as usize)(s)?;
    let type_section = TypeSection { function_types };
    Ok((s, type_section))
}

fn function_type(s: &[u8]) -> IResult<&[u8], FunctionType> {
    let (s, _function_type_id) = tag(FUNCTION_TYPE)(s)?;
    let (s, parameter_type_length) = leb_128(s)?;
    let (s, parameter_types) = count(map(le_u8, byte_to_type), parameter_type_length as usize)(s)?;
    let (s, result_type_length) = leb_128(s)?;
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
    let (s, _section_id) = tag(IMPORT_SECTION_ID)(s)?;
    let (s, _section_length_bytes) = leb_128(s)?;
    let (s, vec_length) = leb_128(s)?;
    let (s, imports) = count(import, vec_length as usize)(s)?;
    Ok((s, ImportSection { imports }))
}

fn import(s: &[u8]) -> IResult<&[u8], Import> {
    let (s, module) = name(s)?;
    let (s, name) = name(s)?;
    let (s, desc_kind_byte) = le_u8(s)?;
    let (s, idx) = leb_128(s)?;
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
    let (s, _section_id) = tag(FUNCTION_SECTION_ID)(s)?;
    let (s, _section_length_bytes) = leb_128(s)?;
    let (s, vec_length) = leb_128(s)?;
    let (s, type_indices) = count(leb_128, vec_length as usize)(s)?;
    Ok((
        s,
        FunctionSection {
            functions: type_indices,
        },
    ))
}

fn table_section(s: &[u8]) -> IResult<&[u8], TableSection> {
    let (s, _section_id) = tag(TABLE_SECTION_ID)(s)?;
    let (s, _section_length_bytes) = leb_128(s)?;
    let (s, vec_length) = leb_128(s)?;

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
    let (s, _section_id) = tag(MEMORY_SECTION_ID)(s)?;
    let (s, _section_length_bytes) = leb_128(s)?;
    let (s, vec_length) = leb_128(s)?;

    let (s, memories) = count(map(limits, |limits| Memory { limits }), vec_length as usize)(s)?;

    Ok((s, MemorySection { memories }))
}

fn global_section(s: &[u8]) -> IResult<&[u8], GlobalSection> {
    let (s, _section_id) = tag(GLOBAL_SECTION_ID)(s)?;
    let (s, _section_length_bytes) = leb_128(s)?;
    let (s, vec_length) = leb_128(s)?;
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
    let (s, _section_id) = tag(EXPORT_SECTION_ID)(s)?;
    let (s, _section_length_bytes) = leb_128(s)?;
    let (s, vec_length) = leb_128(s)?;
    let (s, exports) = count(export, vec_length as usize)(s)?;

    Ok((s, ExportSection { exports }))
}

fn export(s: &[u8]) -> IResult<&[u8], Export> {
    let (s, name) = name(s)?;
    let (s, desc_kind_byte) = le_u8(s)?;
    let (s, idx) = leb_128(s)?;
    let desc = desc(desc_kind_byte, idx);
    Ok((s, Export { name, desc }))
}

fn start_section(s: &[u8]) -> IResult<&[u8], StartSection> {
    let (s, _section_id) = tag(START_SECTION_ID)(s)?;
    let (s, _section_length_bytes) = leb_128(s)?;
    let (s, idx) = leb_128(s)?;

    Ok((s, StartSection { start: idx }))
}

fn element_section(s: &[u8]) -> IResult<&[u8], ElementSection> {
    let (s, _section_id) = tag(ELEMENT_SECTION_ID)(s)?;
    println!("got element section id");
    let (s, _section_length_bytes) = leb_128(s)?;
    let (s, vec_length) = leb_128(s)?;
    let (s, elements) = count(element, vec_length as usize)(s)?;

    Ok((s, ElementSection { elements }))
}

fn element(s: &[u8]) -> IResult<&[u8], Element> {
    let (s, table_index) = leb_128(s)?;
    let (s, offset) = expression(s)?;
    let (s, init_vec_length) = leb_128(s)?;
    let (s, init) = count(leb_128, init_vec_length as usize)(s)?;

    Ok((
        s,
        Element {
            table_index,
            offset,
            init,
        },
    ))
}

fn code_section(s: &[u8]) -> IResult<&[u8], CodeSection> {
    let (s, _section_id) = tag(CODE_SECTION_ID)(s)?;
    let (s, _section_length_bytes) = leb_128(s)?;
    let (s, vec_length) = leb_128(s)?;
    let (s, codes) = count(code, vec_length as usize)(s)?;

    Ok((s, CodeSection { codes }))
}

fn code(s: &[u8]) -> IResult<&[u8], Code> {
    let (s, size) = leb_128(s)?;
    let (s, function) = function(s)?;

    Ok((s, Code { size, function }))
}

fn function(s: &[u8]) -> IResult<&[u8], Function> {
    let (s, locals) = local_declarations(s)?;
    println!("locals {:?}", locals);
    let (s, expression) = expression(s)?;
    Ok((s, Function { locals, expression }))
}

fn local_declarations(s: &[u8]) -> IResult<&[u8], Vec<LocalDeclaration>> {
    let (s, vec_length) = leb_128(s)?;
    let (s, locals) = count(local, vec_length as usize)(s)?;
    Ok((s, locals))
}

fn local(s: &[u8]) -> IResult<&[u8], LocalDeclaration> {
    let (s, entry_count) = leb_128(s)?;
    let (s, value_type) = map(le_u8, byte_to_type)(s)?;
    Ok((
        s,
        LocalDeclaration {
            entry_count,
            value_type,
        },
    ))
}

fn data_section(s: &[u8]) -> IResult<&[u8], DataSection> {
    let (s, _section_id) = tag(DATA_SECTION_ID)(s)?;
    println!("got data section id");
    let (s, _section_length_bytes) = leb_128(s)?;
    let (s, vec_length) = leb_128(s)?;
    let (s, data) = count(data, vec_length as usize)(s)?;

    Ok((s, DataSection { data }))
}

fn data(s: &[u8]) -> IResult<&[u8], Data> {
    let (s, memory_index) = leb_128(s)?;
    let (s, expression) = expression(s)?;
    let (s, byte_vec_length) = leb_128(s)?;
    let (s, bytes) = count(le_u8, byte_vec_length as usize)(s)?;

    Ok((
        s,
        Data {
            memory_index,
            expression,
            bytes,
        },
    ))
}

fn expression(s: &[u8]) -> IResult<&[u8], Expression> {
    let (s, instructions) = many0(instruction)(s)?;
    let (s, _) = tag(END_OPCODE)(s)?;
    Ok((s, Expression { instructions }))
}

fn instruction(s: &[u8]) -> IResult<&[u8], Instruction> {
    let (ss, byte) = take(15usize)(s)?;
    println!("{:#?}", byte);
    let (s, instruction) = alt((
        alt((
            // control instructions
            map(tag(&[0x00]), |_bytecode| Instruction::Unreachable),
            map(tag(&[0x01]), |_bytecode| Instruction::Nop),
            map(
                |s: &[u8]| -> IResult<&[u8], Instruction> {
                    let (s, _) = tag(&[0x02])(s)?;
                    let (s, blocktype) = blocktype(s)?;
                    let (s, instructions) = many0(instruction)(s)?;
                    let (s, _) = tag(END_OPCODE)(s)?;

                    Ok((s, Instruction::Block(blocktype, instructions)))
                },
                |block| block,
            ),
            map(
                |s: &[u8]| -> IResult<&[u8], Instruction> {
                    let (s, _) = tag(&[0x03])(s)?;
                    let (s, blocktype) = blocktype(s)?;
                    let (s, instructions) = many0(instruction)(s)?;
                    let (s, _) = tag(END_OPCODE)(s)?;

                    Ok((s, Instruction::Loop(blocktype, instructions)))
                },
                |block| block,
            ),
            map(pair(tag(&[0x0C]), leb_128), |(_bytecode, idx)| {
                Instruction::Br(idx.try_into().unwrap())
            }),
            map(pair(tag(&[0x0D]), leb_128), |(_bytecode, idx)| {
                Instruction::BrIf(idx.try_into().unwrap())
            }),
            map(
                |s: &[u8]| -> IResult<&[u8], Instruction> {
                    let (s, _) = tag(&[0x0E])(s)?;
                    let (s, vec_length) = leb_128(s)?;
                    let (s, label_idxs1) =
                        count(map(leb_128, |i| i.try_into().unwrap()), vec_length as usize)(s)?;
                    let (s, label_idxs2) =
                        count(map(leb_128, |i| i.try_into().unwrap()), vec_length as usize)(s)?;

                    Ok((s, Instruction::BrTable(label_idxs1, label_idxs2)))
                },
                |block| block,
            ),
            map(tag(&[0x0F]), |_bytecode| Instruction::Return),
            map(
                |s: &[u8]| -> IResult<&[u8], Instruction> {
                    let (s, _) = tag(&[0x10])(s)?;
                    let (s, func_idx) = leb_128(s)?;

                    Ok((s, Instruction::Call(func_idx.try_into().unwrap())))
                },
                |block| block,
            ),
            map(
                |s: &[u8]| -> IResult<&[u8], Instruction> {
                    let (s, _) = tag(&[0x11])(s)?;
                    let (s, type_idx) = leb_128(s)?;
                    let (s, _) = tag(&[0x00])(s)?;

                    Ok((s, Instruction::CallIndirect(type_idx.try_into().unwrap())))
                },
                |block| block,
            ),
            // parametric instructions
            map(tag(&[0x1A]), |_bytecode| Instruction::Drop),
            map(tag(&[0x1B]), |_bytecode| Instruction::Select),
            // variable instructions
            map(pair(tag(&[0x20]), leb_128), |(_bytecode, idx)| {
                Instruction::LocalGet(idx.try_into().unwrap())
            }),
            map(pair(tag(&[0x21]), leb_128), |(_bytecode, idx)| {
                Instruction::LocalSet(idx.try_into().unwrap())
            }),
            map(pair(tag(&[0x22]), leb_128), |(_bytecode, idx)| {
                Instruction::LocalTee(idx.try_into().unwrap())
            }),
            map(pair(tag(&[0x23]), leb_128), |(_bytecode, idx)| {
                Instruction::GlobalGet(idx.try_into().unwrap())
            }),
            map(pair(tag(&[0x24]), leb_128), |(_bytecode, idx)| {
                Instruction::GlobalSet(idx.try_into().unwrap())
            }),
        )),
        alt((
            // memory instructions
            map(
                |s: &[u8]| -> IResult<&[u8], Instruction> {
                    let (s, _) = tag(&[0x28])(s)?;
                    let (s, alignment) = leb_128(s)?;
                    let (s, offset) = leb_128(s)?;
                    Ok((
                        s,
                        Instruction::I32Load(
                            2u32.pow(alignment.try_into().unwrap()),
                            offset.try_into().unwrap(),
                        ),
                    ))
                },
                |block| block,
            ),
            map(
                |s: &[u8]| -> IResult<&[u8], Instruction> {
                    let (s, _) = tag(&[0x29])(s)?;
                    let (s, alignment) = leb_128(s)?;
                    let (s, offset) = leb_128(s)?;
                    Ok((
                        s,
                        Instruction::I64Load(
                            2u32.pow(alignment.try_into().unwrap()),
                            offset.try_into().unwrap(),
                        ),
                    ))
                },
                |block| block,
            ),
            map(
                |s: &[u8]| -> IResult<&[u8], Instruction> {
                    let (s, _) = tag(&[0x2D])(s)?;
                    let (s, alignment) = leb_128(s)?;
                    let (s, offset) = leb_128(s)?;
                    Ok((
                        s,
                        Instruction::I32Load8u(
                            2u32.pow(alignment.try_into().unwrap()),
                            offset.try_into().unwrap(),
                        ),
                    ))
                },
                |block| block,
            ),
            map(
                |s: &[u8]| -> IResult<&[u8], Instruction> {
                    let (s, _) = tag(&[0x2F])(s)?;
                    let (s, alignment) = leb_128(s)?;
                    let (s, offset) = leb_128(s)?;
                    Ok((
                        s,
                        Instruction::I32Load16u(
                            2u32.pow(alignment.try_into().unwrap()),
                            offset.try_into().unwrap(),
                        ),
                    ))
                },
                |block| block,
            ),
            map(
                |s: &[u8]| -> IResult<&[u8], Instruction> {
                    let (s, _) = tag(&[0x36])(s)?;
                    let (s, alignment) = leb_128(s)?;
                    let (s, offset) = leb_128(s)?;
                    Ok((
                        s,
                        Instruction::I32Store(
                            2u32.pow(alignment.try_into().unwrap()),
                            offset.try_into().unwrap(),
                        ),
                    ))
                },
                |block| block,
            ),
            map(
                |s: &[u8]| -> IResult<&[u8], Instruction> {
                    let (s, _) = tag(&[0x37])(s)?;
                    let (s, alignment) = leb_128(s)?;
                    let (s, offset) = leb_128(s)?;
                    Ok((
                        s,
                        Instruction::I64Store(
                            2u32.pow(alignment.try_into().unwrap()),
                            offset.try_into().unwrap(),
                        ),
                    ))
                },
                |block| block,
            ),
            map(
                |s: &[u8]| -> IResult<&[u8], Instruction> {
                    let (s, _) = tag(&[0x3A])(s)?;
                    let (s, alignment) = leb_128(s)?;
                    let (s, offset) = leb_128(s)?;
                    Ok((
                        s,
                        Instruction::I32Store8(
                            2u32.pow(alignment.try_into().unwrap()),
                            offset.try_into().unwrap(),
                        ),
                    ))
                },
                |block| block,
            ),
            map(
                |s: &[u8]| -> IResult<&[u8], Instruction> {
                    let (s, _) = tag(&[0x3B])(s)?;
                    let (s, alignment) = leb_128(s)?;
                    let (s, offset) = leb_128(s)?;
                    Ok((
                        s,
                        Instruction::I32Store16(
                            2u32.pow(alignment.try_into().unwrap()),
                            offset.try_into().unwrap(),
                        ),
                    ))
                },
                |block| block,
            ),
            map(pair(tag(&[0x40]), tag(&[0x00])), |(_bytecode, n)| {
                Instruction::MemoryGrow
            }),
        )),
        alt((
            // numeric instructions
            map(pair(tag(&[0x41]), leb_128_i32), |(_bytecode, n)| {
                Instruction::I32Const(n as i32)
            }),
            map(pair(tag(&[0x42]), leb_128_i32), |(_bytecode, n)| {
                Instruction::I64Const(n)
            }),
            map(tag(&[0x45]), |_| Instruction::I32Eqz),
            map(tag(&[0x46]), |_| Instruction::I32Eq),
            map(tag(&[0x47]), |_| Instruction::I32Ne),
            map(tag(&[0x48]), |_| Instruction::I32Lts),
            map(tag(&[0x49]), |_| Instruction::I32Ltu),
            map(tag(&[0x4A]), |_| Instruction::I32Gts),
            map(tag(&[0x4B]), |_| Instruction::I32Gtu),
            map(tag(&[0x4C]), |_| Instruction::I32Les),
            map(tag(&[0x4D]), |_| Instruction::I32Leu),
            map(tag(&[0x4F]), |_| Instruction::I32Geu),
            map(tag(&[0x51]), |_| Instruction::I64Eq),
            map(tag(&[0x67]), |_bytecode| Instruction::I32Clz),
            map(tag(&[0x68]), |_bytecode| Instruction::I32Ctz),
            map(tag(&[0x6A]), |_bytecode| Instruction::I32Add),
            map(tag(&[0x6B]), |_bytecode| Instruction::I32Sub),
        )),
        alt((
            map(tag(&[0x71]), |_bytecode| Instruction::I32And),
            map(tag(&[0x72]), |_bytecode| Instruction::I32Or),
            map(tag(&[0x73]), |_bytecode| Instruction::I32Xor),
            map(tag(&[0x74]), |_bytecode| Instruction::I32Shl),
            map(tag(&[0x76]), |_bytecode| Instruction::I32ShrU),
            map(tag(&[0x77]), |_bytecode| Instruction::I32RotL),
            map(tag(&[0x7C]), |_bytecode| Instruction::I64Add),
            map(tag(&[0x7F]), |_bytecode| Instruction::I64DivS),
            map(tag(&[0x86]), |_bytecode| Instruction::I64Shl),
            map(tag(&[0x88]), |_bytecode| Instruction::I64ShrU),
            map(tag(&[0x97]), |_bytecode| Instruction::F32Max),
            map(tag(&[0xA7]), |_bytecode| Instruction::I32WrapI64),
            map(tag(&[0xAD]), |_bytecode| Instruction::I64ExtendI32u),
            // TODO:  debug instructions? maybe? what is this?
            // https://yurydelendik.github.io/webassembly-dwarf/#dwarf-locals
            map(
                |s: &[u8]| -> IResult<&[u8], Instruction> {
                    let (s, _) = tag(&[0xEB])(s)?;
                    let (s, location_type_byte) = le_u8(s)?;
                    let (s, location_index) = leb_128(s)?;

                    let location = match location_type_byte {
                        0x00 => DwarfLocation::WasmLocal,
                        0x01 => DwarfLocation::WasmGlobal,
                        0x02 => DwarfLocation::WasmOperandStack,
                        _ => panic!("dwarf location must be 0x00, 0x01, or 0x02"),
                    };

                    Ok((
                        s,
                        Instruction::DwarfOpWasmLocation(location, location_index as u32),
                    ))
                },
                |block| block,
            ),
        )),
    ))(s)?;

    println!("got {:?}", instruction);

    Ok((s, instruction))
}

fn blocktype(s: &[u8]) -> IResult<&[u8], BlockType> {
    let (s, blocktype) = alt((
        map(char(0x40.into()), |_bytecode| BlockType::Empty),
        map(map(le_u8, byte_to_type), |val_type| {
            BlockType::ValType(val_type)
        }),
    ))(s)?;

    Ok((s, blocktype))
}

fn custom_section(s: &[u8]) -> IResult<&[u8], CustomSection> {
    let (s, _section_id) = tag(CUSTOM_SECTION_ID)(s)?;
    let (s, section_length_bytes) = leb_128(s)?;
    let s1 = s.len();
    let (s, name) = name(s)?;
    let s2 = s.len();
    let to_take = section_length_bytes - (s1 as u64 - s2 as u64);
    let (s, bytes) = take(to_take)(s)?;

    Ok((s, CustomSection { name, bytes }))
}

fn desc<T: Description>(desc_kind_byte: u8, idx: u64) -> T {
    match desc_kind_byte {
        0x00 => T::function_index(idx),
        0x01 => T::table_index(idx),
        0x02 => T::memory_index(idx),
        0x03 => T::global_index(idx),
        _ => panic!("Export desc byte must be between 0x00 and 0x03 inclusive."),
    }
}

fn name(s: &[u8]) -> IResult<&[u8], &str> {
    let (s, vec_length) = leb_128(s)?;
    let (s, name) = take(vec_length)(s)?;
    let name = std::str::from_utf8(name).unwrap();

    Ok((s, name))
}

fn limits(s: &[u8]) -> IResult<&[u8], Limits> {
    let (s, kind_byte) = le_u8(s)?;
    match kind_byte {
        0x00 => {
            let (s, min) = leb_128(s)?;
            let max = Max::E;
            Ok((s, Limits { min, max }))
        }
        0x01 => {
            let (s, min) = leb_128(s)?;
            let (s, max) = leb_128(s)?;
            let max = Max::Number(max);
            Ok((s, Limits { min, max }))
        }
        _ => panic!("Limits kind byte must be 0x00 or 0x01"),
    }
}

fn func_ref(s: &[u8]) -> IResult<&[u8], ()> {
    let (s, _) = tag(FUNC_REF_TYPE)(s)?;
    Ok((s, ()))
}

pub const CONTINUATION_BIT: u8 = 1 << 7;

/// https://en.wikipedia.org/wiki/LEB128 and
/// https://stackoverflow.com/questions/43230917/extract-7-bits-signed-integer-from-u8-byte
fn leb_128(s: &[u8]) -> IResult<&[u8], u64> {
    let mut result = 0u64;
    let mut shift = 0;

    let buf: &mut [u8] = &mut [0];
    let mut ss: &[u8] = s;

    let (s, result) = loop {
        let (this_s, this_byte) = take(1usize)(ss)?;
        ss = this_s;
        buf[0] = this_byte[0];

        /*
        !CONTINUATION_BIT
         */
        // let lowest_7_bits = (byte[0] & 0b0111_1111u8) as u32;
        let lowest_7_bits = u64::from(buf[0] & 0b0111_1111);
        result |= lowest_7_bits << shift;

        let highest = buf[0] & 0b1000_0000;
        // if byte[0] & CONTINUATION_BIT == 0 {
        if highest == 0 {
            // return Ok((s, result));
            break (ss, result);
        }

        shift += 7;
    };

    Ok((s, result))
}

const SIGN_BIT: u8 = 1 << 6;

/// https://en.wikipedia.org/wiki/LEB128 and
/// https://stackoverflow.com/questions/43230917/extract-7-bits-signed-integer-from-u8-byte
fn leb_128_i32(s: &[u8]) -> IResult<&[u8], i64> {
    let mut result = 0;
    let mut shift = 0;
    let size = 64;
    let buf: &mut [u8] = &mut [0];
    let mut ss: &[u8] = s;

    let (s, mut result, buf) = loop {
        // let (s, byte) = le_u8(s)?;
        let (this_s, this_byte) = take(1usize)(ss)?;
        ss = this_s;
        buf[0] = this_byte[0];

        if shift == 63 && buf[0] != 0x00 && buf[0] != 0x7f {
            panic!("Overflow");
        }

        // let lowest_7 = byte & 0b0111_1111;
        let lowest_7_bits = i64::from(buf[0] & 0b0111_1111u8);
        result |= lowest_7_bits << shift;
        shift += 7;

        // let highest = byte[0] & 0b1000_0000;
        let highest = buf[0] & 0b1000_0000;
        if highest == 0 {
            break (ss, result, buf);
        }
    };

    if shift < size && (SIGN_BIT & buf[0]) == SIGN_BIT {
        result |= !0 << shift;
    }

    Ok((s, result))
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

        // println!("{:#?}", wasm);
        // println!("remaining: {:#?}", remaining);

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

    #[test]
    fn one_million() {
        let mut f = File::open("fixtures/1_000_000.wasm").unwrap();

        let mut buffer = Vec::new();
        f.read_to_end(&mut buffer).unwrap();

        let (_remaining, wasm) = parse(&buffer).unwrap();

        assert_eq!(wasm.version, 1);
    }

    #[test]
    fn it_does_a_module_with_imports() {
        let mut f = File::open("fixtures/wasm_import_test.wasm").unwrap();

        let mut buffer = Vec::new();
        f.read_to_end(&mut buffer).unwrap();

        let (remaining, wasm) = parse(&buffer).unwrap();

        println!(
            "{:?}",
            remaining.into_iter().take(50).cloned().collect::<Vec<u8>>()
        );
        assert_eq!(wasm.version, 1);

        // types section
        let types = &wasm.types.unwrap();
        assert_eq!(types.function_types[1].parameter_types.len(), 1);
        assert_eq!(types.function_types[1].parameter_types[0], ValType::I32);
        assert_eq!(types.function_types[1].result_types.len(), 0);

        // remaining
        assert!(remaining.is_empty())
    }
}
