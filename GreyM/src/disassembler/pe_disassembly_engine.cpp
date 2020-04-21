#include "pch.h"
#include "pe_disassembly_engine.h"
#include "../utils/defer.h"

PeDisassemblyEngine::PeDisassemblyEngine( const PortableExecutable pe )
    : pe_( pe ),
      disassembler_handle_( 0 ),
      code_( 0 ),
      current_code_index_( 0 ),
      current_instruction_code_( nullptr ),
      code_buf_size_( 0 ),
      address_( 0 ),
      pe_section_headers_( pe_.GetSectionHeaders() ),
      pe_text_section_header_( pe_section_headers_.FromName( ".text" ) ),
      pe_image_base_( pe_.GetNtHeaders()->OptionalHeader.ImageBase ) {
#ifdef _WIN64
  const cs_mode mode = cs_mode::CS_MODE_64;
#else
  const cs_mode mode = cs_mode::CS_MODE_32;
#endif

  const cs_err cs_status = cs_open( CS_ARCH_X86, mode, &disassembler_handle_ );

  if ( cs_status != cs_err::CS_ERR_OK ) {
    throw std::runtime_error( "cs_open failed with error code " +
                              std::to_string( cs_status ) );
  }

  const cs_err detail_status =
      cs_option( disassembler_handle_, cs_opt_type::CS_OPT_DETAIL, CS_OPT_ON );

  if ( detail_status != cs_err::CS_ERR_OK ) {
    throw std::runtime_error( "cs_option failed with error code " +
                              std::to_string( cs_status ) );
  }
}

void PeDisassemblyEngine::SetDisassemblyPoint(
    const DisassemblyPoint& disasm_point,
    const size_t disasm_buffer_size ) {
  code_ = disasm_point.code;
  address_ = disasm_point.rva;
  code_buf_size_ = disasm_buffer_size;
}

bool IsGuaranteedJump( const cs_insn& instruction ) {
  return instruction.id == x86_insn::X86_INS_JMP ||
         instruction.id == x86_insn::X86_INS_LJMP;
}

uintptr_t GetOperandRva( const cs_x86_op& operand,
                         const uintptr_t image_base ) {
  // in x64 pe, the disp is already the rva
  // x64: mov eax, dword ptr ds:[rcx+rax*4+0x10F2F4], (0x10F2F4 is the RVA)
  // x86: jmp dword ptr ds:[ecx*4+0x12EB9C8], (0x12EB9C8 is the rva + image
  // base)

  switch ( operand.type ) {
    case x86_op_type::X86_OP_IMM:
#ifdef _WIN64
      return static_cast<uintptr_t>( operand.imm );
#else
      return static_cast<uintptr_t>( operand.imm ) - image_base;
#endif
      break;
    case x86_op_type::X86_OP_MEM:
#ifdef _WIN64
      return static_cast<uintptr_t>( operand.mem.disp );
#else
      return static_cast<uintptr_t>( operand.mem.disp ) - image_base;
#endif
      break;
    default:
      break;
  }

  throw std::runtime_error( "should never occur" );
}

bool PeDisassemblyEngine::IsVTableOrFunction( const cs_x86_op& operand1,
                                              const cs_x86_op& operand2 ) {
  if ( operand1.type == x86_op_type::X86_OP_MEM &&
       operand2.type == x86_op_type::X86_OP_IMM ) {
    const auto dest_section = pe_section_headers_.FromRva(
        GetOperandRva( operand2, pe_image_base_ ) );
    // if the destination is in a section
    if ( dest_section != nullptr )
      return true;
  }

  return false;
}

bool PeDisassemblyEngine::IsJumpTable( const cs_insn& instruction,
                                       const uint8_t* code,
                                       const uint64_t rva ) {
  const auto& detail = instruction.detail->x86;
#ifdef _WIN64
  if ( detail.op_count == 2 ) {
    return IsJumpTableX64( instruction, detail.operands[ 0 ],
                           detail.operands[ 1 ], code, rva );
  }
#else
  if ( detail.op_count == 1 ) {
    return IsJumpTableX86( instruction, detail.operands[ 0 ] );
  }
#endif

  return false;
}

bool PeDisassemblyEngine::IsJumpTableX86( const cs_insn& instruction,
                                          const cs_x86_op& operand ) {
  // check if the jump is a jump table
  if ( IsGuaranteedJump( instruction ) ||
       instruction.id == x86_insn::X86_INS_MOV ) {
    if ( operand.type == x86_op_type::X86_OP_MEM &&
         operand.mem.scale == sizeof( uint32_t ) ) {
      const auto jump_table_rva = GetOperandRva( operand, pe_image_base_ );

      // is the jump table within the text section?
      if ( section::IsRvaWithinSection(
               *pe_text_section_header_,
               static_cast<uintptr_t>( jump_table_rva ) ) ) {
        return true;
      }
    }
  }

  return false;
}

bool PeDisassemblyEngine::IsJumpTableX64( const cs_insn& instruction,
                                          const cs_x86_op& operand1,
                                          const cs_x86_op& operand2,
                                          const uint8_t* code,
                                          const uint64_t rva ) {
  /*
    ja test executable.7FF6D311F222
    movsxd rax,dword ptr ss:[rbp+174]
    lea rcx,qword ptr ds:[7FF6D3010000]
    * mov eax,dword ptr ds:[rcx+rax*4+10F2F4]
    * add rax,rcx
    * jmp rax
  */

  // x64 jump table example: mov eax, dword ptr ds:[rcx+rax*4+0x10F2F4]
  if ( instruction.id == x86_insn::X86_INS_MOV ) {
    if ( operand1.type == x86_op_type::X86_OP_REG ) {
      if ( operand2.type == x86_op_type::X86_OP_MEM &&
           operand2.mem.scale == sizeof( uint32_t ) ) {
        // disassemble the next 2 instructions
        assert( ( code_buf_size_ - current_code_index_ ) > 0 );

        auto code_copy = code + instruction.size;
        auto code_size = code_buf_size_ - current_code_index_;
        uint64_t rva_copy = rva + static_cast<uint64_t>( instruction.size );

        cs_insn* instruction2 = cs_malloc( disassembler_handle_ );
        Defer( { cs_free( instruction2, 1 ); } );

        // disassemble first instruction
        auto disasm_status =
            cs_disasm_iter( disassembler_handle_, &code_copy, &code_size,
                            &rva_copy, instruction2 );

        if ( instruction2->id != x86_insn::X86_INS_ADD )
          return false;

        if ( instruction2->detail->x86.op_count != 2 )
          return false;

        if ( instruction2->detail->x86.operands[ 0 ].type !=
                 x86_op_type::X86_OP_REG ||
             instruction2->detail->x86.operands[ 1 ].type !=
                 x86_op_type::X86_OP_REG )
          return false;

        const auto saved_add_operand1 =
            instruction2->detail->x86.operands[ 0 ].reg;

        // disassemble second instruction
        disasm_status = cs_disasm_iter( disassembler_handle_, &code_copy,
                                        &code_size, &rva_copy, instruction2 );

        // check if we are jumping to the previously used register in MOV
        if ( IsGuaranteedJump( *instruction2 ) &&
             instruction2->detail->x86.operands[ 0 ].type ==
                 x86_op_type::X86_OP_REG &&
             instruction2->detail->x86.operands[ 0 ].reg == saved_add_operand1 )
          return true;
      }
    }
  }
  return false;
}

DisassemblyPoint
PeDisassemblyEngine::GetOperandDestinationValueDisassasemblyPoint(
    const cs_insn& instruction,
    const uint8_t* instruction_code_ptr,
    const uintptr_t rva ) {
  const auto operand_dest_rva = rva;

  const uint8_t* operand_dest_code = nullptr;

  // In the MOV instruction, the rva we are looking for is an absolute rva,
  // therefore we convert the value to a file offset manually
  if ( instruction.id == x86_insn::X86_INS_MOV ) {
    const auto pe_image_code_ptr = pe_.GetPeImagePtr();
    const auto file_offset =
        pe_section_headers_.RvaToFileOffset( operand_dest_rva );
    operand_dest_code = pe_image_code_ptr + file_offset;
  } else {
    // push or jmp
    const auto dest_delta = operand_dest_rva - instruction.address;
    operand_dest_code = instruction_code_ptr + dest_delta;
  }

  assert( operand_dest_code != nullptr );

  DisassemblyPoint disasm_point;
  disasm_point.rva = operand_dest_rva;
  disasm_point.code = operand_dest_code;

  return disasm_point;
}

void PeDisassemblyEngine::ParseJumpTable( const cs_insn& instruction,
                                          const cs_x86_op& operand ) {
  assert( operand.type == x86_op_type::X86_OP_MEM );

  const auto operand_rva = GetOperandRva( operand, pe_image_base_ );

  AddressRange jump_table_address_range;

  jump_table_address_range.begin_address = operand_rva;

  int i = 0;

  for ( ;; i += operand.mem.scale ) {
    // #ifndef _WIN64
    const auto jump_table_disasm_point =
        GetOperandDestinationValueDisassasemblyPoint(
            instruction, current_instruction_code_, operand_rva );
    //#else
    //    // in x64 mode, the jump tables are MOV's and not JMP's
    //    // meaning that the jump table address is not relative, but absolute
    //    const auto dest_delta = operand_rva - instruction.address;
    //
    //    auto operand_dest_code = current_instruction_code_ + dest_delta;
    //
    //    DisassemblyPoint jump_table_disasm_point;
    //    jump_table_disasm_point.rva = dest_delta;
    //    jump_table_disasm_point.code = const_cast<uint8_t*>( operand_dest_code
    //    );
    //#endif

    const auto jump_table_dest_section =
        pe_section_headers_.FromRva( jump_table_disasm_point.rva );

    // is the jump table located inside any section?
    if ( jump_table_dest_section == nullptr )
      break;

    // is the target function/address within the text section?
    // if ( !pe::IsRvaWithinSection( *pe_text_section_,
    // jump_table_disasm_point.rva) )
    //   break;

    const auto jump_table_code_dest = jump_table_disasm_point.code + i;

    // if the scale is different, then we line below this line won't work
    assert( operand.mem.scale == sizeof( uint32_t ) );

    const auto item_dest_va =
        *reinterpret_cast<const uint32_t*>( jump_table_code_dest );

    // did we reach the end?
    if ( item_dest_va == 0xCCCCCCCC || item_dest_va == 0 )
      break;

#ifdef _WIN64
    const auto item_dest_rva = item_dest_va;  // x64: item_dest_va is also rva,
        // need not subtract image base
#else
    const auto item_dest_rva =
        item_dest_va - pe_image_base_;  // x86: item_dest_va is rva + image base
#endif

    // is the target function/address within the text section?
    if ( !section::IsRvaWithinSection( *pe_text_section_header_,
                                       item_dest_rva ) )
      break;

    const auto item_dest_delta = item_dest_rva - instruction.address;
    const auto item_dest_code = current_instruction_code_ + item_dest_delta;

    DisassemblyPoint disasm_point;
    disasm_point.rva = item_dest_rva;
    disasm_point.code = reinterpret_cast<const uint8_t*>( item_dest_code );

    AddDisassemblyPoint( disasm_point );
  }

  jump_table_address_range.end_address = operand_rva + i;

  data_ranges_.push_back( jump_table_address_range );
}

// checks if the current address that is being disassembled is within a part
// of data within the code section, example a jump table
bool PeDisassemblyEngine::IsAddressWithinDataSectionOfCode(
    const uint64_t address ) {
  for ( const auto& range : data_ranges_ ) {
    // if the current address is within a data section of the .text
    // section example a jump table
    if ( address >= range.begin_address && address < range.end_address ) {
      return true;
    }
  }

  return false;
};

bool PeDisassemblyEngine::IsFunction( const DisassemblyPoint& disasm_point ) {
#ifdef _WIN64
  return IsFunctionX64( disasm_point );
#else
  return IsFunctionX86( disasm_point, 0 );
#endif
}

// Returns true whether or not the instructions are the pattern:
// push ebp
// mov ebp, esp
bool IsFunctionX86Prolog( cs_insn instructions[ 2 ] ) {
  // Ensure the instructions have the correct operand counts
  if ( instructions[ 0 ].detail->x86.op_count != 1 &&
       instructions[ 1 ].detail->x86.op_count != 2 ) {
    return false;
  }

  bool is_push_ebp =
      instructions[ 0 ].id == x86_insn::X86_INS_PUSH &&
      instructions[ 0 ].detail->x86.operands[ 0 ].reg == x86_reg::X86_REG_EBP;

  bool is_mov_ebp_esp =
      instructions[ 1 ].id == x86_insn::X86_INS_MOV &&
      instructions[ 1 ].detail->x86.operands[ 0 ].reg == x86_reg::X86_REG_EBP &&
      instructions[ 1 ].detail->x86.operands[ 1 ].reg == x86_reg::X86_REG_ESP;

  return is_push_ebp && is_mov_ebp_esp;
}

bool PeDisassemblyEngine::IsFunctionX86( const DisassemblyPoint& disasm_point,
                                         int recursion_counter ) {
  const auto rva = disasm_point.rva;
  const auto code = disasm_point.code;

  // we only try to follow jumps 10 times deep
  if ( recursion_counter > 10 )
    return false;

  // Added a temporary check to know whether or not we might even check if code is a function in a non-.text section
  // If this ever occurs, simply change it to an if statement and return false it not in .text section
  assert( section::IsRvaWithinSection( *pe_text_section_header_, rva ) );

  cs_insn* instructions = nullptr;

  assert( ( code_buf_size_ - current_code_index_ ) > 0 );

  const auto kDisassembleInstructionCount = 3;

  const auto disassembled_instruction_count = cs_disasm(
      disassembler_handle_, code, code_buf_size_ - current_code_index_, rva,
      kDisassembleInstructionCount, &instructions );

  Defer( { cs_free( instructions, disassembled_instruction_count ); } );

  if ( disassembled_instruction_count != kDisassembleInstructionCount ) {
    return false;
  }

  auto instruction1 = &instructions[ 0 ];
  auto instruction2 = &instructions[ 1 ];

  if ( IsGuaranteedJump( *instruction1 ) ) {
    const auto& operand = instruction1->detail->x86.operands[ 0 ];
    const auto jump_target_rva = operand.imm;
    const auto jump_dest_disasm_point =
        GetOperandDestinationValueDisassasemblyPoint(
            *instruction1, code, static_cast<uintptr_t>( jump_target_rva ) );
    if ( !section::IsRvaWithinSection( *pe_text_section_header_,
                                       jump_dest_disasm_point.rva ) )
      return false;

    return IsFunctionX86( jump_dest_disasm_point, ++recursion_counter );
  }

  bool is_function = false;

  // if the first instruction is mov edi, edi
  if ( instruction1->id == x86_insn::X86_INS_MOV &&
       instruction1->detail->x86.op_count == 2 &&
       instruction1->detail->x86.operands[ 0 ].reg == x86_reg::X86_REG_EDI &&
       instruction1->detail->x86.operands[ 1 ].reg == x86_reg::X86_REG_EDI ) {
    // Check the function prologue on the next instructions skipping the mov edi, edi
    is_function = IsFunctionX86Prolog( instructions + 1 );
  } else {
    is_function = IsFunctionX86Prolog( instructions );
  }

  // TODO: Check for the epilogue as well
  // mov esp, ebp         ; restore ESP
  // pop ebp              ; restore caller's EBP
  // ret                  ; pop the return address into EIP

  return is_function;
}

bool IsNonVolatileRegister( x86_reg reg ) {
  /*
    Nonvolatilve Registers that must be preseved by the callee:
      R12:R15
      RDI
      RSI
      RBX
      RBP
      RSP
  */

  switch ( reg ) {
    case x86_reg::X86_REG_R12:
    case x86_reg::X86_REG_R13:
    case x86_reg::X86_REG_R14:
    case x86_reg::X86_REG_R15:
    case x86_reg::X86_REG_RDI:
    case x86_reg::X86_REG_RSI:
    case x86_reg::X86_REG_RBX:
    case x86_reg::X86_REG_RBP:
    case x86_reg::X86_REG_RSP:
      return true;
      break;
    default:
      break;
  }

  return false;
};

bool PeDisassemblyEngine::IsFunctionX64(
    const DisassemblyPoint& disasm_point ) {
  assert( ( code_buf_size_ - current_code_index_ ) > 0 );
  bool is_function = false;

  // NOTE: Unsure whether or not this size is correctly calculated, feels off
  auto size = code_buf_size_ - current_code_index_;

  auto code = disasm_point.code;
  auto rva = static_cast<uint64_t>( disasm_point.rva );

  cs_insn* instruction = cs_malloc( disassembler_handle_ );
  Defer( { cs_free( instruction, 1 ); } );

  const auto disasm_status =
      cs_disasm_iter( disassembler_handle_, &code, &size, &rva, instruction );

  if ( !disasm_status ) {
    // If it failed to disassemble the first instruction, it is definitely not a function
    return false;
  }

  assert( instruction );

  // Is the first instruction a jump to the real function?
  if ( IsGuaranteedJump( *instruction ) ) {
    const auto& operand = instruction->detail->x86.operands[ 0 ];
    const auto jump_target_rva = operand.imm;
    const auto jump_dest_disasm_point =
        GetOperandDestinationValueDisassasemblyPoint(
            *instruction, disasm_point.code,
            static_cast<uintptr_t>( jump_target_rva ) );

    if ( !section::IsRvaWithinSection( *pe_text_section_header_,
                                       jump_dest_disasm_point.rva ) ) {
      return false;
    }

    is_function = IsFunctionX64Prolog( jump_dest_disasm_point );
  } else {
    is_function = IsFunctionX64Prolog( disasm_point );
  }

  return is_function;
}

bool PeDisassemblyEngine::IsFunctionX64Prolog(
    const DisassemblyPoint& disasm_point ) {
  /*
    NOTE: Epilog checking is no longer implemented, it was too inconsistent

    https://docs.microsoft.com/en-us/cpp/build/prolog-and-epilog?view=vs-2019
    https://docs.microsoft.com/en-us/cpp/build/x64-software-conventions?view=vs-2019

    Checks if valid x64 function prolog
    What's requirements of valid prolog?

    * First instruction of prolog must exist within 10/5/2 first instructions

    * Must contain at least one type of fixed-stack-alloc instruction
        sub rsp, stack-alloc-size
        or
        lea    R13, 128[RSP] ????

    * If it contains more prolog instructions, all of them must be valid prolog instructions
      The following are valid:
        mov [rsp + any-value % 8 == 0 ], reg (any reg?)
        push non-volatile-reg

        mov rax, rsp
        mov [rax + any-value % 8 == 0], reg (any reg?)


    What does this function do?
    It simply looks for the prolog in the beginning.

    Example x64 function:

    Prolog Description:
    1. MOV's
      Sets up the stack frame pointer for either RSP or RAX, possibly other registers as well. Unsure.
    2. PUSH's
      Preserves the non volatile registers
    3. SUB
      Allocated a fixed size of the stack

    Prolog:
    mov    [RSP + 8], RCX
    push   R15
    push   R14
    push   R13
    sub    RSP, 20

    Epilog Description:
    1. MOV's
      Tears up the frame pointer and gives back the values on the registers previously.
    2. ADD
      Free's the fixed allocated stack
    3. POP's
      Restores the non-volatile registers in the opposite order of the prolog
    4. RET

    Epilog:

    mov    RCX, [RSP + 8]
    add    RSP, 20
    pop    R13
    pop    R14
    pop    R15
    ret
  */

  const auto is_stack_frame_pointer_setup = []( cs_insn* instruction ) {
    // NOTE: In some functions, the instruction: mov rax, rsp
    //                                          mov r11, rsp
    // which sets up the stack frame pointer.
    // the registers are moved into [rax + ?] and not [rsp + ?]

    // mov r11, rsp          <--- This is the stack frame pointer setup
    // mov [r11 + 8], rbx
    // mov [r11 + 16], rsi
    // push rdi
    // sub rsp, 80

    const auto& detail = instruction->detail->x86;

    // is mov ?, ?
    if ( instruction->id == x86_insn::X86_INS_MOV && detail.op_count == 2 ) {
      const auto& operand1 = detail.operands[ 0 ];
      const auto& operand2 = detail.operands[ 1 ];

      // is mov reg, reg
      if ( operand1.type == x86_op_type::X86_OP_REG &&
           operand2.type == x86_op_type::X86_OP_REG ) {
        // is mov reg, rsp
        if ( operand2.reg == x86_reg::X86_REG_RSP ) {
          return true;
        }
      }
    }

    return false;
  };

  const auto is_valid_stack_frame_pointer_setup_instruction =
      []( cs_insn* instruction, x86_reg stack_frame_pointer_reg ) {
        // mov r11, rsp
        // mov [r11 + 8], rbx       <--- This is the stack frame pointer setup instruction
        // mov [r11 + 16], rsi      <--- This is the stack frame pointer setup instruction
        // push rdi
        // sub rsp, 80

        const auto& detail = instruction->detail->x86;

        // is mov ?, ?
        if ( instruction->id == x86_insn::X86_INS_MOV &&
             detail.op_count == 2 ) {
          const auto& operand1 = detail.operands[ 0 ];

          // is mov [stack_frame_pointer_reg + ?], ?
          if ( operand1.type == x86_op_type::X86_OP_MEM &&
               operand1.mem.base == stack_frame_pointer_reg ) {
            const bool is_on_a_x64_alignment =
                operand1.mem.disp % sizeof( uint64_t ) == 0;

            const auto& operand2 = detail.operands[ 1 ];

            // is mov [rsp + ?], reg
            if ( operand2.type == x86_op_type::X86_OP_REG &&
                 is_on_a_x64_alignment ) {
              return true;
            }
          }
        }

        return false;
      };

  const auto is_valid_preserve_reg_instruction = []( cs_insn* instruction,
                                                     x86_insn instruction_id ) {
    // mov r11, rsp
    // mov [r11 + 8], rbx
    // mov [r11 + 16], rsi
    // push rdi                 <--- This is the preserve register instruction
    // sub rsp, 80

    const auto& detail = instruction->detail->x86;

    // is push ?
    if ( instruction->id == instruction_id && detail.op_count == 1 ) {
      const auto& operand = detail.operands[ 0 ];

      // is push reg
      if ( operand.type == x86_op_type::X86_OP_REG ) {
        // is push non-volatile-reg
        if ( IsNonVolatileRegister( operand.reg ) ) {
          return true;
        }
      }
    }

    return false;
  };

  const auto is_valid_push = [&]( cs_insn* instruction ) {
    return is_valid_preserve_reg_instruction( instruction,
                                              x86_insn::X86_INS_PUSH );
  };

  const auto is_valid_fixed_stack_instruction = []( cs_insn* instruction,
                                                    x86_insn instruction_id ) {
    // mov r11, rsp
    // mov [r11 + 8], rbx
    // mov [r11 + 16], rsi
    // push rdi
    // sub rsp, 80            <--- This is the fixed stack alloc instruction

    const auto& detail = instruction->detail->x86;

    // is sub ?, ?
    if ( instruction->id == instruction_id && detail.op_count == 2 ) {
      const auto& operand1 = detail.operands[ 0 ];

      // is sub rsp, ?
      if ( operand1.type == x86_op_type::X86_OP_REG &&
           operand1.reg == x86_reg::X86_REG_RSP ) {
        const auto& operand2 = detail.operands[ 1 ];

        // Unique case if the stack allocated is larger than a page of
        // memory, handle when occurs to know if correct
        assert( operand2.imm < 0x1000 );

        // is sub rsp, imm
        if ( operand2.type == x86_op_type::X86_OP_IMM ) {
          return true;
        }
      }
    }

    return false;
  };

  const auto is_valid_sub = [&]( cs_insn* instruction ) {
    return is_valid_fixed_stack_instruction( instruction,
                                             x86_insn::X86_INS_SUB );
  };

  auto code = disasm_point.code;
  auto rva = static_cast<uint64_t>( disasm_point.rva );

  // NOTE: Unsure whether or not this size is correctly calculated, feels off
  auto size = code_buf_size_ - current_code_index_;

  cs_insn* instruction = cs_malloc( disassembler_handle_ );
  Defer( { cs_free( instruction, 1 ); } );

  uint32_t setup_stackframe_pointer_instructions_count = 0;
  uint32_t preserved_registers_count = 0;
  bool has_allocating_stack_instruction = false;

  enum class PrologSteps {
    FindStackFramePointerRegister,
    FindStackFramePointerSetup,
    FindPreserveNonVolatileRegisters,
    FindFixedStack,
  };

  PrologSteps current_prolog_step = PrologSteps::FindStackFramePointerRegister;

  bool is_function = false;

  bool next_instruction = true;

  bool finished = false;

  constexpr x86_reg kDefaultStackFramePointerReg = x86_reg::X86_REG_RSP;
  x86_reg stack_frame_pointer_reg = kDefaultStackFramePointerReg;

  cs_insn* first_instruction = cs_malloc( disassembler_handle_ );

  Defer( { cs_free( first_instruction, 1 ); } );

  auto code_copy = code;
  auto rva_copy = rva;
  auto size_copy = size;

  const auto disasm_status =
      cs_disasm_iter( disassembler_handle_, &code_copy, &size_copy, &rva_copy,
                      first_instruction );

  if ( !disasm_status ) {
    // Is no function
    return false;
  }

  const bool is_prolog_instruction =
      is_stack_frame_pointer_setup( first_instruction ) ||
      is_valid_stack_frame_pointer_setup_instruction(
          first_instruction, stack_frame_pointer_reg ) ||
      is_valid_push( first_instruction ) || is_valid_sub( first_instruction );

  // If the first instruction is not a instruction valid for the prolog
  if ( !is_prolog_instruction ) {
    // Is no function
    return false;
  }

  while ( !finished ) {
    if ( next_instruction ) {
      const auto disasm_status = cs_disasm_iter( disassembler_handle_, &code,
                                                 &size, &rva, instruction );

      // If it failed to disassemble the instruction, we cannot
      // only assume we have reached invalid executable code
      if ( !disasm_status ) {
        is_function = false;
        finished = true;
        break;
      }

      const bool is_interrupt = cs_insn_group(
          disassembler_handle_, instruction, cs_group_type::CS_GRP_INT );

      const bool is_ret = cs_insn_group( disassembler_handle_, instruction,
                                         cs_group_type::CS_GRP_RET );

      // If the instruction is an e.g INT3, then we have gone outside the bounds of the function
      if ( is_interrupt || is_ret ) {
        is_function = false;
        finished = true;
        break;
      }

      next_instruction = false;
    }

    switch ( current_prolog_step ) {
      case PrologSteps::FindStackFramePointerRegister: {
        if ( is_stack_frame_pointer_setup( instruction ) ) {
          // Save the stack frame pointer register for use in the next step
          stack_frame_pointer_reg = instruction->detail->x86.operands[ 0 ].reg;
          next_instruction = true;
        }

        // If the first instruction is not this, we assume it will never
        // go the next or next one again. Therefore we go immediately to the next step
        current_prolog_step = PrologSteps::FindStackFramePointerSetup;
      } break;

      case PrologSteps::FindStackFramePointerSetup: {
        if ( is_valid_stack_frame_pointer_setup_instruction(
                 instruction, stack_frame_pointer_reg ) ) {
          ++setup_stackframe_pointer_instructions_count;
          next_instruction = true;
        } else {
          // If there are no stack frame pointer setup instructions, BUT there is a stack frame pointer register setup
          // Then it is really fuckin' fishy bruh. Probably not a function.
          if ( stack_frame_pointer_reg != kDefaultStackFramePointerReg &&
               setup_stackframe_pointer_instructions_count <= 0 ) {
            is_function = false;
            finished = true;
            break;
          }

          current_prolog_step = PrologSteps::FindPreserveNonVolatileRegisters;
        }
      } break;

      case PrologSteps::FindPreserveNonVolatileRegisters: {
        if ( is_valid_push( instruction ) ) {
          ++preserved_registers_count;
          next_instruction = true;
        } else {
          current_prolog_step = PrologSteps::FindFixedStack;
        }
      } break;

      case PrologSteps::FindFixedStack: {
        if ( is_valid_sub( instruction ) ) {
          has_allocating_stack_instruction = true;
        } else {
          has_allocating_stack_instruction = false;
        }

        // Require that we have preserved registers and allocated a
        // stack in a prolog for to be a valid function
        const bool prolog_exists =
            preserved_registers_count > 0 && has_allocating_stack_instruction;

        // If no prolog exists, it is no valid function
        if ( !prolog_exists ) {
          is_function = false;
          finished = true;
          break;
        } else {
          is_function = true;
          finished = true;
          break;
        }
      } break;
      default:
        assert( false );
        break;
    }
  }

  return is_function;
}

DisassemblyAction PeDisassemblyEngine::ParseInstruction(
    const cs_insn& instruction ) {
  const bool is_ret = cs_insn_group( disassembler_handle_, &instruction,
                                     cs_group_type::CS_GRP_RET );
  const bool is_interrupt = cs_insn_group( disassembler_handle_, &instruction,
                                           cs_group_type::CS_GRP_INT );
  const bool is_jump = cs_insn_group( disassembler_handle_, &instruction,
                                      cs_group_type::CS_GRP_JUMP );
  const bool is_call = cs_insn_group( disassembler_handle_, &instruction,
                                      cs_group_type::CS_GRP_CALL );

  const auto& ins_detail = instruction.detail->x86;

  if ( is_ret ) {
    // if the instruction is a return
    return DisassemblyAction::NextDisassemblyPoint;
  } else if ( is_call || is_jump ) {
    if ( ins_detail.op_count == 1 ) {
      const auto& operand = ins_detail.operands[ 0 ];

      if ( operand.type == x86_op_type::X86_OP_IMM ) {
        const auto dest_delta = operand.imm - instruction.address;

        // since the capstone api automatically increases the code and address
        // after disassembling the instruction, we have to calulcate the
        // original code pointer outselves.
        const uint8_t* instruction_code_ptr = code_ - instruction.size;

        DisassemblyPoint disasm_point;
        disasm_point.rva =
            static_cast<uintptr_t>( instruction.address + dest_delta );
        disasm_point.code =
            const_cast<uint8_t*>( instruction_code_ptr ) + dest_delta;

        AddDisassemblyPoint( disasm_point );

        if ( IsGuaranteedJump( instruction ) ) {
          // go immediately parse the jump destination
          return DisassemblyAction::NextDisassemblyPoint;
        } else {
          // continue disassembling on the next instruction
          return DisassemblyAction::NextInstruction;
        }
      } else if ( IsJumpTable( instruction, current_instruction_code_,
                               instruction.address ) ) {
        ParseJumpTable( instruction, operand );
        return DisassemblyAction::NextDisassemblyPoint;
      }
    } else {
      // invalid instruction, return ti another disassembly point
      return DisassemblyAction::NextDisassemblyPoint;
      // assert( false );
    }

    if ( IsGuaranteedJump( instruction ) ) {
      // go immediately parse the jump destination
      return DisassemblyAction::NextDisassemblyPoint;
    } else {
      // continue on the next instruction
      return DisassemblyAction::NextInstruction;
    }
  } else if ( is_interrupt ) {
    return DisassemblyAction::NextDisassemblyPoint;
  } else {
    if ( instruction.address == 0x10F1A6 ) {
      int test = 0;
    }

    switch ( instruction.id ) {
      case x86_insn::X86_INS_MOV: {
        switch ( ins_detail.op_count ) {
          case 2: {
            const auto& operand1 = ins_detail.operands[ 0 ];
            const auto& operand2 = ins_detail.operands[ 1 ];

            if ( IsJumpTable( instruction, current_instruction_code_,
                              instruction.address ) ) {
#ifndef _WIN64
              assert( false &&
                      "did we reach this in x86, we're only supposed to be "
                      "here in x64 for jump tables." );
#endif
              ParseJumpTable( instruction, operand2 );
              return DisassemblyAction::NextDisassemblyPoint;
            } else if ( IsVTableOrFunction( operand1, operand2 ) ) {
              // mov mem_op, imm_op
              // if is function

              const auto dest_disasm_point =
                  GetOperandDestinationValueDisassasemblyPoint(
                      instruction, current_instruction_code_,
                      GetOperandRva( operand2, pe_image_base_ ) );

              // if we are not in the text section, then don't even bother
              // checking if it is a function it is most likely a pointer to the
              // .rdata section or something
              if ( section::IsRvaWithinSection( *pe_text_section_header_,
                                                dest_disasm_point.rva ) &&
                   IsFunction( dest_disasm_point ) ) {
                AddDisassemblyPoint( dest_disasm_point );
                return DisassemblyAction::NextInstruction;
              } else {
                // if not a function, the maybe a vtable

                // TODO: Fix the function when we even come to a function that
                // has a vtable
                /*
                for ( int i = 0;; i += 4 ) {
                  const auto jump_table_disasm_point =
                      GetOperandDestinationValueDisassasemblyPoint(
                          instruction, current_instruction_code_,
                          GetOperandRva( operand2, pe_image_base_ ) );

                  // if the jump table is not within the text section? really?
                  // what? if ( !pe::IsRvaWithinSection( *pe_text_section_,
                  //                               jump_table_disasm_point.rva )
                  //                               )
                  //   break;

                  if ( pe::GetSectionByRva( pe_sections_,
                                            jump_table_disasm_point.rva ) ==
                       nullptr )
                    break;

                  const auto jump_table_code_dest =
                      jump_table_disasm_point.code + i;

                  const auto item_dest_va = *reinterpret_cast<const uint32_t*>(
                      jump_table_code_dest );

                  // did we reach the end?
                  if ( item_dest_va == 0xCCCCCCCC )
                    break;

#ifdef _WIN64
                  const auto item_dest_rva =
                      item_dest_va;  // x64: item_dest_va is also rva,
                                     // need not subtract image base
#else
                  const auto item_dest_rva =
                      item_dest_va -
                      pe_image_base_;  // x86: item_dest_va is rva + image base
#endif

                  // is the target function/address within the text section?
                  if ( !pe::IsRvaWithinSection( *pe_text_section_,
                                                item_dest_rva ) )
                    break;

                  const auto item_dest_delta =
                      item_dest_rva - instruction.address;
                  const auto item_dest_code =
                      current_instruction_code_ + item_dest_delta;

                  // TODO: add it to the disassembly points array here
                  DisassemblyPoint disasm_point;
                  disasm_point.rva = item_dest_rva;
                  disasm_point.code = const_cast<uint8_t*>( item_dest_code );

                  if ( IsFunction( disasm_point.code, disasm_point.rva ) ) {
                    // it is a jump table with valid functions lol
                    int test = 0;
                  }
                }
                */
              }
            }
          } break;
          default:
            break;
        }
      } break;

      case x86_insn::X86_INS_PUSH: {
        const auto operand = ins_detail.operands[ 0 ];
        if ( operand.type == x86_op_type::X86_OP_IMM ) {
          const auto operand_rva = GetOperandRva( operand, pe_image_base_ );

          if ( section::IsRvaWithinSection( *pe_text_section_header_,
                                            operand_rva ) ) {
            const auto dest_disasm =
                GetOperandDestinationValueDisassasemblyPoint(
                    instruction, current_instruction_code_, operand_rva );

            if ( IsFunction( dest_disasm ) ) {
              AddDisassemblyPoint( dest_disasm );
            }
          }
        }
      } break;

      default:
        break;
    }
  }

  return DisassemblyAction::NextInstruction;
}

bool PeDisassemblyEngine::ContinueFromDisassemblyPoints() {
  if ( disassembly_points_.empty() ) {
    return false;
  }

  const auto next_disasm_point = disassembly_points_.back();

  code_ = next_disasm_point.code;
  address_ = next_disasm_point.rva;

  disassembly_points_.pop_back();

  return true;
}

void PeDisassemblyEngine::ParseRDataSection() {
  const auto rdata_section_header = pe_section_headers_.FromName( ".rdata" );

  if ( rdata_section_header == nullptr ) {
    throw std::runtime_error( ".rdata was not found" );
  }

  const auto pe_image_ptr = pe_.GetPeImagePtr();

  auto rdata_ptr = pe_image_ptr + rdata_section_header->PointerToRawData;

  const auto rdata_end = rdata_ptr + rdata_section_header->SizeOfRawData;

  for ( ; rdata_ptr < rdata_end; rdata_ptr += sizeof( uintptr_t ) ) {
    const auto value = *reinterpret_cast<const uintptr_t*>( rdata_ptr );

    if ( value == 0 ) {
      continue;
    }

    // We subtract the image base to check whether or not it is a valid RVA value
    const auto value_rva = value - pe_image_base_;

    // Is the rva valid and within the .text section?
    if ( section::IsRvaWithinSection( *pe_text_section_header_, value_rva ) ) {
      const auto value_file_offset =
          pe_section_headers_.RvaToFileOffset( value_rva );

      if ( value_file_offset == 0 ) {
        continue;
      }

      const auto value_destination_ptr = pe_image_ptr + value_file_offset;

      DisassemblyPoint disasm_point;
      {
        disasm_point.code = value_destination_ptr;
        disasm_point.rva = value_rva;
      }

      if ( IsFunction( disasm_point ) ) {
        AddDisassemblyPoint( disasm_point );
      }
    }
  }
}

void PeDisassemblyEngine::ParseTlsCallbacks() {
  const auto nt_headers = pe_.GetNtHeaders();
  const auto image_base = nt_headers->OptionalHeader.ImageBase;

  const auto sections = pe_.GetSectionHeaders();

  const auto tls_callback_list = pe_.GetTlsCallbacklist();

  for ( const auto callback : tls_callback_list ) {
    DisassemblyPoint disasm_point;

    const auto rva = callback - image_base;

    const auto callback_code_offset = sections.RvaToFileOffset( rva );

    disasm_point.rva = rva;
    disasm_point.code = pe_.GetPeImagePtr() + callback_code_offset;

    AddDisassemblyPoint( disasm_point );
  }
}

void PeDisassemblyEngine::AddDisassemblyPoint(
    const DisassemblyPoint& disasm_point ) {
  const bool exists = disassembly_points_cache_.find( disasm_point.rva ) !=
                      disassembly_points_cache_.end();

  if ( !exists ) {
    disassembly_points_.push_back( disasm_point );
    disassembly_points_cache_.insert( disasm_point.rva );
  }
}