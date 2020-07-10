#include "pch.h"
#include "virtualizer.h"
#include "../utils/shellcode.h"

namespace virtualizer {

/*
// Checks if operand is reg
bool IsOperandReg( const cs_x86_op& operand ) {
  return operand.type == x86_op_type::X86_OP_REG;
}
*/

// Checks if the operand is [immediate addr]
bool IsOperandMemoryImmediate( const cs_x86_op& operand ) {
  return operand.type == x86_op_type::X86_OP_MEM &&
         operand.mem.base == x86_reg::X86_REG_INVALID &&
         operand.mem.index == x86_reg::X86_REG_INVALID &&
         operand.mem.segment == x86_reg::X86_REG_INVALID &&
         operand.mem.disp != 0;
}

// Checks if the operand is [reg +- offset]
bool IsOperandMemoryRegOffset( const cs_x86_op& operand ) {
  return operand.type == x86_op_type::X86_OP_MEM &&
         operand.mem.segment == x86_reg::X86_REG_INVALID &&
         operand.mem.base != x86_reg::X86_REG_INVALID &&
         operand.mem.index == x86_reg::X86_REG_INVALID && operand.mem.disp != 0;
}

int GetVmRegisterOffsetFromX86Reg( const x86_reg reg ) {
  // The register variantes can be found on this link
  // https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/x64-architecture

  // Just checking to ensure there are not x64 registers when compiling in x86
#ifndef _WIN64
  switch ( reg ) {
    case x86_reg::X86_REG_RAX:
    case x86_reg::X86_REG_RBX:
    case x86_reg::X86_REG_RCX:
    case x86_reg::X86_REG_RDX:
    case x86_reg::X86_REG_RSI:
    case x86_reg::X86_REG_RDI:
    case x86_reg::X86_REG_RBP:
      assert( false );
    default:
      break;
  };
#endif

  switch ( reg ) {
    case x86_reg::X86_REG_RAX:
    case x86_reg::X86_REG_EAX:
    case x86_reg::X86_REG_AX:
    case x86_reg::X86_REG_AL:
      return offsetof( VmRegisters, eax );
    case x86_reg::X86_REG_RBX:
    case x86_reg::X86_REG_EBX:
    case x86_reg::X86_REG_BX:
    case x86_reg::X86_REG_BL:
      return offsetof( VmRegisters, ebx );
    case x86_reg::X86_REG_RCX:
    case x86_reg::X86_REG_ECX:
    case x86_reg::X86_REG_CX:
    case x86_reg::X86_REG_CL:
      return offsetof( VmRegisters, ecx );
    case x86_reg::X86_REG_RDX:
    case x86_reg::X86_REG_EDX:
    case x86_reg::X86_REG_DX:
    case x86_reg::X86_REG_DL:
      return offsetof( VmRegisters, edx );
    case x86_reg::X86_REG_RSI:
    case x86_reg::X86_REG_ESI:
    case x86_reg::X86_REG_SI:
    case x86_reg::X86_REG_SIL:
      return offsetof( VmRegisters, esi );
    case x86_reg::X86_REG_RDI:
    case x86_reg::X86_REG_EDI:
    case x86_reg::X86_REG_DI:
    case x86_reg::X86_REG_DIL:
      return offsetof( VmRegisters, edi );
    case x86_reg::X86_REG_RBP:
    case x86_reg::X86_REG_EBP:
    case x86_reg::X86_REG_BP:
    case x86_reg::X86_REG_BPL:
      return offsetof( VmRegisters, ebp );

#ifdef _WIN64
    case x86_reg::X86_REG_R15:
    case x86_reg::X86_REG_R15D:
    case x86_reg::X86_REG_R15W:
    case x86_reg::X86_REG_R15B:
      return offsetof( VmRegisters, r15 );
    case x86_reg::X86_REG_R14:
    case x86_reg::X86_REG_R14D:
    case x86_reg::X86_REG_R14W:
    case x86_reg::X86_REG_R14B:
      return offsetof( VmRegisters, r14 );
    case x86_reg::X86_REG_R13:
    case x86_reg::X86_REG_R13D:
    case x86_reg::X86_REG_R13W:
    case x86_reg::X86_REG_R13B:
      return offsetof( VmRegisters, r13 );
    case x86_reg::X86_REG_R12:
    case x86_reg::X86_REG_R12D:
    case x86_reg::X86_REG_R12W:
    case x86_reg::X86_REG_R12B:
      return offsetof( VmRegisters, r12 );
    case x86_reg::X86_REG_R11:
    case x86_reg::X86_REG_R11D:
    case x86_reg::X86_REG_R11W:
    case x86_reg::X86_REG_R11B:
      return offsetof( VmRegisters, r11 );
    case x86_reg::X86_REG_R10:
    case x86_reg::X86_REG_R10D:
    case x86_reg::X86_REG_R10W:
    case x86_reg::X86_REG_R10B:
      return offsetof( VmRegisters, r10 );
    case x86_reg::X86_REG_R9:
    case x86_reg::X86_REG_R9D:
    case x86_reg::X86_REG_R9W:
    case x86_reg::X86_REG_R9B:
      return offsetof( VmRegisters, r9 );
    case x86_reg::X86_REG_R8:
    case x86_reg::X86_REG_R8D:
    case x86_reg::X86_REG_R8W:
    case x86_reg::X86_REG_R8B:
      return offsetof( VmRegisters, r8 );
#endif
    default:
      break;
  }

  return -1;
}

VmRegister GetVmRegisterOffsetFromX86ImmediateReg( const cs_x86_op& operand ) {
  VmRegister vm_reg;
  vm_reg.register_offset = GetVmRegisterOffsetFromX86Reg( operand.reg );
  vm_reg.register_size = operand.size;
  return vm_reg;
}

VmRegister GetVmRegisterOffsetFromX86MemoryReg( const cs_x86_op& operand ) {
  VmRegister vm_reg;
  vm_reg.register_offset = GetVmRegisterOffsetFromX86Reg( operand.mem.base );
  vm_reg.register_size = operand.size;
  return vm_reg;
}

VmOpcodes GetVmOpcode( const cs_insn& instruction ) {
  const auto& operands = instruction.detail->x86.operands;

  VmOpcodes vm_opcode = VmOpcodes::NO_OPCODE;

  switch ( instruction.id ) {
    case x86_insn::X86_INS_MOV: {
      const auto& operand1 = operands[ 0 ];
      const auto& operand2 = operands[ 1 ];

      // If mov reg, x
      if ( operand1.type == x86_op_type::X86_OP_REG ) {
        // If mov reg, imm
        if ( operand2.type == x86_op_type::X86_OP_IMM ) {
          vm_opcode = VmOpcodes::MOV_REGISTER_IMMEDIATE;
        }
        // If mov reg, reg
        else if ( operand2.type == x86_op_type::X86_OP_REG ) {
          vm_opcode = VmOpcodes::MOV_REGISTER_REGISTER;
        }
        // If mov reg, [imm]
        else if ( IsOperandMemoryImmediate( operand2 ) ) {
          vm_opcode = VmOpcodes::MOV_REGISTER_MEMORY_IMMEDIATE;
        }
        // mov reg, [reg +- offset]
        else if ( IsOperandMemoryRegOffset( operand2 ) ) {
          vm_opcode = VmOpcodes::MOV_REGISTER_MEMORY_REG_OFFSET;
        }
      }
      // If mov x, reg
      else if ( operand2.type == x86_op_type::X86_OP_REG ) {
        // mov [reg +- offset], reg
        if ( IsOperandMemoryRegOffset( operand1 ) ) {
          vm_opcode = VmOpcodes::MOV_MEMORY_REG_OFFSET_REG;
        }
      }
      // mov x, imm
      else if ( operand2.type == x86_op_type::X86_OP_IMM ) {
        // mov [reg +- offset], imm
        if ( IsOperandMemoryRegOffset( operand1 ) ) {
          vm_opcode = VmOpcodes::MOV_MEMORY_REG_OFFSET_IMM;
        }
      }
    } break;

    case x86_insn::X86_INS_CALL: {
      const auto& operand1 = operands[ 0 ];

      // If call imm
      if ( operand1.type == X86_OP_IMM ) {
        vm_opcode = VmOpcodes::CALL_IMMEDIATE;
      }
      // if call [imm]
      else if ( IsOperandMemoryImmediate( operand1 ) ) {
        vm_opcode = VmOpcodes::CALL_MEMORY;
      }
      // if call [reg + imm]
      // this is the default for winapi calls on x64
      else if ( IsOperandMemoryRegOffset( operand1 ) ) {
        // Unique case for just the RIP relative calls, those are default on win32 api calls on x64
        if ( operand1.mem.base == x86_reg::X86_REG_RIP ) {
          vm_opcode = VmOpcodes::CALL_MEMORY_RIP_RELATIVE;
        }
      }
    } break;

      //// also changes eflags, read what they change and emulate them
      //// https://c9x.me/x86/html/file_module_x86_id_5.html
      // case x86_insn::X86_INS_ADD: {
      //} break;

      //// no flags are affected
      /// https://c9x.me/x86/html/file_module_x86_id_153.html
      // case x86_insn::X86_INS_LEA: {
      //} break;

    case x86_insn::X86_INS_PUSH: {
      const auto& operand1 = operands[ 0 ];

      if ( operand1.type == x86_op_type::X86_OP_IMM ) {
        vm_opcode = VmOpcodes::PUSH_IMM;
      } else if ( IsOperandMemoryRegOffset( operand1 ) ) {
        vm_opcode = VmOpcodes::PUSH_REGISTER_MEMORY_REG_OFFSET;
      }
    } break;

    case x86_insn::X86_INS_LEA: {
      const auto& operand1 = operands[ 0 ];
      const auto& operand2 = operands[ 1 ];

      if ( operand1.type == x86_op_type::X86_OP_REG &&
           IsOperandMemoryRegOffset( operand2 ) ) {
        if ( operand2.mem.base == x86_reg::X86_REG_RIP ) {
          vm_opcode = VmOpcodes::LEA_REG_MEMORY_IMMEDIATE_RIP_RELATIVE;
        }
      }
    } break;

      // NOTE: What type of jump is X86_INS_LJMP?
    case x86_insn::X86_INS_JMP: {
      const auto& operand1 = operands[ 0 ];

      // jmp imm
      if ( operand1.type == X86_OP_IMM ) {
        vm_opcode = VmOpcodes::JMP_IMM;
      }
    } break;

    default:
      break;
  }

  return vm_opcode;
}

bool IsVirtualizeable( const cs_insn& instruction, const VmOpcodes vm_opcode ) {
  // the instruction has to be bigger than a jmp
  if ( instruction.size < 5 ) {
    return false;
  }

  return vm_opcode != VmOpcodes::NO_OPCODE;
}

uintptr_t GetOperandMemoryValue( const cs_x86_op& operand,
                                 const bool relocated,
                                 const uintptr_t default_image_base ) {
  if ( relocated ) {
    return static_cast<uintptr_t>( operand.mem.disp ) - default_image_base;
  } else {
    return static_cast<uintptr_t>( operand.mem.disp );
  }
}

uintptr_t GetOperandImmediateValue( const cs_x86_op& operand,
                                    const bool relocated,
                                    const uintptr_t default_image_base ) {
  if ( relocated ) {
    return static_cast<uintptr_t>( operand.imm ) - default_image_base;
  } else {
    return static_cast<uintptr_t>( operand.imm );
  }
}

Shellcode CreateVirtualizedShellcode(
    const cs_insn& instruction,
    const VmOpcodes vm_opcode,
    const uint32_t vm_opcode_encyption_key,
    const std::vector<uintptr_t>& relocations_within_instruction,
    const uintptr_t default_image_base ) {
  Shellcode shellcode;

  assert( vm_opcode != VmOpcodes::NO_OPCODE );

  shellcode.AddValue<uint32_t>( static_cast<uint32_t>( vm_opcode ) ^
                                vm_opcode_encyption_key );

  const auto& operands = instruction.detail->x86.operands;

  int imm_count = 0;
  int mem_count = 0;

  for ( const auto& op : operands ) {
    if ( op.type == x86_op_type::X86_OP_IMM ) {
      imm_count++;
    } else if ( op.type == x86_op_type::X86_OP_MEM ) {
      mem_count++;
    }
  }

  // An instruction that has more than 1 type of the same operand is not
  // supported due to the relocation code I have added
  assert( imm_count < 2 );
  assert( mem_count < 2 );

  bool relocated_disp = false;
  bool relocated_imm = false;

  // The below code assumes that an instruction cannot have 2 immediate values
  // or 2 memory values
  for ( const auto relocation_rva : relocations_within_instruction ) {
    for ( const auto& op : operands ) {
      const auto& enc = instruction.detail->x86.encoding;

      const auto delta = relocation_rva - instruction.address;

      if ( delta == enc.disp_offset ) {
        // reg offset is being relocated
        relocated_disp = true;
      } else if ( delta == enc.imm_offset ) {
        // imm offset is being relocated
        relocated_imm = true;
      }
    }
  }

  // Add uint8_t RelocatedDisp 0/1
  shellcode.AddByte( static_cast<uint8_t>( relocated_disp ) );

  // Add uint8_t RelocatedImm 0/1
  shellcode.AddByte( static_cast<uint8_t>( relocated_imm ) );

  switch ( vm_opcode ) {
    case VmOpcodes::LEA_REG_MEMORY_IMMEDIATE_RIP_RELATIVE: {
      assert( operands[ 0 ].type == x86_op_type::X86_OP_REG &&
              operands[ 1 ].type == x86_op_type::X86_OP_MEM &&
              operands[ 1 ].mem.base == x86_reg::X86_REG_RIP );

#ifdef _WIN64
      // Ensure it is a qword on 64 bit, bcuz that is only what the interpreter can handle
      assert( operands[ 1 ].size == 8 );
#else
      // Ensure it is a dword on 32 bit, bcuz that is only what the interpreter can handle
      // call dword ptr ds:[0xF61008]
      assert( operands[ 1 ].size == 4 );
#endif

      // Ensure both of the operand sizes are the same
      assert( operands[ 0 ].size == operands[ 1 ].size );

      const auto vm_reg =
          GetVmRegisterOffsetFromX86ImmediateReg( operands[ 0 ] );

      if ( vm_reg.register_offset == -1 ) {
        return {};
      }

      // i do not handle relocations for this instruction yet
      assert( relocated_imm == false );
      assert( relocated_disp == false );

      shellcode.AddValue( vm_reg );

      const auto relative_data_addr = GetOperandMemoryValue(
          operands[ 1 ], relocated_disp, default_image_base );

      const auto rip = instruction.address;

      const auto abs_data_addr = relative_data_addr + instruction.size + rip;

      shellcode.AddValue<uintptr_t>( abs_data_addr );
    } break;

    case VmOpcodes::CALL_MEMORY_RIP_RELATIVE: {
      assert( operands[ 0 ].type == x86_op_type::X86_OP_MEM &&
              operands[ 0 ].mem.base == x86_reg::X86_REG_RIP );

#ifdef _WIN64
      // Ensure it is a qword on 64 bit, bcuz that is only what the interpreter can handle
      // call qword ptr ds:[0x00007FF648F61008]
      assert( operands[ 0 ].size == 8 );
#else
      // Ensure it is a dword on 32 bit, bcuz that is only what the interpreter can handle
      // call dword ptr ds:[0xF61008]
      assert( operands[ 0 ].size == 4 );
#endif

      /*
        The x64 rip relative addressing

        In x64 basic (win32) memory calls are rip relative. 
        Meaning that it is relative to the address the instrution lies on.
        Therefore I need to calculate the absolute call address relative to the image base

        I made the following equation with what values I had:
          abs_dest_call - rip = relative_call_addr + 6

        Turned into to get what I need:

          abs_dest_call = relative_call_addr + 6 + rip
      */

      const auto relative_call_addr = GetOperandMemoryValue(
          operands[ 0 ], relocated_disp, default_image_base );

      const auto rip = instruction.address;

      const auto abs_dest_call = relative_call_addr + instruction.size + rip;

      shellcode.AddValue<uintptr_t>( abs_dest_call );
    } break;

    case VmOpcodes::CALL_MEMORY: {
      assert( operands[ 0 ].type == x86_op_type::X86_OP_MEM );

#ifdef _WIN64
      // Ensure it is a qword on 64 bit, bcuz that is only what the interpreter can handle
      // call qword ptr ds:[0x00007FF648F61008]
      assert( operands[ 0 ].size == 8 );
#else
      // Ensure it is a dword on 32 bit, bcuz that is only what the interpreter can handle
      // call dword ptr ds:[0xF61008]
      assert( operands[ 0 ].size == 4 );
#endif

      const auto absolute_call_target_addr = GetOperandMemoryValue(
          operands[ 0 ], relocated_disp, default_image_base );

      shellcode.AddValue<uintptr_t>( absolute_call_target_addr );
    } break;

    case VmOpcodes::CALL_IMMEDIATE: {
      assert( operands[ 0 ].type == x86_op_type::X86_OP_IMM );

      const auto absolute_call_target_addr = GetOperandImmediateValue(
          operands[ 0 ], relocated_imm, default_image_base );

      shellcode.AddValue<uintptr_t>( absolute_call_target_addr );
    } break;

    case VmOpcodes::JMP_IMM: {
      assert( operands[ 0 ].type == x86_op_type::X86_OP_IMM );

      const auto absolute_jmp_target_addr = GetOperandImmediateValue(
          operands[ 0 ], relocated_imm, default_image_base );

      shellcode.AddValue<uintptr_t>( absolute_jmp_target_addr );
    } break;

    case VmOpcodes::MOV_REGISTER_MEMORY_IMMEDIATE: {
      assert( operands[ 0 ].type == x86_op_type::X86_OP_REG );
      assert( operands[ 1 ].type == x86_op_type::X86_OP_MEM );

      // Ensure both of the operand sizes are the same
      assert( operands[ 0 ].size == operands[ 1 ].size );

      auto vm_reg = GetVmRegisterOffsetFromX86ImmediateReg( operands[ 0 ] );

      // If the register is not supported, return empty
      if ( vm_reg.register_offset == -1 )
        return {};

      // Push the register index to the virtualized code
      shellcode.AddValue( vm_reg );

      shellcode.AddValue( GetOperandMemoryValue( operands[ 1 ], relocated_disp,
                                                 default_image_base ) );
    } break;

      // Example: mov ecx, dword ptr [eax + 0x43c140]
    case VmOpcodes::MOV_REGISTER_MEMORY_REG_OFFSET: {
      // reg value: mem.base
      // reg diff : mem.disp

      assert( operands[ 0 ].type == x86_op_type::X86_OP_REG );
      assert( operands[ 1 ].type == x86_op_type::X86_OP_MEM );

      // Ensure both of the operand sizes are the same
      assert( operands[ 0 ].size == operands[ 1 ].size );

      auto vm_reg_dest =
          GetVmRegisterOffsetFromX86ImmediateReg( operands[ 0 ] );

      // If the register is not supported, return empty
      if ( vm_reg_dest.register_offset == -1 )
        return {};

      const auto& operand2 = operands[ 1 ];

      const auto vm_reg_src = GetVmRegisterOffsetFromX86MemoryReg( operand2 );

      // If the register is not supported, return empty
      if ( vm_reg_src.register_offset == -1 )
        return {};

      auto reg_src_disp =
          GetOperandMemoryValue( operand2, relocated_disp, default_image_base );

      // Push the register offset to be changed to the virtualized code
      shellcode.AddValue( vm_reg_dest );

      // Push the reg offset
      shellcode.AddValue( vm_reg_src );

      // Push the reg disp offset
      shellcode.AddValue( reg_src_disp );
    } break;

    case VmOpcodes::MOV_REGISTER_REGISTER: {
      assert( operands[ 0 ].type == x86_op_type::X86_OP_REG );
      assert( operands[ 1 ].type == x86_op_type::X86_OP_REG );

      // Ensure both of the operand sizes are the same
      assert( operands[ 0 ].size == operands[ 1 ].size );

      const auto vm_reg_dest =
          GetVmRegisterOffsetFromX86ImmediateReg( operands[ 0 ] );
      const auto vm_reg_src =
          GetVmRegisterOffsetFromX86ImmediateReg( operands[ 1 ] );

      // If the register is not supported, return empty
      if ( vm_reg_dest.register_offset == -1 ||
           vm_reg_src.register_offset == -1 )
        return {};

      // Push the register index to the virtualized code
      shellcode.AddValue( vm_reg_dest );
      shellcode.AddValue( vm_reg_src );
    } break;

    case VmOpcodes::MOV_REGISTER_IMMEDIATE: {
      assert( operands[ 0 ].type == x86_op_type::X86_OP_REG );
      assert( operands[ 1 ].type == x86_op_type::X86_OP_IMM );

      // Ensure both of the operand sizes are the same
      assert( operands[ 0 ].size == operands[ 1 ].size );

      if ( operands[ 0 ].size == 1 || operands[ 0 ].size == 2 ||
           operands[ 0 ].size == 8 )
        return {};

      const auto vm_reg =
          GetVmRegisterOffsetFromX86ImmediateReg( operands[ 0 ] );

      // If the register is not supported, return empty
      if ( vm_reg.register_offset == -1 )
        return {};

      // Push the register index to the virtualized code
      shellcode.AddValue( vm_reg );
      shellcode.AddValue( GetOperandImmediateValue(
          operands[ 1 ], relocated_imm, default_image_base ) );
    } break;

      // Example: mov dword ptr [eax + 0x43c50c], ecx
    case VmOpcodes::MOV_MEMORY_REG_OFFSET_REG: {
      assert( operands[ 0 ].type == x86_op_type::X86_OP_MEM );
      assert( operands[ 1 ].type == x86_op_type::X86_OP_REG );

      // Ensure both of the operand sizes are the same
      assert( operands[ 0 ].size == operands[ 1 ].size );

      const auto& dest_operand1 = operands[ 0 ];
      const auto& src_operand2 = operands[ 1 ];

      const auto vm_reg_dest =
          GetVmRegisterOffsetFromX86MemoryReg( dest_operand1 );
      const auto vm_reg_src =
          GetVmRegisterOffsetFromX86ImmediateReg( src_operand2 );

      // If the register is not supported, return empty
      if ( vm_reg_dest.register_offset == -1 ||
           vm_reg_src.register_offset == -1 )
        return {};

      // Push the register offset to be changed to the virtualized code
      shellcode.AddValue( vm_reg_dest );

      // Push the source reg offset
      shellcode.AddValue( vm_reg_src );

      // Push the reg disp offset
      shellcode.AddValue( GetOperandMemoryValue( dest_operand1, relocated_disp,
                                                 default_image_base ) );
    } break;

    case VmOpcodes::MOV_MEMORY_REG_OFFSET_IMM: {
      assert( operands[ 0 ].type == x86_op_type::X86_OP_MEM );
      assert( operands[ 1 ].type == x86_op_type::X86_OP_IMM );

      // Ensure both of the operand sizes are the same
      assert( operands[ 0 ].size == operands[ 1 ].size );

      //assert( operands[ 0 ].size == 8 );

      const auto& dest_operand1 = operands[ 0 ];
      const auto& src_operand2 = operands[ 1 ];

      const auto vm_reg_dest =
          GetVmRegisterOffsetFromX86MemoryReg( dest_operand1 );

      // If the register is not supported, return empty
      if ( vm_reg_dest.register_offset == -1 )
        return {};

      // Both cannot be relocated at the same time, if so,
      // modify the interpreter simply call if for both instead of else if
      assert( !( relocated_imm && relocated_disp ) );

      shellcode.AddValue( vm_reg_dest );

      shellcode.AddValue( GetOperandImmediateValue( src_operand2, relocated_imm,
                                                    default_image_base ) );

      shellcode.AddValue( GetOperandMemoryValue( dest_operand1, relocated_disp,
                                                 default_image_base ) );

// On x86, we do not support operand sizes of 8
#ifndef _WIN64
      // NOTE: On mov instruction we support all sizes on both x86 and x64
      // REMOVE THIS ASSERT WHEN IN OCCURS TO DETERMINE IF ISSUES ARE FOUND

      // Currently only support these 3 sizes
      assert( dest_operand1.size == 1 || dest_operand1.size == 2 ||
              dest_operand1.size == 4 );

      // qword is currently not supported, if this assert sets off, consider supporting it
      assert( dest_operand1.size != 8 );
#endif
    } break;

    case VmOpcodes::PUSH_IMM: {
      assert( operands[ 0 ].type == x86_op_type::X86_OP_IMM );

#ifdef _WIN64
      // Ensure it is a qword on 64 bit, bcuz that is only what the interpreter can handle atm
      assert( operands[ 0 ].size == 8 );
#else
      // Ensure it is a dword on 32 bit, bcuz that is only what the interpreter can handle atm
      assert( operands[ 0 ].size == 4 );
#endif

      shellcode.AddValue( GetOperandImmediateValue(
          operands[ 0 ], relocated_imm, default_image_base ) );
    } break;

    case VmOpcodes::PUSH_REGISTER_MEMORY_REG_OFFSET: {
      assert( operands[ 0 ].type == x86_op_type::X86_OP_MEM );

#ifdef _WIN64
      // Ensure it is a qword on 64 bit, bcuz that is only what the interpreter can handle atm
      assert( operands[ 0 ].size == 8 );
#else
      // Ensure it is a dword on 32 bit, bcuz that is only what the interpreter can handle atm
      assert( operands[ 0 ].size == 4 );
#endif

      const auto& operand1 = operands[ 0 ];

      const auto vm_reg_dest = GetVmRegisterOffsetFromX86MemoryReg( operand1 );

      // If the register is not supported, return empty
      if ( vm_reg_dest.register_offset == -1 )
        return {};

      // Push the register offset to be changed to the virtualized code
      shellcode.AddValue( vm_reg_dest );

      // Push the reg disp offset
      shellcode.AddValue( GetOperandMemoryValue( operand1, relocated_disp,
                                                 default_image_base ) );
    } break;

    default:
      break;
  }

#ifndef _WIN64
  // On x86, the interpreter does not properly handle reading sizes larger than 4 due to using uintptr_t when reading
  for ( int i = 0; i < instruction.detail->x86.op_count; ++i ) {
    assert( instruction.detail->x86.operands[ i ].size <= 4 );
  }
#endif

  return shellcode;
}

Shellcode GetX86LoaderShellcodeForVirtualizedCode(
    const cs_insn& instruction,
    const VmOpcodes vm_opcode,
    const uintptr_t image_base ) {
  /*
      It is very important that we do not access data outside the actual stack, if an interrupt 
      occurs that the wrong moment, the data outside the stack can become corrupt.

      NOTE: The following code does not modify the E/RFLAGS as the previous iteration did

      Before Interpreter
        pushfd 
        push eax
        push ebx
        push ecx
        push edx
        push ebp
        push esi
        push edi
        sub esp,C8
        push esp
        add dword ptr ss:[esp],C8
        sub esp,100
        push test executable out.3F0000
        push 58B1
        push esp
        push C993A
        call test executable out.4394D0
        add esp,100
        pop esp
        pop edi
        pop esi
        pop ebp
        pop edx
        pop ecx
        pop ebx
        pop eax
        popfd 
        jmp test executable out.43937B

      Call:
        We are pushing the destination address 2 times from the interpreter
        
        push eax                <-- Save eax because we use it
        call 0                  <-- Push the current eip to the stack
        pop eax                 <-- Read the pushed eip into eax
        lea eax, [eax + 0xA]    <-- Same as add eax, 0xA
        mov [esp + 0x8], eax    <-- Move return address into proper space on stack
        pop eax               
        ret                     <-- Jump to destination call

      Jmp:
        Simply RET immediately because we push the destination to the real stack from the interpreter
  */

  Shellcode shellcode;

  //shellcode.Reserve( 100 );

  // pushfd
  shellcode.AddByte( 0x9C );
  // push eax
  shellcode.AddByte( 0x50 );
  // push ebx
  shellcode.AddByte( 0x53 );
  // push ecx
  shellcode.AddByte( 0x51 );
  // push edx
  shellcode.AddByte( 0x52 );
  // push ebp
  shellcode.AddByte( 0x55 );
  // push esi
  shellcode.AddByte( 0x56 );
  // push edi
  shellcode.AddByte( 0x57 );

  // sub esp, 200 (MAX_PUSHES * sizeof(uint32_t))
  shellcode.AddBytes( { 0x81, 0xEC, 0xC8, 0x00, 0x00, 0x00 } );

  // push esp
  shellcode.AddByte( 0x54 );

  // add dword ptr [esp], 0x200
  shellcode.AddBytes( { 0x81, 0x04, 0x24, 0xC8, 0x00, 0x00, 0x00 } );

  // sub rsp, 0x100
  shellcode.AddBytes( { 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00 } );

  // push the address to .vmvar section
  // push
  shellcode.AddByte( 0x68 );
  shellcode.AddVariable<uint32_t>( image_base, ImageBaseVariable );

  // push current eip
  // push
  shellcode.AddByte( 0x68 );
  shellcode.AddVariable<uint32_t>( 0, VmOpcodeEncryptionKeyVariable );

  // push esp
  shellcode.AddByte( 0x54 );

  // push
  shellcode.AddByte( 0x68 );
  shellcode.AddVariable( 0, VmCodeAddrVariable );

  // call
  shellcode.AddByte( 0xE8 );
  shellcode.AddVariable( 0, VmCoreFunctionVariable );

  // add rsp, 0x100
  shellcode.AddBytes( { 0x81, 0xC4, 0x00, 0x01, 0x00, 0x00 } );

  // pop esp
  shellcode.AddByte( 0x5C );

  // pop edi
  shellcode.AddByte( 0x5F );
  // pop esi
  shellcode.AddByte( 0x5E );
  // pop ebp
  shellcode.AddByte( 0x5D );
  // pop edx
  shellcode.AddByte( 0x5A );
  // pop ecx
  shellcode.AddByte( 0x59 );
  // pop ebx
  shellcode.AddByte( 0x5B );
  // pop eax
  shellcode.AddByte( 0x58 );

  // popfd
  shellcode.AddByte( 0x9D );

  if ( vm_opcode == VmOpcodes::CALL_IMMEDIATE ) {
    // push eax
    shellcode.AddByte( 0x50 );

    // call 0
    shellcode.AddBytes( { 0xE8, 0x00, 0x00, 0x00, 0x00 } );

    // pop eax
    shellcode.AddByte( 0x58 );

    // lea eax, ds:[eax+0xA]
    shellcode.AddBytes( { 0x8D, 0x40, 0x0A } );

    // mov dword ptr ss:[esp+0x8], eax
    shellcode.AddBytes( { 0x89, 0x44, 0x24, 0x08 } );

    // pop eax
    shellcode.AddByte( 0x58 );

    // ret
    shellcode.AddByte( 0xC3 );
  } else if ( vm_opcode == VmOpcodes::CALL_MEMORY ) {
    // push eax
    shellcode.AddByte( 0x50 );

    // call 0
    shellcode.AddBytes( { 0xE8, 0x00, 0x00, 0x00, 0x00 } );

    // pop eax
    shellcode.AddByte( 0x58 );

    // lea eax, ds:[eax+0xA]
    shellcode.AddBytes( { 0x8D, 0x40, 0x0A } );

    // mov dword ptr ss:[esp+0x8], eax
    shellcode.AddBytes( { 0x89, 0x44, 0x24, 0x08 } );

    // pop eax
    shellcode.AddByte( 0x58 );

    // ret
    shellcode.AddByte( 0xC3 );
  } else if ( vm_opcode == VmOpcodes::JMP_IMM ) {
    // ret
    shellcode.AddByte( 0xC3 );
  }

  // jmp
  shellcode.AddByte( 0xE9 );
  shellcode.AddVariable( 0, OrigAddrVariable );

  return shellcode;
}

Shellcode GetX64LoaderShellcodeForVirtualizedCode( const cs_insn& instruction,
                                                   const VmOpcodes vm_opcode,
                                                   const uint64_t image_base ) {
  /*
      It is very important that we do not access data outside the actual stack, if an interrupt 
      occurs that the wrong moment, the data outside the stack can become corrupt.

      NOTE: The following code does not modify the E/RFLAGS as the previous iteration did

      Previous method to save XMM register (push xmm7):
        sub rsp, 0x10
        movdqu xmmword ptr ss:[rsp], xmm7

      Before Interpreter:
        pushfq 
        push rax
        push rbx
        push rcx
        push rdx
        push rbp
        push rsi
        push rdi
        sub rsp,80
        movdqu xmmword ptr ss:[rsp+70],xmm7
        movdqu xmmword ptr ss:[rsp+60],xmm6
        movdqu xmmword ptr ss:[rsp+50],xmm5
        movdqu xmmword ptr ss:[rsp+40],xmm4
        movdqu xmmword ptr ss:[rsp+30],xmm3
        movdqu xmmword ptr ss:[rsp+20],xmm2
        movdqu xmmword ptr ss:[rsp+10],xmm1
        movdqu xmmword ptr ss:[rsp],xmm0
        push r8
        push r9
        push r10
        push r11
        push r12
        push r13
        push r14
        push r15
        sub rsp,C8                                <-- Allocate extra stack incase we push values onto the stack
        push rsp
        add dword ptr ss:[rsp],C8
                                                      Allocate stack space for the function call, 
        sub rsp,100                               <-- the stack space depends on how many arguments 
                                                      the call has in this case it has 4, so i dont know
        mov r9, Imagebase                         <-- 4th Argument Image Base
        mov r8d,7A0F                              <-- 3rd Argument Xor Key
        mov rdx,rsp                               <-- 2nd Argument RSP
        mov rcx,437686A                           <-- 1st Argument VmCodeAddress
        call VmInterpreter
        add rsp,100                               <-- Free stack that was allocated before function call
        pop rsp
        pop r15
        pop r14
        pop r13
        pop r12
        pop r11
        pop r10
        pop r9
        pop r8
        movdqu xmm0,xmmword ptr ss:[rsp]
        movdqu xmm1,xmmword ptr ss:[rsp+10]
        movdqu xmm2,xmmword ptr ss:[rsp+20]
        movdqu xmm3,xmmword ptr ss:[rsp+30]
        movdqu xmm4,xmmword ptr ss:[rsp+40]
        movdqu xmm5,xmmword ptr ss:[rsp+50]
        movdqu xmm6,xmmword ptr ss:[rsp+60]
        movdqu xmm7,xmmword ptr ss:[rsp+70]
        add rsp,80
        pop rdi
        pop rsi
        pop rbp
        pop rdx
        pop rcx
        pop rbx
        pop rax
        popfq 
        jmp test executable out.7FF71E5386AD      <-- Jump back to the next instruction of the original code

      Call:
        We are pushing the destination address 2 times from the interpreter

        OLD WAY (UNOPTIMIZED):

        pushfq                    <-- Save RFLAGS because add ?, ? modifies them
        push rax                  <-- Save RAX because we use it
        call 0                    <-- Push RIP
        add qword [rsp], 0x15     <-- Add 0x15 to the RIP
        mov rax, qword [rsp]      <-- Save the return address in RAX
        mov qword[rsp+0x20], rax  <-- Move the return address into the second pushed stack values
        add rsp, 8                <-- Remove the RIP we pushed from call earlier
        pop rax
        popfq
        ret                       <-- Call the real function

        NEW WAY (OPTIMIZED):

        push rax
        lea rax, [rip + 0x7]      <-- Move the return address into rax
        mov [rsp + 0x10], rax   <-- Move return address into proper space on stack
        pop rax
        ret

      Jmp:
        Simply RET immediately because we push the destination to the real stack from the interpreter
  */

  Shellcode shellcode;

  // shellcode.Reserve( 100 );

  // pushfd
  shellcode.AddByte( 0x9C );
  // push rax
  shellcode.AddByte( 0x50 );
  // push rbx
  shellcode.AddByte( 0x53 );
  // push rcx
  shellcode.AddByte( 0x51 );
  // push rdx
  shellcode.AddByte( 0x52 );
  // push rbp
  shellcode.AddByte( 0x55 );
  // push rsi
  shellcode.AddByte( 0x56 );
  // push rdi
  shellcode.AddByte( 0x57 );

  // sub rsp, 0x80
  shellcode.AddBytes( { 0x48, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00 } );

  // movdqu xmmword ptr ss:[rsp+0x70], xmm7
  shellcode.AddBytes( { 0xF3, 0x0F, 0x7F, 0x7C, 0x24, 0x70 } );

  // movdqu xmmword ptr ss:[rsp+0x60], xmm6
  shellcode.AddBytes( { 0xF3, 0x0F, 0x7F, 0x74, 0x24, 0x60 } );

  // movdqu xmmword ptr ss:[rsp+0x50], xmm5
  shellcode.AddBytes( { 0xF3, 0x0F, 0x7F, 0x6C, 0x24, 0x50 } );

  // movdqu xmmword ptr ss:[rsp+0x40], xmm4
  shellcode.AddBytes( { 0xF3, 0x0F, 0x7F, 0x64, 0x24, 0x40 } );

  // movdqu xmmword ptr ss:[rsp+0x30], xmm3
  shellcode.AddBytes( { 0xF3, 0x0F, 0x7F, 0x5C, 0x24, 0x30 } );

  // movdqu xmmword ptr ss:[rsp+0x20], xmm2
  shellcode.AddBytes( { 0xF3, 0x0F, 0x7F, 0x54, 0x24, 0x20 } );

  // movdqu xmmword ptr ss:[rsp+0x10], xmm1
  shellcode.AddBytes( { 0xF3, 0x0F, 0x7F, 0x4C, 0x24, 0x10 } );

  // movdqu xmmword ptr ss:[rsp], xmm0
  shellcode.AddBytes( { 0xF3, 0x0F, 0x7F, 0x04, 0x24 } );

  // push r8
  shellcode.AddBytes( { 0x41, 0x50 } );
  // push r9
  shellcode.AddBytes( { 0x41, 0x51 } );
  // push r10
  shellcode.AddBytes( { 0x41, 0x52 } );
  // push r11
  shellcode.AddBytes( { 0x41, 0x53 } );
  // push r12
  shellcode.AddBytes( { 0x41, 0x54 } );
  // push r13
  shellcode.AddBytes( { 0x41, 0x55 } );
  // push r14
  shellcode.AddBytes( { 0x41, 0x56 } );
  // push r15
  shellcode.AddBytes( { 0x41, 0x57 } );

  // sub rsp, 200 (MAX_PUSHES * sizeof(uint32_t))
  shellcode.AddBytes( { 0x48, 0x81, 0xEC, 0xC8, 0x00, 0x00, 0x00 } );

  // push rsp
  shellcode.AddByte( 0x54 );

  // add dword ptr [rsp], 0xC8
  shellcode.AddBytes( { 0x81, 0x04, 0x24, 0xC8, 0x00, 0x00, 0x00 } );

  // sub rsp, 0x100
  shellcode.AddBytes( { 0x48, 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00 } );

  // mov r9, Imagebase
  shellcode.AddBytes( { 0x49, 0xB9 } );
  shellcode.AddVariable<uint64_t>( image_base, ImageBaseVariable );

  // mov r8, 4 byte variabe (3rd argument)
  shellcode.AddBytes( { 0x41, 0xB8 } );
  shellcode.AddVariable<uint32_t>( 0, VmOpcodeEncryptionKeyVariable );

  // mov rdx, rsp (2nd argument)
  shellcode.AddBytes( { 0x48, 0x8B, 0xD4 } );

  // mov rcx, 8bytes
  shellcode.AddBytes( { 0x48, 0xB9 } );
  shellcode.AddVariable<uint64_t>( 0, VmCodeAddrVariable );

  // call
  shellcode.AddByte( 0xE8 );
  shellcode.AddVariable( 0, VmCoreFunctionVariable );

  // add rsp, 0x100
  shellcode.AddBytes( { 0x48, 0x81, 0xC4, 0x00, 0x01, 0x00, 0x00 } );

  // pop esp
  shellcode.AddByte( 0x5C );

  // pop r15
  shellcode.AddBytes( { 0x41, 0x5F } );
  // pop r14
  shellcode.AddBytes( { 0x41, 0x5E } );
  // pop r13
  shellcode.AddBytes( { 0x41, 0x5D } );
  // pop r12
  shellcode.AddBytes( { 0x41, 0x5C } );
  // pop r11
  shellcode.AddBytes( { 0x41, 0x5B } );
  // pop r10
  shellcode.AddBytes( { 0x41, 0x5A } );
  // pop r9
  shellcode.AddBytes( { 0x41, 0x59 } );
  // pop r8
  shellcode.AddBytes( { 0x41, 0x58 } );

  // movdqu xmm0, xmmword ptr ss:[rsp]
  shellcode.AddBytes( { 0xF3, 0x0F, 0x6F, 0x04, 0x24 } );

  // movdqu xmm1, xmmword ptr ss:[rsp+0x10]
  shellcode.AddBytes( { 0xF3, 0x0F, 0x6F, 0x4C, 0x24, 0x10 } );

  // movdqu xmm2, xmmword ptr ss:[rsp+0x20]
  shellcode.AddBytes( { 0xF3, 0x0F, 0x6F, 0x54, 0x24, 0x20 } );

  // movdqu xmm3, xmmword ptr ss:[rsp+0x30]
  shellcode.AddBytes( { 0xF3, 0x0F, 0x6F, 0x5C, 0x24, 0x30 } );

  // movdqu xmm4, xmmword ptr ss:[rsp+0x40]
  shellcode.AddBytes( { 0xF3, 0x0F, 0x6F, 0x64, 0x24, 0x40 } );

  // movdqu xmm5, xmmword ptr ss:[rsp+0x50]
  shellcode.AddBytes( { 0xF3, 0x0F, 0x6F, 0x6C, 0x24, 0x50 } );

  // movdqu xmm6, xmmword ptr ss:[rsp+0x60]
  shellcode.AddBytes( { 0xF3, 0x0F, 0x6F, 0x74, 0x24, 0x60 } );

  // movdqu xmm7, xmmword ptr ss:[rsp+0x70]
  shellcode.AddBytes( { 0xF3, 0x0F, 0x6F, 0x7C, 0x24, 0x70 } );

  // add rsp, 0x80
  shellcode.AddBytes( { 0x48, 0x81, 0xC4, 0x80, 0x00, 0x00, 0x00 } );

  // pop edi
  shellcode.AddByte( 0x5F );
  // pop esi
  shellcode.AddByte( 0x5E );
  // pop ebp
  shellcode.AddByte( 0x5D );
  // pop edx
  shellcode.AddByte( 0x5A );
  // pop ecx
  shellcode.AddByte( 0x59 );
  // pop ebx
  shellcode.AddByte( 0x5B );
  // pop eax
  shellcode.AddByte( 0x58 );
  // popfd
  shellcode.AddByte( 0x9D );

  if ( vm_opcode == VmOpcodes::CALL_IMMEDIATE ) {
    // push rax
    shellcode.AddByte( 0x50 );

    // lea rax, [rip + 0x7]
    shellcode.AddBytes( { 0x48, 0x8D, 0x05, 0x07, 0x00, 0x00, 0x00 } );

    // mov qword ptr ss:[rsp+0x10], rax
    shellcode.AddBytes( { 0x48, 0x89, 0x44, 0x24, 0x10 } );

    // pop rax
    shellcode.AddByte( 0x58 );

    // ret
    shellcode.AddByte( 0xC3 );

  } else if ( vm_opcode == VmOpcodes::CALL_MEMORY ) {
    // push rax
    shellcode.AddByte( 0x50 );

    // lea rax, [rip + 0x7]
    shellcode.AddBytes( { 0x48, 0x8D, 0x05, 0x07, 0x00, 0x00, 0x00 } );

    // mov qword ptr ss:[rsp+0x10], rax
    shellcode.AddBytes( { 0x48, 0x89, 0x44, 0x24, 0x10 } );

    // pop rax
    shellcode.AddByte( 0x58 );

    // ret
    shellcode.AddByte( 0xC3 );
  } else if ( vm_opcode == VmOpcodes::CALL_MEMORY_RIP_RELATIVE ) {
    // push rax
    shellcode.AddByte( 0x50 );

    // lea rax, [rip + 0x7]
    shellcode.AddBytes( { 0x48, 0x8D, 0x05, 0x07, 0x00, 0x00, 0x00 } );

    // mov qword ptr ss:[rsp+0x10], rax
    shellcode.AddBytes( { 0x48, 0x89, 0x44, 0x24, 0x10 } );

    // pop rax
    shellcode.AddByte( 0x58 );

    // ret
    shellcode.AddByte( 0xC3 );
  } else if ( vm_opcode == VmOpcodes::JMP_IMM ) {
    // The interpreter simply pushes the jump destination
    // to the stack and we simply ret to it

    // ret
    shellcode.AddByte( 0xC3 );
  }

  // jmp
  shellcode.AddByte( 0xE9 );
  shellcode.AddVariable( 0, OrigAddrVariable );

  return shellcode;
}

Shellcode GetLoaderShellcodeForVirtualizedCode( const cs_insn& instruction,
                                                const VmOpcodes vm_opcode,
                                                const uintptr_t image_base ) {
#ifdef _WIN64
  return GetX64LoaderShellcodeForVirtualizedCode( instruction, vm_opcode,
                                                  image_base );
#else
  return GetX86LoaderShellcodeForVirtualizedCode( instruction, vm_opcode,
                                                  image_base );
#endif
}

}  // namespace virtualizer