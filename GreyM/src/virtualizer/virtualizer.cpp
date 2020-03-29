#include "pch.h"
#include "virtualizer.h"
#include "../utils/shellcode.h"

namespace virtualizer {

// Checks if the operand is [immediate addr]
bool IsMemoryImmediate( const cs_x86_op& operand ) {
  return operand.type == x86_op_type::X86_OP_MEM &&
         operand.mem.base == x86_reg::X86_REG_INVALID &&
         operand.mem.index == x86_reg::X86_REG_INVALID &&
         operand.mem.segment == x86_reg::X86_REG_INVALID &&
         operand.mem.disp != 0;
}

// Checks if the operand is [reg +- offset]
bool IsMemoryRegOffset( const cs_x86_op& operand ) {
  return operand.type == x86_op_type::X86_OP_MEM &&
         operand.mem.segment == x86_reg::X86_REG_INVALID &&
         operand.mem.base != x86_reg::X86_REG_INVALID &&
         operand.mem.index == x86_reg::X86_REG_INVALID && operand.mem.disp != 0;
}

uint32_t GetRegisterStructOffset( const cs_x86_op& operand ) {
  int reg_struct_offset = -1;

  switch ( operand.reg ) {
      // REMOVED BECAUSE WE CANNOT READ OR CHANGE THE ESP VALUE IN THE VM
      // case x86_reg::X86_REG_ESP:
      // {
      //   reg_struct_offset = ESP_VM_IDENTIFIER;
      // } break;
    case x86_reg::X86_REG_EAX: {
      reg_struct_offset = offsetof( VM_REGISTERS, eax );
    } break;
    case x86_reg::X86_REG_EBX: {
      reg_struct_offset = offsetof( VM_REGISTERS, ebx );
    } break;
    case x86_reg::X86_REG_ECX: {
      reg_struct_offset = offsetof( VM_REGISTERS, ecx );
    } break;
    case x86_reg::X86_REG_EDX: {
      reg_struct_offset = offsetof( VM_REGISTERS, edx );
    } break;
    case x86_reg::X86_REG_EBP: {
      reg_struct_offset = offsetof( VM_REGISTERS, ebp );
    } break;
    case x86_reg::X86_REG_ESI: {
      reg_struct_offset = offsetof( VM_REGISTERS, esi );
    } break;
    case x86_reg::X86_REG_EDI: {
      reg_struct_offset = offsetof( VM_REGISTERS, edi );
    } break;
    default:
      break;
  }

  return reg_struct_offset;
}

uint32_t GetRegisterStructOffsetMemory( const cs_x86_op& operand ) {
  int reg_struct_offset = -1;

  switch ( operand.mem.base ) {
      // REMOVED BECAUSE WE CANNOT READ OR CHANGE THE ESP VALUE IN THE VM
      // case x86_reg::X86_REG_ESP:
      // {
      //   reg_struct_offset = ESP_VM_IDENTIFIER;
      // } break;
    case x86_reg::X86_REG_EAX: {
      reg_struct_offset = offsetof( VM_REGISTERS, eax );
    } break;
    case x86_reg::X86_REG_EBX: {
      reg_struct_offset = offsetof( VM_REGISTERS, ebx );
    } break;
    case x86_reg::X86_REG_ECX: {
      reg_struct_offset = offsetof( VM_REGISTERS, ecx );
    } break;
    case x86_reg::X86_REG_EDX: {
      reg_struct_offset = offsetof( VM_REGISTERS, edx );
    } break;
    case x86_reg::X86_REG_EBP: {
      reg_struct_offset = offsetof( VM_REGISTERS, ebp );
    } break;
    case x86_reg::X86_REG_ESI: {
      reg_struct_offset = offsetof( VM_REGISTERS, esi );
    } break;
    case x86_reg::X86_REG_EDI: {
      reg_struct_offset = offsetof( VM_REGISTERS, edi );
    } break;
    default:
      break;
  }

  return reg_struct_offset;
}

VmOpcodes GetVmOpcode( const cs_insn& instruction ) {
  const auto& operands = instruction.detail->x86.operands;

  switch ( instruction.id ) {
    case x86_insn::X86_INS_MOV: {
      const auto& operand1 = operands[ 0 ];
      const auto& operand2 = operands[ 1 ];

      // If mov reg, x
      if ( operand1.type == x86_op_type::X86_OP_REG ) {
        // If mov reg, imm
        if ( operand2.type == x86_op_type::X86_OP_IMM ) {
          return VmOpcodes::MOV_REGISTER_IMMEDIATE;
        }
        // If mov reg, reg
        else if ( operand2.type == x86_op_type::X86_OP_REG ) {
          return VmOpcodes::MOV_REGISTER_REGISTER;
        }
        // If mov reg, [imm]
        else if ( IsMemoryImmediate( operand2 ) ) {
          return VmOpcodes::MOV_REGISTER_MEMORY_IMMEDIATE;
        }
        // mov reg, [reg +- offset]
        else if ( IsMemoryRegOffset( operand2 ) ) {
          return VmOpcodes::MOV_REGISTER_MEMORY_REG_OFFSET;
        }
      }
      // If mov x, reg
      else if ( operand2.type == x86_op_type::X86_OP_REG ) {
        // mov [reg +- offset], reg
        if ( IsMemoryRegOffset( operand1 ) ) {
          return VmOpcodes::MOV_MEMORY_REG_OFFSET_REG;
        }
      }
      // mov x, imm
      else if ( operand2.type == x86_op_type::X86_OP_IMM ) {
        // mov [reg +- offset], imm
        if ( IsMemoryRegOffset( operand1 ) ) {
          return VmOpcodes::MOV_MEMORY_REG_OFFSET_IMM;
        }
      }
    } break;

    case x86_insn::X86_INS_CALL: {
      const auto& operand1 = operands[ 0 ];

      // If call imm
      if ( operand1.type == X86_OP_IMM ) {
        return VmOpcodes::CALL_IMMEDIATE;
      }
      // if call [imm]
      else if ( IsMemoryImmediate( operand1 ) ) {
        return VmOpcodes::CALL_MEMORY;
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

      // TODO: the below code causes issues in my gui
      // push 0x40F7C0
    case x86_insn::X86_INS_PUSH: {
      const auto& operand1 = operands[ 0 ];

      if ( operand1.type == x86_op_type::X86_OP_IMM ) {
        return VmOpcodes::PUSH_IMM;
      } else if ( IsMemoryRegOffset( operand1 ) ) {
        return VmOpcodes::PUSH_REGISTER_MEMORY_REG_OFFSET;
      }
    } break;

    default:
      break;
  }

  return VmOpcodes::NO_OPCODE;
}

bool IsVirtualizeable( const cs_insn& instruction, const VmOpcodes vm_opcode ) {
  // the instruction has to be bigger than a jmp
  if ( instruction.size < 5 )
    return false;

  return vm_opcode != VmOpcodes::NO_OPCODE;
}

Shellcode CreateVirtualizedShellcode(
    const cs_insn& instruction,
    const VmOpcodes vm_opcode,
    const uint32_t vm_opcode_encyption_key,
    const std::vector<uintptr_t>& relocations_within_instruction ) {
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
  /*
  for ( const auto relocation_rva : relocations ) {
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
  */

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
    case VmOpcodes::CALL_MEMORY: {
      const auto absolute_call_target_addr =
          static_cast<uintptr_t>( operands[ 0 ].mem.disp );

      // Push the register index to the virtualized code
      shellcode.AddValue<uintptr_t>( absolute_call_target_addr );
    } break;

    case VmOpcodes::CALL_IMMEDIATE: {
      const auto absolute_call_target_addr =
          static_cast<uintptr_t>( operands[ 0 ].imm );

      // Push the register index to the virtualized code
      shellcode.AddValue<uintptr_t>( absolute_call_target_addr );
    } break;

      /*
      case VmOpcodes::SUB_REGISTER_IMMEDIATE: {
        uint32_t reg_struct_offset = GetRegisterStructOffset( operands[ 0 ] );

        // If the register is not supported, return empty
        if ( reg_struct_offset == -1 )
          return {};

        // Push the register index to the virtualized code
        shellcode.AddValue( reg_struct_offset );

        shellcode.AddValue( static_cast<int32_t>( operands[ 1 ].imm ) );
      } break;

      case VmOpcodes::SUB_REGISTER_MEMORY_REG_OFFSET: {
        uint32_t reg_dest_offset = GetRegisterStructOffset( operands[ 0 ] );

        // If the register is not supported, return empty
        if ( reg_dest_offset == -1 )
          return {};

        const auto& operand2 = operands[ 1 ];

        const uint32_t reg_src_offset = GetRegisterStructOffsetMemory( operand2
      );

        // If the register is not supported, return empty
        if ( reg_src_offset == -1 )
          return {};

        // TODO: X64 change to int64_t
        const auto reg_src_disp = static_cast<int32_t>( operand2.mem.disp );

        // Push the register offset to be changed to the virtualized code
        shellcode.AddValue( reg_dest_offset );

        // Push the reg offset
        shellcode.AddValue( reg_src_offset );

        // Push the reg disp offset
        shellcode.AddValue( reg_src_disp );
      } break;
      */

    case VmOpcodes::MOV_REGISTER_MEMORY_IMMEDIATE: {
      uint32_t reg_struct_offset = GetRegisterStructOffset( operands[ 0 ] );

      // If the register is not supported, return empty
      if ( reg_struct_offset == -1 )
        return {};

      // Push the register index to the virtualized code
      shellcode.AddValue<uint32_t>( reg_struct_offset );

      assert( operands[ 1 ].type == x86_op_type::X86_OP_MEM );

      shellcode.AddValue( static_cast<uintptr_t>( operands[ 1 ].mem.disp ) );
    } break;

      // Example: mov ecx, dword ptr [eax + 0x43c140]
    case VmOpcodes::MOV_REGISTER_MEMORY_REG_OFFSET: {
      // reg value: mem.base
      // reg diff : mem.disp

      uint32_t reg_dest_offset = GetRegisterStructOffset( operands[ 0 ] );

      // If the register is not supported, return empty
      if ( reg_dest_offset == -1 )
        return {};

      const auto& operand2 = operands[ 1 ];

      const uint32_t reg_src_offset = GetRegisterStructOffsetMemory( operand2 );

      // If the register is not supported, return empty
      if ( reg_src_offset == -1 )
        return {};

      // TODO: X64 change to int64_t
      const auto reg_src_disp = static_cast<uintptr_t>( operand2.mem.disp );

      // Push the register offset to be changed to the virtualized code
      shellcode.AddValue( reg_dest_offset );

      // Push the reg offset
      shellcode.AddValue( reg_src_offset );

      // Push the reg disp offset
      shellcode.AddValue( reg_src_disp );
    } break;

    case VmOpcodes::MOV_REGISTER_REGISTER: {
      uint32_t reg_struct_offset_dest =
          GetRegisterStructOffset( operands[ 0 ] );
      uint32_t reg_struct_offset_src = GetRegisterStructOffset( operands[ 1 ] );

      // If the register is not supported, return empty
      if ( reg_struct_offset_dest == -1 || reg_struct_offset_src == -1 )
        return {};

      // Push the register index to the virtualized code
      shellcode.AddValue( reg_struct_offset_dest );
      shellcode.AddValue( reg_struct_offset_src );
    } break;

    case VmOpcodes::MOV_REGISTER_IMMEDIATE: {
      uint32_t reg_struct_offset = GetRegisterStructOffset( operands[ 0 ] );

      // If the register is not supported, return empty
      if ( reg_struct_offset == -1 )
        return {};

      // Push the register index to the virtualized code
      shellcode.AddValue( reg_struct_offset );
      shellcode.AddValue( static_cast<uintptr_t>( operands[ 1 ].imm ) );
    } break;

      // Example: mov dword ptr [eax + 0x43c50c], ecx
    case VmOpcodes::MOV_MEMORY_REG_OFFSET_REG: {
      const auto& dest_operand1 = operands[ 0 ];
      const auto& src_operand2 = operands[ 1 ];

      uint32_t reg_dest_offset = GetRegisterStructOffsetMemory( dest_operand1 );
      uint32_t reg_src_offset = GetRegisterStructOffset( src_operand2 );

      // If the register is not supported, return empty
      if ( reg_dest_offset == -1 || reg_src_offset == -1 )
        return {};

      // Push the register offset to be changed to the virtualized code
      shellcode.AddValue( reg_dest_offset );

      // Push the source reg offset
      shellcode.AddValue( reg_src_offset );

      // Push the reg disp offset
      shellcode.AddValue( static_cast<uintptr_t>( dest_operand1.mem.disp ) );
    } break;

    case VmOpcodes::MOV_MEMORY_REG_OFFSET_IMM: {
      const auto& dest_operand1 = operands[ 0 ];
      const auto& src_operand2 = operands[ 1 ];

      const uint32_t reg_dest_offset =
          GetRegisterStructOffsetMemory( dest_operand1 );

      // If the register is not supported, return empty
      if ( reg_dest_offset == -1 )
        return {};

      shellcode.AddValue( reg_dest_offset );

      shellcode.AddValue( static_cast<uintptr_t>( src_operand2.imm ) );

      shellcode.AddValue( static_cast<uintptr_t>( dest_operand1.mem.disp ) );

      // TODO: Fix issue with this instruction:
      // Example 1: mov dword ptr [eax + 0x7d765c], 2
      // Example 2: mov dword ptr [ebp - 0x20], 0x7d7268
      // The issue is that either the offset on the register and the
      // immediate value can be relocated

      // can use the x86.encoding to figure out if the what is being relocated

      // ins.address - relocated rva = difference to check again encoding
      // variable

      /*
        TODO: Fix the issue that the instruction can be "mov dword ptr" and
        "mov byte ptr" In other words, different sizes

        0x00EF1000 = FF FF FF FF

        mov BYTE PTR [0x00EF1000], 5  ; Store 8-bit value
        0x00EF1000 = 05 FF FF FF // Represents the change on the destination

        mov WORD PTR [0x00EF1000], 5  ; Store 16-bit value
        0x00EF1000 = 05 00 FF FF // Represents the change on the destination

        mov DWORD PTR [0x00EF1000], 5 ; Store 32-bit value
        0x00EF1000 = 05 00 00 00 // Represents the change on the destination
      */

      // Add the size of the destination
      // Example if it is "dword ptr", "word ptr" or "byte ptr"
      shellcode.AddValue<uint32_t>( dest_operand1.size );

      // qword is currently not supported
      assert( dest_operand1.size != 8 );
    } break;

    case VmOpcodes::PUSH_IMM: {
      shellcode.AddValue( static_cast<uintptr_t>( operands[ 0 ].imm ) );
    } break;

    case VmOpcodes::PUSH_REGISTER_MEMORY_REG_OFFSET: {
      const auto& operand1 = operands[ 0 ];
      uint32_t reg_dest_offset = GetRegisterStructOffsetMemory( operand1 );

      // If the register is not supported, return empty
      if ( reg_dest_offset == -1 )
        return {};

      // Push the register offset to be changed to the virtualized code
      shellcode.AddValue( reg_dest_offset );

      // Push the reg disp offset
      shellcode.AddValue( static_cast<intptr_t>( operand1.mem.disp ) );
    } break;

    default:
      break;
  }

  // shellcode.ModifyValue<uint32_t>(
  //     TEXT( "Size" ), shellcode.GetBuffer().size() - sizeof( uint32_t ) );

  return shellcode;
}

Shellcode GetX86LoaderShellcodeForVirtualizedCode(
    const cs_insn& instruction,
    const VmOpcodes vm_opcode,
    const uintptr_t image_base ) {
  Shellcode shellcode;

  shellcode.Reserve( 100 );

  shellcode.AddByte( 0x9C );  // pushfd

  shellcode.AddByte( 0x50 );  // push eax
  shellcode.AddByte( 0x53 );  // push ebx
  shellcode.AddByte( 0x51 );  // push ecx
  shellcode.AddByte( 0x52 );  // push edx
  shellcode.AddByte( 0x55 );  // push ebp
  shellcode.AddByte( 0x56 );  // push esi
  shellcode.AddByte( 0x57 );  // push edi

  /*
  https://stackoverflow.com/questions/43358429/save-value-of-xmm-registers
  shellcode.AddBytes( {
      0x8D, 0xA4, 0x24, 0xEE, 0xFE, 0xFF, 0xFF, 0xC5, 0xFA, 0x7F, 0x04,
      0x24, 0xC5, 0xFA, 0x7F, 0x4C, 0x24, 0x16, 0xC5, 0xFA, 0x7F, 0x54,
      0x24, 0x32, 0xC5, 0xFA, 0x7F, 0x5C, 0x24, 0x48, 0xC5, 0xFA, 0x7F,
      0x64, 0x24, 0x64, 0xC5, 0xFA, 0x7F, 0xAC, 0x24, 0x80, 0x00, 0x00,
      0x00, 0xC5, 0xFA, 0x7F, 0xB4, 0x24, 0x96, 0x00, 0x00, 0x00, 0xC5,
      0xFA, 0x7F, 0xBC, 0x24, 0x12, 0x01, 0x00, 0x00,
  } );
  */

  shellcode.AddBytes(
      { 0x81, 0xEC, 0xC8, 0x00, 0x00,
        0x00 } );  // sub esp, 200 (MAX_PUSHES * sizeof(uint32_t))

  shellcode.AddByte( 0x54 );  // push esp

  shellcode.AddBytes( { 0x81, 0x04, 0x24, 0xC8, 0x00, 0x00,
                        0x00 } );  // add dword ptr [esp], 0x200

  // temp sub
  shellcode.AddBytes( { 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00 } );

  // push the address to .vmvar section
  shellcode.AddByte( 0x68 );  // push
  shellcode.AddValue<uint32_t>( image_base, TEXT( "VmVarSection" ) );

  // push current eip
  shellcode.AddByte( 0x68 );  // push
  shellcode.AddValue<uint32_t>( /*vm_opcode_encyption_key*/ 0,
                                TEXT( "vm_opcode_encyption_key" ) );

  shellcode.AddByte( 0x54 );  // push esp (maybe not needed to push, just use
      // in vmcorefunction immedieatly)

  shellcode.AddByte( 0x68 );  // push
  shellcode.AddValue( 0, TEXT( "VmCodeAddr" ) );

  shellcode.AddByte( 0xE8 );  // call
  shellcode.AddValue( 0, TEXT( "VmCoreFunction" ) );

  // TEMP add
  shellcode.AddBytes( { 0x81, 0xC4, 0x00, 0x01, 0x00, 0x00 } );

  shellcode.AddByte( 0x5C );  // pop esp

  /*
  https://stackoverflow.com/questions/43358429/save-value-of-xmm-registers
  shellcode.AddBytes(
      { 0xC5, 0xFA, 0x6F, 0xBC, 0x24, 0x12, 0x01, 0x00, 0x00, 0xC5, 0xFA,
        0x6F, 0xB4, 0x24, 0x96, 0x00, 0x00, 0x00, 0xC5, 0xFA, 0x6F, 0xAC,
        0x24, 0x80, 0x00, 0x00, 0x00, 0xC5, 0xFA, 0x6F, 0x64, 0x24, 0x64,
        0xC5, 0xFA, 0x6F, 0x5C, 0x24, 0x48, 0xC5, 0xFA, 0x6F, 0x54, 0x24,
        0x32, 0xC5, 0xFA, 0x6F, 0x4C, 0x24, 0x16, 0xC5, 0xFA, 0x6F, 0x04,
        0x24, 0x8D, 0xA4, 0x24, 0x12, 0x01, 0x00, 0x00 } );
        */

  shellcode.AddByte( 0x5F );  // pop edi
  shellcode.AddByte( 0x5E );  // pop esi
  shellcode.AddByte( 0x5D );  // pop ebp
  shellcode.AddByte( 0x5A );  // pop edx
  shellcode.AddByte( 0x59 );  // pop ecx
  shellcode.AddByte( 0x5B );  // pop ebx
  shellcode.AddByte( 0x58 );  // pop eax

  shellcode.AddByte( 0x9D );  // popfd

  if ( vm_opcode == VmOpcodes::CALL_IMMEDIATE ) {
    // Before jmp back:
    // add esp, 4 || 83 C4 04
    // call dword ptr ss:[esp-0x4] || FF 54 24 FC
    shellcode.AddBytes( { 0x83, 0xC4, 0x04 } );

    // call dword ptr ss:[esp-0x4]
    shellcode.AddBytes( { 0xFF, 0x54, 0x24, 0xFC } );
  } else if ( vm_opcode == VmOpcodes::CALL_MEMORY ) {
    // Before jmp back:
    // add esp, 4 || 83 C4 04
    shellcode.AddBytes( { 0x83, 0xC4, 0x04 } );

    // call dword ptr ds:[esp-0x4] || 3E FF 54 24 FC
    shellcode.AddBytes( { 0x3E, 0xFF, 0x54, 0x24, 0xFC } );
  }

  shellcode.AddByte( 0xE9 );  // jmp
  shellcode.AddValue( 0, TEXT( "OrigAddr" ) );

  return shellcode;
}

Shellcode GetX64LoaderShellcodeForVirtualizedCode( const cs_insn& instruction,
                                                   const VmOpcodes vm_opcode,
                                                   const uint64_t image_base ) {
  Shellcode shellcode;

  shellcode.Reserve( 100 );

  shellcode.AddByte( 0x9C );  // pushfd

  shellcode.AddByte( 0x50 );  // push eax
  shellcode.AddByte( 0x53 );  // push ebx
  shellcode.AddByte( 0x51 );  // push ecx
  shellcode.AddByte( 0x52 );  // push edx
  shellcode.AddByte( 0x55 );  // push ebp
  shellcode.AddByte( 0x56 );  // push esi
  shellcode.AddByte( 0x57 );  // push edi

  // push xmm7
  shellcode.AddBytes( { 0x48, 0x83, 0xEC, 0x10 } );  // sub rsp, 16
  shellcode.AddBytes(
      { 0xF3, 0x0F, 0x7F, 0x3C, 0x24 } );  // movdqu xmmword ptr ss:[rsp], xmm7

  // push xmm6
  shellcode.AddBytes( { 0x48, 0x83, 0xEC, 0x10 } );  // sub rsp, 16
  shellcode.AddBytes(
      { 0xF3, 0x0F, 0x7F, 0x34, 0x24 } );  // movdqu xmmword ptr ss:[rsp], xmm6

  // push xmm5
  shellcode.AddBytes( { 0x48, 0x83, 0xEC, 0x10 } );  // sub rsp, 16
  shellcode.AddBytes(
      { 0xF3, 0x0F, 0x7F, 0x2C, 0x24 } );  // movdqu xmmword ptr ss:[rsp], xmm5

  // push xmm4
  shellcode.AddBytes( { 0x48, 0x83, 0xEC, 0x10 } );  // sub rsp, 16
  shellcode.AddBytes(
      { 0xF3, 0x0F, 0x7F, 0x24, 0x24 } );  // movdqu xmmword ptr ss:[rsp], xmm4

  // push xmm3
  shellcode.AddBytes( { 0x48, 0x83, 0xEC, 0x10 } );  // sub rsp, 16
  shellcode.AddBytes(
      { 0xF3, 0x0F, 0x7F, 0x1C, 0x24 } );  // movdqu xmmword ptr ss:[rsp], xmm3

  // push xmm2
  shellcode.AddBytes( { 0x48, 0x83, 0xEC, 0x10 } );  // sub rsp, 16
  shellcode.AddBytes(
      { 0xF3, 0x0F, 0x7F, 0x14, 0x24 } );  // movdqu xmmword ptr ss:[rsp], xmm2

  // push xmm1
  shellcode.AddBytes( { 0x48, 0x83, 0xEC, 0x10 } );  // sub rsp, 16
  shellcode.AddBytes(
      { 0xF3, 0x0F, 0x7F, 0x0C, 0x24 } );  // movdqu xmmword ptr ss:[rsp], xmm1

  // push xmm0
  shellcode.AddBytes( { 0x48, 0x83, 0xEC, 0x10 } );  // sub rsp, 16
  shellcode.AddBytes(
      { 0xF3, 0x0F, 0x7F, 0x04, 0x24 } );  // movdqu xmmword ptr ss:[rsp], xmm0

  shellcode.AddBytes( { 0x41, 0x50 } );  // push r8
  shellcode.AddBytes( { 0x41, 0x51 } );  // push r9
  shellcode.AddBytes( { 0x41, 0x52 } );  // push r10
  shellcode.AddBytes( { 0x41, 0x53 } );  // push r11
  shellcode.AddBytes( { 0x41, 0x54 } );  // push r12
  shellcode.AddBytes( { 0x41, 0x55 } );  // push r13
  shellcode.AddBytes( { 0x41, 0x56 } );  // push r14
  shellcode.AddBytes( { 0x41, 0x57 } );  // push r15

  // sub esp, 200 (MAX_PUSHES * sizeof(uint32_t))
  //shellcode.AddBytes( { 0x81, 0xEC, 0xC8, 0x00, 0x00, 0x00 } );
  // sub rsp, 200 (MAX_PUSHES * sizeof(uint32_t))
  shellcode.AddBytes( { 0x48, 0x81, 0xEC, 0xC8, 0x00, 0x00, 0x00 } );

  // push esp
  shellcode.AddByte( 0x54 );

  shellcode.AddBytes( { 0x81, 0x04, 0x24, 0xC8, 0x00, 0x00,
                        0x00 } );  // add dword ptr [esp], 0x200

  // Allocate stack space for the function call, the stack space depends on how many arguments the call has
  // in this case it has 4, so i dont know
  // sub rsp, 100h
  shellcode.AddBytes( { 0x48, 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00 } );

  // mov r9, 0 (4th argument)
  //shellcode.AddBytes( { 0x41, 0xB9, 0x0, 0x0, 0x0, 0x0 } );
  shellcode.AddBytes( { 0x49, 0xB9 } );
  shellcode.AddValue<uint64_t>( image_base, TEXT( "VmVarSection" ) );

  // push eip (x64 way)
  // mov r8, 4 byte variabe (3rd argument)
  shellcode.AddBytes( { 0x41, 0xB8 } );
  shellcode.AddValue<uint32_t>( /*vm_opcode_encyption_key*/ 0,
                                TEXT( "vm_opcode_encyption_key" ) );

  // push esp (x64 way)
  // mov rdx, rsp (2nd argument)
  shellcode.AddBytes( { 0x48, 0x8B, 0xD4 } );

  // push first argument
  // mov rcx, 4 byte variables (1st argument)
  //shellcode.AddByte( 0xB9 );
  //shellcode.AddValue<uint32_t>( 0, TEXT( "VmCodeAddr" ) );

  // mov rcx, 8bytes
  shellcode.AddBytes( { 0x48, 0xB9 } );
  shellcode.AddValue<uint64_t>( 0, TEXT( "VmCodeAddr" ) );

  shellcode.AddByte( 0xE8 );  // call
  shellcode.AddValue( 0, TEXT( "VmCoreFunction" ) );

  // De-Allocate stack space for the function call, the stack space depends on how many arguments the call has
  // in this case it has 4, so i dont know
  // add rsp, 100h
  shellcode.AddBytes( { 0x48, 0x81, 0xC4, 0x00, 0x01, 0x00, 0x00 } );

  shellcode.AddByte( 0x5C );  // pop esp

  shellcode.AddBytes( { 0x41, 0x5F } );  // pop r15
  shellcode.AddBytes( { 0x41, 0x5E } );  // pop r14
  shellcode.AddBytes( { 0x41, 0x5D } );  // pop r13
  shellcode.AddBytes( { 0x41, 0x5C } );  // pop r12
  shellcode.AddBytes( { 0x41, 0x5B } );  // pop r11
  shellcode.AddBytes( { 0x41, 0x5A } );  // pop r10
  shellcode.AddBytes( { 0x41, 0x59 } );  // pop r9
  shellcode.AddBytes( { 0x41, 0x58 } );  // pop r8

  // pop xmm0
  shellcode.AddBytes(
      { 0xF3, 0x0F, 0x6F, 0x04, 0x24 } );  // movdqu xmm0, xmmword ptr ss:[rsp]
  shellcode.AddBytes( { 0x48, 0x83, 0xC4, 0x10 } );  // add rsp, 0x16

  // pop xmm1
  shellcode.AddBytes(
      { 0xF3, 0x0F, 0x6F, 0x0C, 0x24 } );  // movdqu xmm1, xmmword ptr ss:[rsp]
  shellcode.AddBytes( { 0x48, 0x83, 0xC4, 0x10 } );  // add rsp, 0x16

  // pop xmm2
  shellcode.AddBytes(
      { 0xF3, 0x0F, 0x6F, 0x14, 0x24 } );  // movdqu xmm2, xmmword ptr ss:[rsp]
  shellcode.AddBytes( { 0x48, 0x83, 0xC4, 0x10 } );  // add rsp, 0x16

  // pop xmm3
  shellcode.AddBytes(
      { 0xF3, 0x0F, 0x6F, 0x1C, 0x24 } );  // movdqu xmm3, xmmword ptr ss:[rsp]
  shellcode.AddBytes( { 0x48, 0x83, 0xC4, 0x10 } );  // add rsp, 0x16

  // pop xmm4
  shellcode.AddBytes(
      { 0xF3, 0x0F, 0x6F, 0x24, 0x24 } );  // movdqu xmm4, xmmword ptr ss:[rsp]
  shellcode.AddBytes( { 0x48, 0x83, 0xC4, 0x10 } );  // add rsp, 0x16

  // pop xmm5
  shellcode.AddBytes(
      { 0xF3, 0x0F, 0x6F, 0x2C, 0x24 } );  // movdqu xmm5, xmmword ptr ss:[rsp]
  shellcode.AddBytes( { 0x48, 0x83, 0xC4, 0x10 } );  // add rsp, 0x16

  // pop xmm6
  shellcode.AddBytes(
      { 0xF3, 0x0F, 0x6F, 0x34, 0x24 } );  // movdqu xmm6, xmmword ptr ss:[rsp]
  shellcode.AddBytes( { 0x48, 0x83, 0xC4, 0x10 } );  // add rsp, 0x16

  // pop xmm7
  shellcode.AddBytes(
      { 0xF3, 0x0F, 0x6F, 0x3C, 0x24 } );  // movdqu xmm7, xmmword ptr ss:[rsp]
  shellcode.AddBytes( { 0x48, 0x83, 0xC4, 0x10 } );  // add rsp, 0x16

  shellcode.AddByte( 0x5F );  // pop edi
  shellcode.AddByte( 0x5E );  // pop esi
  shellcode.AddByte( 0x5D );  // pop ebp
  shellcode.AddByte( 0x5A );  // pop edx
  shellcode.AddByte( 0x59 );  // pop ecx
  shellcode.AddByte( 0x5B );  // pop ebx
  shellcode.AddByte( 0x58 );  // pop eax

  shellcode.AddByte( 0x9D );  // popfd

  if ( vm_opcode == VmOpcodes::CALL_IMMEDIATE ) {
    // Before jmp back:
    // add esp, 4 || 83 C4 04
    // call dword ptr ss:[esp-0x4] || FF 54 24 FC
    //shellcode.AddBytes( { 0x83, 0xC4, 0x04 } );
    shellcode.AddBytes( { 0x48, 0x83, 0xC4, 0x08 } );  // add rsp, 0x8
    //shellcode.AddBytes( { 0x48, 0x83, 0xC4, 0x04 } );  // add rsp, 0x4

    // call qword ptr ss:[rsp-0x8]
    shellcode.AddBytes( { 0xFF, 0x54, 0x24, 0xF8 } );
  } else if ( vm_opcode == VmOpcodes::CALL_MEMORY ) {
    // Before jmp back:
    // add esp, 4 || 83 C4 04
    // call dword ptr ds:[esp-0x4] || 3E FF 54 24 FC
    //shellcode.AddBytes( { 0x83, 0xC4, 0x04 } );
    shellcode.AddBytes( { 0x48, 0x83, 0xC4, 0x08 } );  // add rsp, 0x8

    // call qword ptr ds:[rsp-0x8]
    shellcode.AddBytes( { 0x3E, 0xFF, 0x54, 0x24, 0xF8 } );
  }

  shellcode.AddByte( 0xE9 );  // jmp
  shellcode.AddValue( 0, TEXT( "OrigAddr" ) );

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