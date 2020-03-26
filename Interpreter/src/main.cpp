#include <Windows.h>
#include <cstdint>
#include <stdio.h>

#include <intrin.h>

#include "main.h"

#pragma code_seg( VM_FUNCTIONS_SECTION_NAME )

/*
#if DLL
__declspec( dllexport ) void NTAPI __declspec( dllexport ) BOOL WINAPI
    EntryPoint( HINSTANCE instance, DWORD reason, LPVOID reserved ) {}
#else
__declspec( dllexport ) int WINAPI EntryPoint( HINSTANCE instance,
                                               HINSTANCE prev_instance,
                                               PWSTR cmdline,
                                               int cmdshow ) {}
#endif
*/

__declspec( dllexport ) void NTAPI
    TlsCallback( PVOID DllHandle, DWORD Reason, PVOID Reserved ) {}

void PushValueToRealStack( VM_CONTEXT* vm_context, uintptr_t value ) {
  const auto current_registers_address =
      reinterpret_cast<uintptr_t>( vm_context->registers );

  auto current_register_last_value_address =
      current_registers_address + sizeof( VM_REGISTERS ) - sizeof( uintptr_t );

  // Make a copy of the registers
  const auto registers_copy = *vm_context->registers;

  // Get the new registers address on the stack (subtracted by sizeof(ptr))
  auto new_registers = reinterpret_cast<VM_REGISTERS*>(
      current_registers_address - sizeof( uintptr_t ) );

  // Copy the registers to the new location
  *new_registers = *vm_context->registers;

  // Set the push value
  *( uintptr_t* )current_register_last_value_address = value;

  // Modify esp appropriately in order to return to the correct esp so the
  // pushed arguments show on top of stack
  vm_context->esp -= sizeof( uintptr_t );
}

uintptr_t* GetRegisterValuePointer( VM_CONTEXT* vm_context,
                                    uint32_t reg_offset ) {
  uint8_t* register_struct_bytes = ( uint8_t* )vm_context->registers;
  return ( uintptr_t* )( register_struct_bytes + reg_offset );
}

const PEB* GetCurrentPeb() {
#if defined( _WIN64 )
  uintptr_t peb_addr = __readgsqword( 0x60 );
#else
  uintptr_t peb_addr = __readfsdword( 0x30 );
#endif
  return reinterpret_cast<const PEB*>( peb_addr );
}

template <typename T>
T ReadValue( uint8_t** code ) {
  const T value = *reinterpret_cast<T*>( *code );

  *code += sizeof( T );

  return value;
}

// Used when an instruction has e.g. "mov dword ptr" or "mov byte ptr"
void WriteValueToDestinationSpecificSize( const uint8_t size,
                                          uint32_t write_dest_addr,
                                          uint32_t value ) {
  // NOTE: Using a switch causes a jump table to be created, but we cannot do it
  // because since we added a dynamic base support, the interpreter is not being
  // relocated to the new random base address
  // We would have to copy the relocations from the interpreter inside this
  // section into new PE

  /*
  switch ( size ) {
    case 1: {
      auto reg_dest_value_with_disp = ( uint8_t* )( write_dest_addr );
      *reg_dest_value_with_disp = value;
    } break;
    case 2: {
      auto reg_dest_value_with_disp = ( uint16_t* )( write_dest_addr );
      *reg_dest_value_with_disp = value;
    } break;
    case 4: {
      auto reg_dest_value_with_disp = ( uint32_t* )( write_dest_addr );
      *reg_dest_value_with_disp = value;
    } break;
    case 8: {
      auto reg_dest_value_with_disp = ( uint64_t* )( write_dest_addr );
      *reg_dest_value_with_disp = value;
    } break;
    default:
      break;
  }
  */

  if ( size == 1 ) {
    auto reg_dest_value_with_disp = ( uint8_t* )( write_dest_addr );
    *reg_dest_value_with_disp = value;
  } else if ( size == 2 ) {
    auto reg_dest_value_with_disp = ( uint16_t* )( write_dest_addr );
    *reg_dest_value_with_disp = value;
  } else if ( size == 4 ) {
    auto reg_dest_value_with_disp = ( uint32_t* )( write_dest_addr );
    *reg_dest_value_with_disp = value;
  } else if ( size == 8 ) {
    auto reg_dest_value_with_disp = ( uint64_t* )( write_dest_addr );
    *reg_dest_value_with_disp = value;
  }
}

/*
    Notes:

    Adding (__declspec(dllexport)) in order to export the function ensures that
   the parameters won't be incorrectly optimized due to the way I am calling
   this function inside of the code.

    Use __stdcall calling convention because I need the functionality to be able
   to push the parameters to the function. When using __fastcall it uses the
   registers immedietly expecting that you have specific registers with proper
   values. On x64 the only calling convention is __fastcall, I hate it...fuck.
  */

#ifdef _WIN64
__declspec( dllexport ) int32_t
    __fastcall VmInterpreter( uint8_t* code,
                              size_t allocated_stack_addr,
                              uint32_t vm_opcode_encyption_key,
                              uintptr_t image_base_address ) {
#else
__declspec( dllexport ) int32_t
    __stdcall VmInterpreter( uint8_t* code,
                             size_t allocated_stack_addr,
                             uint32_t vm_opcode_encyption_key,
                             uintptr_t image_base_address ) {
#endif
  // The total bytes of the arguments that was pushed to this function call
  // before the esp was pushed
  uint32_t kTotalParametersBeforeEspPush = sizeof( uint32_t ) * 2;

#ifdef _WIN64
  kTotalParametersBeforeEspPush = /*16*/ 0;
#endif

  // for the sub and add before and after call

  // A value that describes the amount of stack we allocate before we call this interpreter in the loader shellcode
  // It is based on the sub esp, 0x100
  //                    add esp, 0x100
  // This is not required for x86, but I am still doing it for consistency on both x86 and x64
  const auto interpreter_call_stack_allocation_space = 0x100 /*+ (0x16 * 8)*/;

  // Read whole struct from stack in one read
  VM_CONTEXT* vm_context =
      ( VM_CONTEXT* )( allocated_stack_addr + kTotalParametersBeforeEspPush +
                       interpreter_call_stack_allocation_space );

  // Initialize the pointer to the pushed registers
  vm_context->registers =
      ( VM_REGISTERS* )( ( uintptr_t )( vm_context ) +
                         VM_INTERPRETER_STACK_ALLOCATION_SIZE_BYTES +
                         sizeof( vm_context->esp ) -
                         offsetof( VM_CONTEXT, registers ) +
                         sizeof( vm_context->registers ) );

  /*
  const auto peb = GetCurrentPeb();

#if DLL
  const auto ret_addr = reinterpret_cast<uintptr_t>( _ReturnAddress() );

  // TODO: Find a better universal solution to get the image base address with
  // better performance that works for both exe and dll

  // TODO: Instead of having a variable for the default pe base address
  // (DEFAULT_PE_BASE_ADDRESS) Read it from the header after retreiving the
  // image base and save it somewhere to be able to protect both EXE and DLL
  // without recompilation

  // NOTE: Manualmapping does not work because the module is not linked in the
  // PEB
  // I can fix by on entrypoint using __stdcall DLLMAIN parameters and use
  // HINSTANCE and save it. Because multiple threads can read from same location
  // without issues.

  uintptr_t image_base_address = 0;

  const auto beginning_link = &peb->Ldr->InLoadOrderModuleList;

  auto current_link = beginning_link->Flink;

  do {
    const auto entry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>( current_link );

    const auto image_base = reinterpret_cast<uintptr_t>( entry->DllBase );

    // If the return address is within the range of the module
    if ( ret_addr >= image_base &&
         ret_addr < ( image_base + entry->SizeOfImage ) ) {
      image_base_address = image_base;
      break;
    }

    current_link = current_link->Flink;
  } while ( current_link != beginning_link && current_link );
#else
  const auto image_base_address =
      reinterpret_cast<uintptr_t>( peb->ImageBaseAddress );
#endif
*/

  code += image_base_address;

  const auto vm_opcode = ReadValue<uint32_t>( &code ) ^ vm_opcode_encyption_key;

  const auto relocated_disp = ReadValue<uint8_t>( &code );
  const auto relocated_imm = ReadValue<uint8_t>( &code );

  // NOTE: Cannot use the nt_header->ImageBase to get default image base, it
  // gets relocated

  switch ( vm_opcode ) {
    case 0x90: {
      break;
    } break;

    case VmOpcodes::MOV_REGISTER_MEMORY_REG_OFFSET: {
      // Read the next 4 bytes as uint32_t
      const auto reg_dest_offset = ReadValue<uint32_t>( &code );
      const auto reg_src_offset = ReadValue<uint32_t>( &code );

      auto reg_src_disp = ReadValue<uintptr_t>( &code );

      if ( relocated_disp ) {
        reg_src_disp =
            reg_src_disp - DEFAULT_PE_BASE_ADDRESS + image_base_address;
      }

      const auto reg_src_value =
          *GetRegisterValuePointer( vm_context, reg_src_offset );

      const auto reg_src_value_with_disp = reg_src_value + reg_src_disp;

      const auto mov_value = *( uintptr_t* )reg_src_value_with_disp;

      *GetRegisterValuePointer( vm_context, reg_dest_offset ) = mov_value;
    } break;

    case VmOpcodes::MOV_REGISTER_MEMORY_IMMEDIATE: {
      const auto reg_offset = ReadValue<uint32_t>( &code );
      auto value = ReadValue<uintptr_t>( &code );

      if ( relocated_disp ) {
        value = value - DEFAULT_PE_BASE_ADDRESS + image_base_address;
      }

      *GetRegisterValuePointer( vm_context, reg_offset ) =
          *( uintptr_t* )( value );
    } break;

    case VmOpcodes::MOV_REGISTER_REGISTER: {
      const auto reg_offset_dest = ReadValue<uint32_t>( &code );
      const auto reg_offset_src = ReadValue<uint32_t>( &code );

      *GetRegisterValuePointer( vm_context, reg_offset_dest ) =
          *GetRegisterValuePointer( vm_context, reg_offset_src );
    } break;

    case VmOpcodes::MOV_REGISTER_IMMEDIATE: {
      // Read the next 4 bytes as uint32_t
      const auto reg_offset = ReadValue<uint32_t>( &code );

      auto value = ReadValue<uintptr_t>( &code );

      if ( relocated_imm ) {
        value = value - DEFAULT_PE_BASE_ADDRESS + image_base_address;
      }

      *GetRegisterValuePointer( vm_context, reg_offset ) = value;
    } break;

    case VmOpcodes::MOV_MEMORY_REG_OFFSET_REG: {
      // Read the next 4 bytes as uint32_t
      const auto reg_dest_offset = ReadValue<uint32_t>( &code );
      const auto reg_src_offset = ReadValue<uint32_t>( &code );

      auto reg_dest_disp = ReadValue<uintptr_t>( &code );

      if ( relocated_disp ) {
        reg_dest_disp =
            reg_dest_disp - DEFAULT_PE_BASE_ADDRESS + image_base_address;
      }

      // Read the src register value
      const auto reg_src_value =
          *GetRegisterValuePointer( vm_context, reg_src_offset );

      const auto reg_dest_value =
          *GetRegisterValuePointer( vm_context, reg_dest_offset );

      auto reg_dest_value_with_disp =
          ( uintptr_t* )( reg_dest_value + reg_dest_disp );

      *reg_dest_value_with_disp = reg_src_value;
    } break;

    case VmOpcodes::MOV_MEMORY_REG_OFFSET_IMM: {
      // Example 1: mov dword ptr [eax + 0x7d765c], 2
      // Example 2: mov dword ptr [ebp - 0x20], 0x7d7268

      const auto reg_dest_offset = ReadValue<uint32_t>( &code );

      auto source_value = ReadValue<uintptr_t>( &code );
      auto reg_dest_disp = ReadValue<uintptr_t>( &code );

      const auto dest_size = ReadValue<uint32_t>( &code );

      if ( relocated_disp ) {
        reg_dest_disp =
            reg_dest_disp - DEFAULT_PE_BASE_ADDRESS + image_base_address;
      } else if ( relocated_imm ) {
        source_value =
            source_value - DEFAULT_PE_BASE_ADDRESS + image_base_address;
      }

      const auto reg_dest_value =
          *GetRegisterValuePointer( vm_context, reg_dest_offset );

      // TODO: Call WriteValueToDestinationSpecificSize for all instructions
      // that has the dword ptr or byte ptr or word ptr

      WriteValueToDestinationSpecificSize(
          dest_size, reg_dest_value + reg_dest_disp, source_value );
    } break;

    case VmOpcodes::SUB_REGISTER_IMMEDIATE: {
      // UPDATE THE CODE BEFORE USING IT
      /*
      // Read the next 4 bytes as uint32_t
      uint32_t reg_offset = *( uint32_t* )( code + i + 4 );
      uint32_t value = *( uint32_t* )( code + i + 8 );

      i += 8;

      const uint32_t reg_dest_value =
          *GetRegisterValuePointer( vm_context, reg_offset );

      *GetRegisterValuePointer( vm_context, reg_offset ) =
          reg_dest_value - value;
      */
    } break;

    case VmOpcodes::SUB_REGISTER_MEMORY_REG_OFFSET: {
      // UPDATE THE CODE BEFORE USING IT
      /*
      // Read the next 4 bytes as uint32_t
      uint32_t reg_dest_offset = *( uint32_t* )( code + i + 4 );
      uint32_t reg_src_offset = *( uint32_t* )( code + i + 8 );
      int32_t reg_src_disp = *( int32_t* )( code + i + 12 );

      uint32_t reg_src_value =
          *GetRegisterValuePointer( vm_context, reg_src_offset );
      uint32_t reg_src_value_with_disp = reg_src_value + reg_src_disp;

      uint32_t sub_value = *( uint32_t* )reg_src_value_with_disp;

      i += 12;

      *GetRegisterValuePointer( vm_context, reg_dest_offset ) =
          *GetRegisterValuePointer( vm_context, reg_dest_offset ) - sub_value;
      */
    } break;

    case VmOpcodes::CALL_MEMORY: {
      // push the call address to the stack

      auto absolute_call_target_addr_addr = ReadValue<uintptr_t>( &code );

      if ( relocated_disp ) {
        absolute_call_target_addr_addr = absolute_call_target_addr_addr -
                                         DEFAULT_PE_BASE_ADDRESS +
                                         image_base_address;
      }

      uintptr_t absolute_call_target_addr =
          *( uintptr_t* )absolute_call_target_addr_addr;

      PushValueToRealStack( vm_context, absolute_call_target_addr );

      // when exiting the vm (before jmp back), push return address
      // then jmp to
    } break;

    case VmOpcodes::CALL_IMMEDIATE: {
      // push the call address to the stack

      auto absolute_call_target_addr = ReadValue<uintptr_t>( &code );

      // add the image base
      // absolute_call_target_addr += DEFAULT_PE_BASE_ADDRESS;
      absolute_call_target_addr += image_base_address;

      PushValueToRealStack( vm_context, absolute_call_target_addr );

      // when exiting the vm (before jmp back), push return address
      // then jmp to
    } break;

    case VmOpcodes::PUSH_IMM: {
      auto pushed_addr = ReadValue<uintptr_t>( &code );

      if ( relocated_imm ) {
        pushed_addr =
            pushed_addr - DEFAULT_PE_BASE_ADDRESS + image_base_address;
      }

      PushValueToRealStack( vm_context, pushed_addr );
    } break;

    case VmOpcodes::PUSH_REGISTER_MEMORY_REG_OFFSET: {
      const auto reg_src_offset = ReadValue<uint32_t>( &code );
      auto reg_src_disp = ReadValue<uintptr_t>( &code );

      if ( relocated_disp ) {
        reg_src_disp =
            reg_src_disp - DEFAULT_PE_BASE_ADDRESS + image_base_address;
      }

      // read the register value
      const auto reg_src_value =
          *GetRegisterValuePointer( vm_context, reg_src_offset );

      // read the stack value at the register + disp offset
      const auto value_to_push =
          *( uintptr_t* )( reg_src_value + reg_src_disp );

      PushValueToRealStack( vm_context, value_to_push );
    } break;

      // case VmOpcodes::JUMP_RELATIVE:
      //{
      //  // Check if the destination address is within the size of the
      //  virtualized code

      //  int8_t jump_offset = *(int8_t *)(code + i + 4);
      //  int8_t jump_instruction_count = *(int8_t *)(code + i + 5);
      //  uint32_t origin_address = *(uint32_t *)(code + i + 8);

      //  if (jump_offset < 0) {
      //    // it jumps backwards
      //  }
      //  else {
      //    if (jump_offset) {

      //    }
      //  }
      //} break;

    default:
      break;
  }

  // TODO: When returning, push all the values on the vm_stack to the real stack

  // Return 0 indicating that we should exit the handler and everything is good.
  return 0;
}

// Reset the code_seg, add code to normal .text section again
#pragma code_seg()

// VS OPTIONS
// JUST MY CODE: NO
// SECURITY CHECK: NO
// SAFE EXCEPTION HANDLER: NO
// BASIC RUNTIME CHECKS: DEFAULT
// ENABLED ENHANCED INSTRUCTION SET: IA32 (required to avoid interpreter from
// using SSE2, then we would need to save the XMM registers)

/*
  TODO:
  Protect with SEC_NO_CHANGE, then look if CreateSection was hooked or somehow
  did not succeed by trying to manipulate the protected memory. If an error
  occured while trying to change memory protection, then we're good.
  // Look at this possible to thing detect protectino changes:
  https://stackoverflow.com/questions/8004945/how-to-catch-a-memory-write-and-call-function-with-address-of-write

  ---


*/

BOOL WINAPI DllMain( HINSTANCE instance_handle,
                     DWORD reason,
                     LPVOID reserved ) {
  printf( "Fuck me 1" );

  VmInterpreter( ( uint8_t* )0x1, 0x2, 0x3, 0x4 );

  printf( "Fuck me 2" );

  return 1;
}

/*
  Where I left off:
  I was going to fix x64, but, is it not possible to disable xmm registers on
  the x64 build
*/