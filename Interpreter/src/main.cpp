/*
  Visual Studio Project Settings

  JUST MY CODE: NO
  SECURITY CHECK: NO
  SAFE EXCEPTION HANDLER: NO
  BASIC RUNTIME CHECKS: DEFAULT
  ENABLED ENHANCED INSTRUCTION SET: IA32 (required to avoid interpreter from
                                          using SSE2, then we would need to save the XMM registers)

  Debug Version has limitations because it e.g. always initializes variables to zero.
  With arrays, it does so with a memcpy function located in the .text section.
  Meaning that when I virtualize my TLS callbacks, it tried to virtualize a call that 
  is not located in the section and crashes.

  Protect with SEC_NO_CHANGE, then look if CreateSection was hooked or somehow
  did not succeed by trying to manipulate the protected memory. If an error
  occured while trying to change memory protection, then we're good.
  // Look at this possible to thing detect protectino changes:
  https://stackoverflow.com/questions/8004945/how-to-catch-a-memory-write-and-call-function-with-address-of-write
*/

#include <Windows.h>
#include <cstdint>
#include <stdio.h>

#include <intrin.h>

#include "main.h"

#pragma code_seg( VM_FUNCTIONS_SECTION_NAME )

using LoadLibraryA_t = decltype( &LoadLibraryA );
using GetProcAddress_t = decltype( &GetProcAddress );
using VirtualProtect_t = decltype( &VirtualProtect );
using VirtualAlloc_t = decltype( &VirtualAlloc );

struct Modules {
  uintptr_t ntdll;
  uintptr_t kernel32;
};

struct ApiAddresses {
  LoadLibraryA_t LoadLibraryA;
  GetProcAddress_t GetProcAddress;
  VirtualProtect_t VirtualProtect;
  VirtualAlloc_t VirtualAlloc;
};

IMAGE_NT_HEADERS* GetNtHeaders( const PVOID base ) {
  auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>( base );
  auto nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(
      reinterpret_cast<uint8_t*>( dos_header ) + dos_header->e_lfanew );
  return nt_header;
}

void FixNextCorruptedTlsCallback( PVOID dll_base ) {
  const auto base_addr = reinterpret_cast<uintptr_t>( dll_base );

  auto nt_headers = GetNtHeaders( dll_base );

  auto tls_data_directory =
      &nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_TLS ];

  if ( tls_data_directory->Size != 0 ) {
    auto tls_directory = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(
        base_addr + tls_data_directory->VirtualAddress );
    // In the function AddTlsCallbacks() I always add my TLS callbacks as the two last ones
    // The last TLS callback is the one we will "decrypt"
    auto callback_list =
        reinterpret_cast<uintptr_t*>( tls_directory->AddressOfCallBacks );

    uintptr_t* last_tls_callback = 0;

    for ( ; *callback_list; callback_list++ ) {
      last_tls_callback = callback_list;
    }

    // TODO: Consider using a better solution to fix the corrupted tls callback
    // E.g. XOR the value to decrypt it
    *last_tls_callback += DEFAULT_PE_BASE_ADDRESS;
  }
}

// A basic hash function to bypass usage of string
constexpr uintptr_t HashString( const char* s ) {
  return *s ? static_cast<uintptr_t>( *s ) + 653119926 * HashString( s + 1 )
            : 75438945;
}

constexpr uintptr_t HashStringBuffer( const char* s, const int size ) {
  return size != 0 ? static_cast<uintptr_t>( *s ) +
                         653119926 * HashStringBuffer( s + 1, size - 1 )
                   : 75438945;
}

// A basic hash function to bypass usage of string
constexpr uintptr_t HashWideString( const wchar_t* s ) {
  return *s ? static_cast<uintptr_t>( *s ) + 653119926 * HashWideString( s + 1 )
            : 75438945;
}

constexpr wchar_t ToLowerConstexpr( wchar_t c ) {
  if ( c >= 'A' && c <= 'Z' ) {
    return 'a' + c - 'A';
  }

  return c;
}

/*
constexpr char ToLowerConstexpr( char c ) {
  if ( c >= 'A' && c <= 'Z' ) {
    return 'a' + c - 'A';
  }

  return c;
}
*/

constexpr uintptr_t HashWideStringLowercase( const wchar_t* s ) {
  return *s ? static_cast<uintptr_t>( ToLowerConstexpr( *s ) ) +
                  653119926 * HashWideStringLowercase( s + 1 )
            : 75438945;
}

constexpr uintptr_t HashWideStringLowercase( const wchar_t* s,
                                             const int size ) {
  return size != 0 ? static_cast<uintptr_t>( ToLowerConstexpr( *s ) ) +
                         653119926 * HashWideStringLowercase( s + 1, size - 1 )
                   : 75438945;
}

const PEB* GetCurrentPeb() {
#if defined( _WIN64 )
  uintptr_t peb_addr = __readgsqword( 0x60 );
#else
  uintptr_t peb_addr = __readfsdword( 0x30 );
#endif
  return reinterpret_cast<const PEB*>( peb_addr );
}

/*
wchar_t ToLower( wchar_t c ) {
  if ( c >= 'A' && c <= 'Z' ) {
    return 'a' + c - 'A';
  }

  return c;
}

void WideToLower( wchar_t* s, wchar_t* buf_out ) {
  for ( ; *s; ++s, ++buf_out ) {
    *buf_out = ToLower( *s );
  }
}

void MemorySet( uint8_t* src, int size, uint8_t value ) {
  for ( int i = 0; i < size; ++i ) {
    *src = value;
    ++src;
  }
}
*/

void MemoryCopy( uint8_t* src, uint8_t* dest, int size ) {
  for ( int i = 0; i < size; ++i ) {
    *dest = *src;

    ++src;
    ++dest;
  }
}

uintptr_t GetModule( const uintptr_t module_name_hash ) {
  const auto peb = GetCurrentPeb();

  const auto head = &peb->Ldr->InLoadOrderModuleList;

  // Set the first entry
  auto link = head->Flink;

  do {
    auto entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>( link );

    const auto name_length = entry->BaseDllName.Length / sizeof( wchar_t );

    const auto current_module_hash = HashWideStringLowercase(
        reinterpret_cast<wchar_t*>( entry->BaseDllName.Buffer ), name_length );

    if ( current_module_hash == module_name_hash ) {
      return reinterpret_cast<uintptr_t>( entry->DllBase );
    }

    link = link->Flink;
  } while ( link != head );

  return 0;
}

uintptr_t GetExport( const uintptr_t module,
                     const uintptr_t ansi_export_name_hash ) {
  const auto nt_headers = GetNtHeaders( reinterpret_cast<PVOID>( module ) );

  const auto& export_data_directory =
      nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

  const auto export_directory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
      module + export_data_directory.VirtualAddress );

  const auto names =
      reinterpret_cast<uint32_t*>( module + export_directory->AddressOfNames );
  const auto ordinals = reinterpret_cast<uint16_t*>(
      module + export_directory->AddressOfNameOrdinals );
  const auto addresses = reinterpret_cast<uint32_t*>(
      module + export_directory->AddressOfFunctions );

  for ( int i = 0; i < export_directory->NumberOfNames; ++i ) {
    const auto name = ( const char* )( module + names[ i ] );

    if ( HashString( name ) == ansi_export_name_hash ) {
      const auto address = addresses[ ordinals[ i ] ];
      return module + address;
    }
  }

  return 0;
}

IMAGE_SECTION_HEADER* GetSectionHeaderByHash( const PVOID base,
                                              const uintptr_t name_hash ) {
  const auto nt_headers = GetNtHeaders( base );

  const auto sections = IMAGE_FIRST_SECTION( nt_headers );

  for ( int i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i ) {
    const auto section = &sections[ i ];

    const auto section_name_hash =
        HashString( reinterpret_cast<const char*>( section->Name ) );

    if ( section_name_hash == name_hash ) {
      return &sections[ i ];
    }
  }

  return 0;
}

uintptr_t GetVmCodeSection( const PVOID base ) {
  constexpr auto vm_code_section_name_hash =
      HashWideString( TEXT( VM_CODE_SECTION_NAME ) );

  const auto sec_header =
      GetSectionHeaderByHash( base, vm_code_section_name_hash );

  return reinterpret_cast<uintptr_t>( base ) + sec_header->VirtualAddress;
}

void FixImports( uint8_t* dll_base_addr,
                 VmCodeSectionData* vm_code_section_data,
                 const IMAGE_DATA_DIRECTORY& import_data_directory,
                 const ApiAddresses& apis ) {
  const auto import_redirections_alloc_size =
      vm_code_section_data->import_count *
      sizeof( vm_code_section_data->import_redirect_shellcode );

  int import_redirect_memory_offset = 0;

  // Allocate the memory where we'll write all of the import redirections
  const auto import_redirect_memory = reinterpret_cast<uintptr_t>(
      apis.VirtualAlloc( NULL, import_redirections_alloc_size,
                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) );

  auto import_desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
      dll_base_addr + import_data_directory.VirtualAddress );

  // For each import descriptor
  for ( ; import_desc->Name; ++import_desc ) {
    const auto dll_name =
        reinterpret_cast<const char*>( dll_base_addr + import_desc->Name );

    const HINSTANCE dll_instance = apis.LoadLibraryA( dll_name );

    // We read from the original thunk
    auto original_thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
        dll_base_addr + import_desc->OriginalFirstThunk );

    // We write to the first thunk
    auto first_thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
        dll_base_addr + import_desc->FirstThunk );

    // For each import thunk
    for ( ; original_thunk->u1.AddressOfData;
          ++original_thunk, ++first_thunk ) {
      uintptr_t import_function_address = 0;

      if ( IMAGE_SNAP_BY_ORDINAL( original_thunk->u1.Ordinal ) ) {
        // TODO: Replace with my own get proc address, support ordinal tho
        import_function_address =
            reinterpret_cast<uintptr_t>( apis.GetProcAddress(
                dll_instance, reinterpret_cast<char*>(
                                  LOWORD( original_thunk->u1.Ordinal ) ) ) );
      } else {
        const auto import_by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
            dll_base_addr + original_thunk->u1.AddressOfData );

        import_function_address = reinterpret_cast<uintptr_t>(
            apis.GetProcAddress( dll_instance, import_by_name->Name ) );
      }

#if ENABLE_API_REDIRECTION
      auto redirection_shellcode =
          vm_code_section_data->import_redirect_shellcode;

      // TODO: Consider randomly generating/modifying one line in the shellcode to not only have a simple XOR
      // TODO: Generate the xor key "randomly" using the import_redirect_memory_offset as a seed

      const uint32_t xor_key = 0x1337;

#ifdef _WIN64
      // Write the encrypted address
      *reinterpret_cast<uint64_t*>( redirection_shellcode + 5 ) =
          import_function_address ^ xor_key;

      // Write the xor key
      *reinterpret_cast<uint32_t*>( redirection_shellcode + 15 ) = xor_key;
#else
      // Write the encrypted address
      *reinterpret_cast<uint32_t*>( redirection_shellcode + 4 ) =
          import_function_address ^ xor_key;

      // Write the xor key
      *reinterpret_cast<uint32_t*>( redirection_shellcode + 9 ) = xor_key;
#endif

      const auto redirection_destination = reinterpret_cast<uint8_t*>(
          import_redirect_memory + import_redirect_memory_offset );

      // Write the redirection shellcode to the allocated location
      MemoryCopy( redirection_shellcode, redirection_destination,
                  sizeof( vm_code_section_data->import_redirect_shellcode ) );

      DWORD old_protection;
      apis.VirtualProtect( first_thunk, sizeof( IMAGE_THUNK_DATA ),
                           PAGE_EXECUTE_READWRITE, &old_protection );

      // Set the API call to the redirection shellcode
      *reinterpret_cast<uintptr_t*>( first_thunk ) =
          import_redirect_memory + import_redirect_memory_offset;

      apis.VirtualProtect( first_thunk, sizeof( IMAGE_THUNK_DATA ),
                           old_protection, &old_protection );

      import_redirect_memory_offset +=
          sizeof( vm_code_section_data->import_redirect_shellcode );
#else
      DWORD old_protection;
      apis.VirtualProtect( first_thunk, sizeof( IMAGE_THUNK_DATA ),
                           PAGE_EXECUTE_READWRITE, &old_protection );

      // Set the API call to the redirection shellcode
      *reinterpret_cast<uintptr_t*>( first_thunk ) = import_function_address;

      apis.VirtualProtect( first_thunk, sizeof( IMAGE_THUNK_DATA ),
                           old_protection, &old_protection );
#endif
    }
  }
}

void AntiAttachDebugger( const Modules& module_addresses,
                         const ApiAddresses& apis ) {
  constexpr auto dbg_ui_remote_breakin_hash =
      HashString( "DbgUiRemoteBreakin" );
  const auto dbg_ui_remote_breakin =
      GetExport( module_addresses.ntdll, dbg_ui_remote_breakin_hash );

  constexpr auto dbg_break_point_hash = HashString( "DbgBreakPoint" );
  const auto dbg_breakpoint =
      GetExport( module_addresses.ntdll, dbg_break_point_hash );

  DWORD old_protection;
  apis.VirtualProtect( reinterpret_cast<LPVOID>( dbg_ui_remote_breakin ), 1,
                       PAGE_READWRITE, &old_protection );

  // ret
  *reinterpret_cast<uint8_t*>( dbg_ui_remote_breakin ) = 0xC3;

  apis.VirtualProtect( reinterpret_cast<LPVOID>( dbg_ui_remote_breakin ), 1,
                       old_protection, &old_protection );

  apis.VirtualProtect( reinterpret_cast<LPVOID>( dbg_breakpoint ), 1,
                       PAGE_READWRITE, &old_protection );

  // ret
  *reinterpret_cast<uint8_t*>( dbg_breakpoint ) = 0xC3;

  apis.VirtualProtect( reinterpret_cast<LPVOID>( dbg_breakpoint ), 1,
                       old_protection, &old_protection );
}

Modules GetModules() {
  constexpr auto ntdll_hash = HashWideString( TEXT( "ntdll.dll" ) );
  const auto ntdll = GetModule( ntdll_hash );

  constexpr auto kernel32_hash = HashWideString( TEXT( "kernel32.dll" ) );
  const auto kernel32 = GetModule( kernel32_hash );

  Modules module_addresses;

  module_addresses.kernel32 = kernel32;
  module_addresses.ntdll = ntdll;

  return module_addresses;
}

ApiAddresses InitializeApis( const Modules& modules ) {
  const auto kernel32 = modules.kernel32;
  const auto ntdll = modules.ntdll;

  constexpr auto load_library_a_hash = HashString( "LoadLibraryA" );
  const auto load_library_a = reinterpret_cast<decltype( &LoadLibraryA )>(
      GetExport( kernel32, load_library_a_hash ) );

  constexpr auto get_proc_address_hash = HashString( "GetProcAddress" );
  const auto get_proc_address = reinterpret_cast<decltype( &GetProcAddress )>(
      GetExport( kernel32, get_proc_address_hash ) );

  constexpr auto virtual_protect_hash = HashString( "VirtualProtect" );
  const auto virtual_protect = reinterpret_cast<decltype( &VirtualProtect )>(
      GetExport( kernel32, virtual_protect_hash ) );

  constexpr auto virtual_alloc_hash = HashString( "VirtualAlloc" );
  const auto virtual_alloc = reinterpret_cast<decltype( &VirtualAlloc )>(
      GetExport( kernel32, virtual_alloc_hash ) );

  ApiAddresses apis;

  apis.GetProcAddress = get_proc_address;
  apis.LoadLibraryA = load_library_a;
  apis.VirtualProtect = virtual_protect;
  apis.VirtualAlloc = virtual_alloc;

  return apis;
}

__declspec( dllexport ) void NTAPI
    FirstTlsCallback( PVOID dll_base, DWORD reason, PVOID reserved ) {
  // TODO: use fiber to execute the all the code

  /*
    Remove the TLS callback immediately after they are called, in themselves
    That means, if we e.g. fix imports in the TLS callbacks, are they are removed once someone dumps them, means invalid PE?

    1. Check the integrity of the image
    2. 
  */

  /*
    Limitations:
      We cannot use direct winapi calls
      We cannot use strings because they are compiled into the .rdata section
      No direct exception handling
      Cannot use arrays due to VS Debug mode variable auto initialization, it calls a memcpy from another section..
  */

  switch ( reason ) {
    case DLL_PROCESS_ATTACH: {
#if ENABLE_TLS_CALLBACKS
      FixNextCorruptedTlsCallback( dll_base );
#endif
      const auto modules = GetModules();
      const auto apis = InitializeApis( modules );

      AntiAttachDebugger( modules, apis );

      const uintptr_t vm_code_section_addr = GetVmCodeSection( dll_base );

      if ( !vm_code_section_addr ) {
        return;
      }

      auto vm_code_section_data =
          reinterpret_cast<VmCodeSectionData*>( vm_code_section_addr );

      const auto dll_base_ptr = reinterpret_cast<uint8_t*>( dll_base );

      const auto import_data_directory =
          vm_code_section_data->import_data_directory;

      if ( import_data_directory.Size > 0 ) {
        FixImports( dll_base_ptr, vm_code_section_data, import_data_directory,
                    apis );

        // Remove it info in case someone dumps the PE
        vm_code_section_data->import_data_directory.Size = 0;
        vm_code_section_data->import_data_directory.VirtualAddress = 0;
      }
    } break;
    default:
      break;
  }
  // TODO: Fix the imports in this tls callback, OR, add another dynamic TLS callback and fix the imports in that.
  // Meaning we have to let the protector ruin the imports

  // Read here to ruin the imports: https://github.com/namreeb/dumpwow/blob/master/dll/dumper.cpp

  // TODO: Consider removing the calling tls callback from the callback list when it has JUST entered the call
  // The FIRST thing we do in the TLS callback, is remove itself from the TLS callback list

  // 1. Decrypt all strings
  // 2. Fix all imports
  // 3. Remap

  // Integrity check ONLY sections that does NOT have the writeable flags

  // Flow:
  // 1. Decrypt the sections, extra layer to waste time
  // 2. Remap
  // 3. Check integrity that was written in a data section by the protector
  // 4. Try to modify the remapped memory to ensure that it was properly remapped and no disgusting things occur.
  //    Ensure that when we try to modify it, do not use an API call that can be hooked
}

__declspec( dllexport ) void NTAPI
    SecondTlsCallback( PVOID dll_base, DWORD reason, PVOID reserved ) {
  // TODO: Add a dynamic TLS callback here, ensure that when do so, we never directly
  // reference the new TLS callback by address to ensure someone cannot
  // simply find it by decompiling the code in IDA

  auto nt_headers = GetNtHeaders( dll_base );
}

#if DLL
/*
__declspec( dllexport ) void NTAPI __declspec( dllexport ) BOOL WINAPI
    EntryPoint( HINSTANCE instance, DWORD reason, LPVOID reserved ) {}
*/
#else
__declspec( dllexport ) int WINAPI EntryPoint( HINSTANCE instance,
                                               HINSTANCE prev_instance,
                                               PWSTR cmdline,
                                               int cmdshow ) {
  return 1;
}
#endif

void PushValueToRealStack( VmContext* vm_context, uintptr_t value ) {
  const auto current_registers_address =
      reinterpret_cast<uintptr_t>( vm_context->registers );

  auto current_register_last_value_address =
      current_registers_address + sizeof( VmRegisters ) - sizeof( uintptr_t );

  // Make a copy of the registers
  const auto registers_copy = *vm_context->registers;

  // Get the new registers address on the stack (subtracted by sizeof(ptr))
  auto new_registers = reinterpret_cast<VmRegisters*>(
      current_registers_address - sizeof( uintptr_t ) );

  // Copy the registers to the new location
  *new_registers = *vm_context->registers;

  // Modify the vm_context->registers variable to the new stack address
  vm_context->registers = new_registers;

  // Set the push value
  *reinterpret_cast<uintptr_t*>( current_register_last_value_address ) = value;

  // Modify esp appropriately in order to return to the correct esp so the
  // pushed arguments show on top of stack
  vm_context->esp -= sizeof( uintptr_t );
}

uintptr_t* GetPointerToRegister( const VmContext* vm_context,
                                 const uint32_t reg_offset ) {
  uint8_t* register_struct_bytes = ( uint8_t* )vm_context->registers;
  return ( uintptr_t* )( register_struct_bytes + reg_offset );
}

template <typename T>
T ReadValue( uint8_t** code ) {
  const T value = *reinterpret_cast<T*>( *code );

  *code += sizeof( T );

  return value;
}

void WriteSizedValue( const uint32_t size,
                      const uintptr_t* write_dest,
                      const uintptr_t value ) {
  switch ( size ) {
    case 1: {
      auto reg_dest_value_with_disp = ( uint8_t* )( write_dest );
      *reg_dest_value_with_disp = ( uint8_t )value;
    } break;
    case 2: {
      auto reg_dest_value_with_disp = ( uint16_t* )( write_dest );
      *reg_dest_value_with_disp = ( uint16_t )value;
    } break;
    case 4: {
      auto reg_dest_value_with_disp = ( uint32_t* )( write_dest );
      *reg_dest_value_with_disp = ( uint32_t )value;
    } break;
    case 8: {
      auto reg_dest_value_with_disp = ( uint64_t* )( write_dest );
      *reg_dest_value_with_disp = ( uint64_t )value;
    } break;
    default:
      break;
  }
}

void WriteSizedValueToRegister( const VmContext* vm_context,
                                const VmRegister& vm_reg,
                                const uintptr_t value ) {
  const auto write_dest_ptr =
      GetPointerToRegister( vm_context, vm_reg.register_offset );

  if ( vm_reg.register_size == 4 ) {
    // https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/x64-architecture
    // Operations that output to a 32-bit subregister are automatically zero-extended
    // to the entire 64-bit register. Operations that output to 8-bit or 16-bit
    // subregisters are not zero-extended (this is compatible x86 behavior).

    // If my understand of the statement above is correct, then the follwing line should
    // zero-extend the whole 64 register on x64 and the whole x86 register on x86, but on x86 it does not matter
    *( uintptr_t* )( write_dest_ptr ) = 0;
  }

  WriteSizedValue( vm_reg.register_size, write_dest_ptr, value );
}

/*
  Adding (__declspec(dllexport)) in order to export the function ensures that
  the parameters won't be incorrectly optimized due to the way I am calling
  this function inside of the code.

  Use __stdcall calling convention because I need the functionality to be able
  to push the parameters to the function. 
  
  When using __fastcall it uses the
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
  kTotalParametersBeforeEspPush = 0;
#endif

  // A value that describes the amount of stack we allocate before we call this interpreter in the loader shellcode
  // It is based on the sub esp, 0x100
  //                    add esp, 0x100
  // This is not required for x86, but I am still doing it for consistency on both x86 and x64
  const auto interpreter_call_stack_allocation_space = 0x100;

  // Read whole struct from stack in one read
  VmContext* vm_context =
      ( VmContext* )( allocated_stack_addr + kTotalParametersBeforeEspPush +
                      interpreter_call_stack_allocation_space );

  // Initialize the pointer to the pushed registers
  vm_context->registers =
      ( VmRegisters* )( ( uintptr_t )( vm_context ) +
                        VM_INTERPRETER_STACK_ALLOCATION_SIZE_BYTES +
                        sizeof( vm_context->esp ) -
                        offsetof( VmContext, registers ) +
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

  switch ( static_cast<VmOpcodes>( vm_opcode ) ) {
    case VmOpcodes::MOV_REGISTER_MEMORY_REG_OFFSET: {
      // Read the next 4 bytes as uint32_t
      const auto vm_reg_dest = ReadValue<VmRegister>( &code );
      const auto vm_reg_src = ReadValue<VmRegister>( &code );

      auto reg_src_disp = ReadValue<uintptr_t>( &code );

      if ( relocated_disp ) {
        reg_src_disp =
            reg_src_disp - DEFAULT_PE_BASE_ADDRESS + image_base_address;
      }

      const auto reg_src_value =
          *GetPointerToRegister( vm_context, vm_reg_src.register_offset );

      const auto reg_src_value_with_disp = reg_src_value + reg_src_disp;

      const auto mov_value = *( uintptr_t* )reg_src_value_with_disp;

      WriteSizedValueToRegister( vm_context, vm_reg_dest, mov_value );
    } break;

    case VmOpcodes::MOV_REGISTER_MEMORY_IMMEDIATE: {
      const auto vm_reg_dest = ReadValue<VmRegister>( &code );
      auto value_src_addr = ReadValue<uintptr_t>( &code );

      if ( relocated_disp ) {
        value_src_addr =
            value_src_addr - DEFAULT_PE_BASE_ADDRESS + image_base_address;
      }

      const auto value = *( uintptr_t* )( value_src_addr );

      WriteSizedValueToRegister( vm_context, vm_reg_dest, value );
    } break;

    case VmOpcodes::MOV_REGISTER_REGISTER: {
      const auto vm_reg_dest = ReadValue<VmRegister>( &code );
      const auto vm_reg_src = ReadValue<VmRegister>( &code );

      const auto value =
          *GetPointerToRegister( vm_context, vm_reg_src.register_offset );

      WriteSizedValueToRegister( vm_context, vm_reg_dest, value );
    } break;

    case VmOpcodes::MOV_REGISTER_IMMEDIATE: {
      // Read the next 4 bytes as uint32_t
      const auto vm_reg_dest = ReadValue<VmRegister>( &code );

      auto value = ReadValue<uintptr_t>( &code );

      if ( relocated_imm ) {
        value = value - DEFAULT_PE_BASE_ADDRESS + image_base_address;
      }

      WriteSizedValueToRegister( vm_context, vm_reg_dest, value );
    } break;

    case VmOpcodes::MOV_MEMORY_REG_OFFSET_REG: {
      const auto vm_reg_dest = ReadValue<VmRegister>( &code );
      const auto vm_reg_src = ReadValue<VmRegister>( &code );

      auto reg_dest_disp = ReadValue<uintptr_t>( &code );

      if ( relocated_disp ) {
        reg_dest_disp =
            reg_dest_disp - DEFAULT_PE_BASE_ADDRESS + image_base_address;
      }

      // NOTE: Might be issues within this handling due to the different sizes of the read/writes of registers

      // Read the src register value
      const auto reg_src_value =
          *GetPointerToRegister( vm_context, vm_reg_src.register_offset );

      const auto reg_dest_value =
          *GetPointerToRegister( vm_context, vm_reg_dest.register_offset );

      auto reg_dest_value_with_disp =
          ( uintptr_t* )( reg_dest_value + reg_dest_disp );

      WriteSizedValue( vm_reg_dest.register_size, reg_dest_value_with_disp,
                       reg_src_value );
    } break;

    case VmOpcodes::MOV_MEMORY_REG_OFFSET_IMM: {
      // Example 1: mov dword ptr [eax + 0x7d765c], 2
      // Example 2: mov dword ptr [ebp - 0x20], 0x7d7268

      // mov [reg + 0x0], imm

      const auto vm_reg_dest = ReadValue<VmRegister>( &code );

      auto source_value = ReadValue<uintptr_t>( &code );
      auto reg_dest_disp = ReadValue<uintptr_t>( &code );

      if ( relocated_disp ) {
        reg_dest_disp =
            reg_dest_disp - DEFAULT_PE_BASE_ADDRESS + image_base_address;
      } else if ( relocated_imm ) {
        source_value =
            source_value - DEFAULT_PE_BASE_ADDRESS + image_base_address;
      }

      // NOTE: Might be issues within this handling due to the different sizes of the read/writes of registers

      const auto reg_dest_value =
          *GetPointerToRegister( vm_context, vm_reg_dest.register_offset );

      const auto dest_ptr = ( uintptr_t* )( reg_dest_value + reg_dest_disp );

      WriteSizedValue( vm_reg_dest.register_size, dest_ptr, source_value );
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

    case VmOpcodes::LEA_REG_MEMORY_IMMEDIATE_RIP_RELATIVE: {
      const auto vm_reg_dest = ReadValue<VmRegister>( &code );

      const auto relative_data_addr = ReadValue<uintptr_t>( &code );

      const auto absolute_addr_to_data =
          relative_data_addr + image_base_address;

      WriteSizedValueToRegister( vm_context, vm_reg_dest,
                                 absolute_addr_to_data );
    } break;

    case VmOpcodes::CALL_MEMORY_RIP_RELATIVE: {
      const auto destination_addr = ReadValue<uintptr_t>( &code );

      const auto absolute_addr_to_call = *reinterpret_cast<uintptr_t*>(
          destination_addr + image_base_address );

      // Push a value that the loader prolog will use
      PushValueToRealStack( vm_context, 0 );

      PushValueToRealStack( vm_context, absolute_addr_to_call );
    } break;

    case VmOpcodes::CALL_MEMORY: {
      // push the call address to the stack

      // TODO: add size as with all other instructions

      auto absolute_call_target_addr_addr = ReadValue<uintptr_t>( &code );

      if ( relocated_disp ) {
        absolute_call_target_addr_addr = absolute_call_target_addr_addr -
                                         DEFAULT_PE_BASE_ADDRESS +
                                         image_base_address;
      }

      uintptr_t absolute_call_target_addr =
          *( uintptr_t* )absolute_call_target_addr_addr;

      // Push a value that the loader prolog will use
      PushValueToRealStack( vm_context, 0 );

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

      // Push a value that the loader prolog will use
      PushValueToRealStack( vm_context, 0 );

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
      // TODO: Consider handling different sizes of push, at the moment
      // I prevent it from handling any other sizes of push

      const auto vm_reg_src = ReadValue<VmRegister>( &code );
      auto reg_src_disp = ReadValue<uintptr_t>( &code );

      if ( relocated_disp ) {
        reg_src_disp =
            reg_src_disp - DEFAULT_PE_BASE_ADDRESS + image_base_address;
      }

      // read the register value
      const auto reg_src_value =
          *GetPointerToRegister( vm_context, vm_reg_src.register_offset );

      // read the stack value at the register + disp offset
      const auto value_to_push =
          *( uintptr_t* )( reg_src_value + reg_src_disp );

      PushValueToRealStack( vm_context, value_to_push );
    } break;

    case VmOpcodes::JMP_IMM: {
      // NOTE: I do not think this can be relocated

      auto absolute_jmp_target_addr = ReadValue<uintptr_t>( &code );

      // add the image base
      absolute_jmp_target_addr += image_base_address;

      PushValueToRealStack( vm_context, absolute_jmp_target_addr );

      // when exiting the vm (before jmp back), push return address
      // then jmp to
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

BOOL WINAPI DllMain( HINSTANCE instance_handle,
                     DWORD reason,
                     LPVOID reserved ) {
  printf( "Fuck me 1" );

  VmInterpreter( ( uint8_t* )0x1, 0x2, 0x3, 0x4 );

  printf( "Fuck me 2" );

  return 1;
}