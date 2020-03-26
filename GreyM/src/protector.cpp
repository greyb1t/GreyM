#include "pch.h"
#include "protector.h"
#include "disassembler/pe_disassembly_engine.h"
#include "pe/portable_executable.h"
#include "utils/stopwatch.h"
#include "virtualizer/virtualizer.h"
#include "utils/shellcode.h"
#include "utils/file_io.h"
#include "rtti_obfuscator.h"
#include "utils/random.h"
#include "pe/peutils.h"

#include "../../Interpreter/src/main.h"

#include "../pe/peutils.h"

namespace protector {

// Returns count of relocations
uint32_t GetRelocationsWithinInstruction(
    const cs_insn& instruction,
    PortableExecutable& original_pe,
    std::array<uint32_t, 16>* relocation_rvas,
    std::vector<uintptr_t>& reloc_set_lol ) {
  uint32_t relocation_count = 0;

  auto it_found_result = reloc_set_lol.end();
  auto instruction_offset_result = 0;

  for ( int i = 0; i < instruction.size; ++i ) {
    const auto rva_to_find = instruction.address + i;
    auto it = std::lower_bound( reloc_set_lol.begin(), reloc_set_lol.end(),
                                rva_to_find );

    // if we found that exact value
    if ( it != reloc_set_lol.end() && *it == rva_to_find ) {
      ( *relocation_rvas )[ relocation_count ] = *it;
      relocation_count++;

      it_found_result = it;
      instruction_offset_result = i;
      break;
    }
  }

#if 1
  // check if we found any relocation within the instruction
  if ( it_found_result != reloc_set_lol.end() ) {
    // If we found it, we don't need to binary search the whole vector again
    // Continue iterating the found iterator above
    for ( auto it = it_found_result + 1; it != reloc_set_lol.end(); ++it ) {
      const auto reloc_rva = *it;

      const bool is_reloc_within_instruction =
          ( reloc_rva >= instruction.address ) &&
          ( reloc_rva < ( instruction.address + instruction.size ) );

      // if the reloc rva was not within the current instructino, then we are
      // done because the relocations following this one are definitely not
      // within this instruction
      if ( !is_reloc_within_instruction )
        break;

      ( *relocation_rvas )[ relocation_count ] = *it;
      relocation_count++;
    }
  }
#endif

  /*
  // OLD WAY, BAD PERFORMANCE, NOW USING BINARY SEARCH INSTEAD
  original_pe.EachRelocation( [&]( const uintptr_t rva, Relocation* reloc ) {
    const bool is_reloc_within_instruction =
        ( rva >= instruction.address ) &&
        ( rva < ( instruction.address + instruction.size ) );

    // From MSDN PE documentation:
    // reloc.type = IMAGE_REL_BASED_ABSOLUTE: The base relocation is
    // skipped. This type can be used to pad a block. Therefore we skip
    // relocating if the relocation is of that type to avoid issues
    if ( is_reloc_within_instruction &&
         reloc->type != IMAGE_REL_BASED_ABSOLUTE ) {
      ( *relocation_rvas )[ relocation_count ] = rva;

      ++relocation_count;
    }
  } );
  */

  return relocation_count;
}  // namespace protector

PortableExecutable ReadInterpreterPe() {
  const std::wstring interpreter_filename = TEXT( "Interpreter.dll" );

  const auto interpreter_file_data =
      fileio::ReadBinaryFile( interpreter_filename );

  if ( interpreter_file_data.empty() )
    throw std::runtime_error( "Unable to read the content of Interpreter.dll" );

  return pe::Open( interpreter_file_data );
}

void AddLoaderCodeToSection( const PortableExecutable& interpreter_pe,
                             Section* section ) {
  auto section_headers = interpreter_pe.GetSectionHeaders();

  const auto interpreter_vm_section =
      section_headers.GetSectionByName( VM_FUNCTIONS_SECTION_NAME );

  auto temp_section_copy = interpreter_pe.CopySection( interpreter_vm_section );

  const auto nt_header = interpreter_pe.GetNtHeaders();

  section->AppendCode( *temp_section_copy.GetData(),
                       nt_header->OptionalHeader.SectionAlignment,
                       nt_header->OptionalHeader.FileAlignment );
}

// returns -1 if not found, offset otherwise
uint32_t GetExportedFunctionOffsetRelativeToSection(
    const PortableExecutable& pe,
    const std::string& function_name ) {
  uint32_t interpreter_function_rva = 0;
  const auto exports = pe.GetExports();

  for ( const auto& exprt : exports ) {
    if ( exprt.function_name == function_name ) {
      interpreter_function_rva = exprt.function_addr_rva;
      break;
    }
  }

  if ( interpreter_function_rva == 0 )
    return -1;

  const auto section_headers = pe.GetSectionHeaders();

  const auto section_containing_interpreter =
      section_headers.GetSectionByRva( interpreter_function_rva );

  // TODO: consider using the section offset function
  const auto interpreter_offset_relative_to_section =
      interpreter_function_rva - section_containing_interpreter->VirtualAddress;

  return interpreter_offset_relative_to_section;
}

void AddTlsCallbacks( const PortableExecutable& original_pe,
                      const PortableExecutable& interpreter_pe,
                      const uint32_t vm_section_virtual_address,
                      Section& vm_section,
                      const IMAGE_NT_HEADERS& original_pe_nt_headers,
                      std::vector<uint8_t>& header_data ) {
  if ( original_pe.GetNtHeaders()
           ->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_TLS ]
           .Size != 0 ) {
    throw std::runtime_error(
        "The target executable already has a TLS directory, not supported at "
        "the moment." );
  }

  const auto interpreter_tls_callback_offset =
      GetExportedFunctionOffsetRelativeToSection( interpreter_pe,
                                                  "TlsCallback" );

  // Add the address of callbacks array
  uintptr_t tls_callback_list[] = { DEFAULT_PE_BASE_ADDRESS +
                                        vm_section_virtual_address +
                                        interpreter_tls_callback_offset,
                                    0, 0, 0 };

  uint8_t* tls_callback_list_ptr =
      reinterpret_cast<uint8_t*>( tls_callback_list );

  std::vector<uint8_t> tls_callbacks_list_data;
  tls_callbacks_list_data.assign(
      &tls_callback_list_ptr[ 0 ],
      &tls_callback_list_ptr[ sizeof( tls_callback_list ) ] );

  // Add the TLS callback addresses section
  const auto callback_list_offset = vm_section.AppendCode(
      tls_callbacks_list_data,
      original_pe_nt_headers.OptionalHeader.SectionAlignment,
      original_pe_nt_headers.OptionalHeader.FileAlignment );

  IMAGE_TLS_DIRECTORY tls_directory;
  // The loader will copy the data between StartAddressOfRawData and
  // EndAddressOfRawData, make them zero to not copy anything
  tls_directory.StartAddressOfRawData = 0;
  tls_directory.EndAddressOfRawData = 0;

  // AddressOfIndex can simply just point to some data that is 0
  tls_directory.AddressOfIndex = DEFAULT_PE_BASE_ADDRESS +
                                 vm_section_virtual_address +
                                 callback_list_offset + 16;

  tls_directory.AddressOfCallBacks = DEFAULT_PE_BASE_ADDRESS +
                                     vm_section_virtual_address +
                                     callback_list_offset;

  tls_directory.SizeOfZeroFill = 0;
  tls_directory.Characteristics = IMAGE_SCN_ALIGN_4BYTES;
  // https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#the-tls-section
  // WHAT, ADDRESS IS NOT RVA, BUT A ADDRESS WITH BASE RELOCATION??
  // MAYBE NOT NEEDED BECAUSE WE REMOVED DYNAMIC BASE ADDRESS

  // TODO: if adding support for dynamic base address, we need to relocate the
  // values in IMAGE_TLS_DIRECTORY struct

  uint8_t* tls_directory_ptr = reinterpret_cast<uint8_t*>( &tls_directory );

  std::vector<uint8_t> tls_directory_data;
  tls_directory_data.assign( &tls_directory_ptr[ 0 ],
                             &tls_directory_ptr[ sizeof( tls_directory ) ] );

  /*
    prevent dumping
    modify the protection of the tls data StartAddressOfRawData &
    EndAddressOfRawData that the loader copies corrupt it somehow, or change
    protection to prevent dumping
    do it in the tls callback

    -

    Also: modify AddressOfIndex to 0 to make un-runnable
  */

  // Add the TLS data to last section before calculating the vm section
  // virtual address
  const auto tls_directory_data_offset = vm_section.AppendCode(
      tls_directory_data,
      original_pe_nt_headers.OptionalHeader.SectionAlignment,
      original_pe_nt_headers.OptionalHeader.FileAlignment );

  // Modify the header to add the TLS directry location in the PE
  auto header_data_nt_headers = peutils::GetNtHeaders( header_data.data() );

  auto& tls_data_directory = header_data_nt_headers->OptionalHeader
                                 .DataDirectory[ IMAGE_DIRECTORY_ENTRY_TLS ];
  tls_data_directory.Size = sizeof( IMAGE_TLS_DIRECTORY );
  tls_data_directory.VirtualAddress =
      vm_section_virtual_address + tls_directory_data_offset;
}

void InitializeVmSection( PortableExecutable* interpreter_pe,
                          const IMAGE_NT_HEADERS* original_pe_nt_headers,
                          const SectionHeaders& original_pe_sections,
                          Section* vm_section ) {
  auto interpreter_sections = interpreter_pe->GetSectionHeaders();

  const auto vm_fun_section =
      interpreter_sections.GetSectionByName( VM_FUNCTIONS_SECTION_NAME );

  // Calculates the correct next section virtual address provided the current
  // last section is unmodified and will no longer be changed
  // in this case it is .reloc and we never change that, therefore we cannot
  // predict the vm_section VA
  /*
  const auto calculate_next_section_virtual_address =
      []( const SectionHeaders& section_headers,
          const IMAGE_NT_HEADERS* nt_headers ) {
        const auto& last_section_header = section_headers.headers.back();

        uint32_t virtual_address =
            peutils::Align( last_section_header->VirtualAddress +
                                last_section_header->Misc.VirtualSize,
                            nt_headers->OptionalHeader.SectionAlignment );

        return virtual_address;
      };
  */

  /*
  const auto vm_section_virtual_address =
      calculate_next_section_virtual_address( original_pe_sections,
                                              original_pe_nt_headers );
  */

  // temporary solution
  const auto vm_section_virtual_address = 0;

  const auto section_delta =
      vm_section_virtual_address - vm_fun_section->VirtualAddress;

  const auto base_address_delta =
      original_pe_nt_headers->OptionalHeader.ImageBase -
      interpreter_pe->GetNtHeaders()->OptionalHeader.ImageBase;

  // before we add the the loader code to the section
  // relocate the whole interpreter image
  // this fixes e.g. the jump/switch table in the interpreter when you directly
  // copy it to another section
  // NOTE: This only works if the new PE is disabled ASLR, the base address
  // always set to 0x400000.
  // If we want to support the new PE having dynamic base address, we need to
  // copy the relocations
  // NOTE: We still need this to relocate it to the default PE base address,
  // then use relocations to relocate it further
  interpreter_pe->Relocate( base_address_delta + section_delta );

  // NOTE: When having a jump table in the interpreter, it has a pointer to the
  // jump table that contains addresses to locations. Those locations are being
  // relocated, we need to copy the relocations of the interpreter to the new PE

  // initialize the vm section with the required functions
  AddLoaderCodeToSection( *interpreter_pe, vm_section );
}

std::vector<uint8_t> CreateRelocationBlock(
    const uint32_t virtual_address,
    const std::vector<Relocation>& relocations ) {
  std::vector<uint8_t> relocation_block_bytes;

  // Required to be size of a WORD due to the PE format
  assert( sizeof( Relocation ) == sizeof( WORD ) );

  IMAGE_BASE_RELOCATION reloc_block;
  reloc_block.VirtualAddress = virtual_address;
  reloc_block.SizeOfBlock = sizeof( IMAGE_BASE_RELOCATION ) +
                            relocations.size() * sizeof( Relocation );

  uint8_t* buf = reinterpret_cast<uint8_t*>( &reloc_block );

  relocation_block_bytes.insert( relocation_block_bytes.begin(), buf,
                                 buf + sizeof( reloc_block ) );

  for ( const auto& reloc : relocations ) {
    const uint8_t* buf2 = reinterpret_cast<const uint8_t*>( &reloc );

    relocation_block_bytes.insert( relocation_block_bytes.end(), buf2,
                                   buf2 + sizeof( reloc ) );
  }

  return relocation_block_bytes;
}

uint32_t GetRelocationBlockCount( PortableExecutable& pe ) {
  uint32_t last_default_reloc_block_index = 0;

  IMAGE_BASE_RELOCATION* prev_reloc_block = nullptr;

  pe.EachRelocation( [&]( IMAGE_BASE_RELOCATION* reloc_block, uintptr_t rva,
                          Relocation* reloc ) {
    if ( prev_reloc_block != nullptr ) {
      if ( reloc_block->VirtualAddress != prev_reloc_block->VirtualAddress ) {
        ++last_default_reloc_block_index;
        prev_reloc_block = reloc_block;
      }
    } else {
      prev_reloc_block = reloc_block;
      ++last_default_reloc_block_index;
    }
  } );

  return last_default_reloc_block_index;
}

uintptr_t AlignUpSimple( const uintptr_t value, const uintptr_t alignment ) {
  return value + ( alignment - ( value % alignment ) );
}

uint32_t DetermineFirstRelocationBlockVirtualAddress(
    const std::vector<uintptr_t>& vm_section_offsets_to_relocate,
    const int highest_reloc_offset ) {
  assert( vm_section_offsets_to_relocate.size() > 0 );
  return peutils::AlignDown( vm_section_offsets_to_relocate[ 0 ],
                             highest_reloc_offset );
}

void TrimRelocSectionPadding( const IMAGE_NT_HEADERS* nt_headers,
                              Section& reloc_section ) {
  auto reloc_section_data = reloc_section.GetData();

  const auto& reloc_directory =
      nt_headers->OptionalHeader
          .DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];

  // Trim the end of reloc section and remove the padding
  reloc_section_data->erase( reloc_section_data->begin() + reloc_directory.Size,
                             reloc_section_data->end() );

  // TODO:
  // Just like .AppendCode(), consider adding a RemoveCode() and adjusts the
  // section header as well in case we do not have enough relocations for the
  // amount of bytes trimmed
}

void AppendRelocationBlock( const uintptr_t reloc_block_virtual_address,
                            std::vector<Relocation>& relocations,
                            IMAGE_NT_HEADERS* nt_headers,
                            Section& reloc_section ) {
  // if the count of relocations are odd, we need to add one no-op with type
  // and offset 0 to align to 32 bit boundary
  if ( relocations.size() % 2 != 0 ) {
    relocations.push_back( Relocation{ 0 } );
  }

  std::vector<uint8_t> reloc_block_bytes =
      CreateRelocationBlock( reloc_block_virtual_address, relocations );

  reloc_section.AppendCode( reloc_block_bytes,
                            nt_headers->OptionalHeader.SectionAlignment,
                            nt_headers->OptionalHeader.FileAlignment );

  auto& reloc_directory = nt_headers->OptionalHeader
                              .DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];

  reloc_directory.Size += reloc_block_bytes.size();
}

void AddLoaderShellcodeRelocations(
    const std::vector<uintptr_t>& vm_section_offsets_to_relocate,
    PortableExecutable& pe,
    Section& reloc_section ) {
  constexpr auto kHighestNumberFrom12Bits = 1 << 12;

  auto reloc_block_virtual_address =
      DetermineFirstRelocationBlockVirtualAddress(
          vm_section_offsets_to_relocate, kHighestNumberFrom12Bits );

  auto nt_headers = pe.GetNtHeaders();

  TrimRelocSectionPadding( nt_headers, reloc_section );

  std::vector<Relocation> new_relocations;

  for ( const uint32_t vm_section_offset_to_relocate :
        vm_section_offsets_to_relocate ) {
    const auto delta_offset_from_reloc_block_va =
        vm_section_offset_to_relocate - reloc_block_virtual_address;

    Relocation relocation;
#ifdef _WIN64
    relocation.type = IMAGE_REL_BASED_DIR64;
#else
    relocation.type = IMAGE_REL_BASED_HIGHLOW;
#endif
    relocation.offset = delta_offset_from_reloc_block_va;

    // has the delta exceeded the highest number for a reloc offset?
    if ( delta_offset_from_reloc_block_va >= kHighestNumberFrom12Bits ) {
      AppendRelocationBlock( reloc_block_virtual_address, new_relocations,
                             nt_headers, reloc_section );

      new_relocations.clear();

      reloc_block_virtual_address += 0x1000;

      // refresh the offset for the new block
      relocation.offset =
          vm_section_offset_to_relocate - reloc_block_virtual_address;
    }

    new_relocations.push_back( relocation );
  }

  // if there are still relocations left to add
  if ( new_relocations.size() > 0 ) {
    AppendRelocationBlock( reloc_block_virtual_address, new_relocations,
                           nt_headers, reloc_section );
  }
}

void FixupLoaderRelocationBlocks( const uint32_t original_reloc_block_count,
                                  PortableExecutable& new_pe ) {
  const auto new_pe_vm_section_rva =
      new_pe.GetSectionHeaders()
          .GetSectionByName( VM_LOADER_SECTION_NAME )
          ->VirtualAddress;

  uint32_t last_default_reloc_block_index2 = 0;

  IMAGE_BASE_RELOCATION* prev_reloc_block2 = nullptr;

  new_pe.EachRelocation( [&]( IMAGE_BASE_RELOCATION* reloc_block,
                              const uintptr_t rva, Relocation* reloc ) {
    // Fixup the VirtualAddress of the new reloction blocks

    if ( prev_reloc_block2 != nullptr ) {
      if ( reloc_block->VirtualAddress != prev_reloc_block2->VirtualAddress ) {
        ++last_default_reloc_block_index2;
        prev_reloc_block2 = reloc_block;

        if ( last_default_reloc_block_index2 > original_reloc_block_count ) {
          reloc_block->VirtualAddress += new_pe_vm_section_rva;
        }
      }
    } else {
      prev_reloc_block2 = reloc_block;
      ++last_default_reloc_block_index2;

      if ( last_default_reloc_block_index2 > original_reloc_block_count ) {
        reloc_block->VirtualAddress += new_pe_vm_section_rva;
      }
    }
  } );
}

PortableExecutable Protect( const PortableExecutable& original_pe ) {
  PeDisassemblyEngine pe_disassembler( original_pe );

  // Copy the original pe because will we modify it, keep the original pe clean
  auto original_pe_copy = original_pe;

  // todo make the section sizes aligned with the remap
  // be aware, that remap will not work if protected with vmprotect

  PortableExecutable interpreter_pe = ReadInterpreterPe();

  if ( !interpreter_pe.IsValidPortableExecutable() )
    throw std::runtime_error( "Interpreter is not valid portable executable" );

  const auto interpreter_function_offset =
      GetExportedFunctionOffsetRelativeToSection( interpreter_pe,
                                                  "VmInterpreter" );

  const auto original_pe_sections = original_pe_copy.GetSectionHeaders();
  const auto original_pe_nt_headers = original_pe_copy.GetNtHeaders();

  // TODO: Remove IMAGE_SCN_MEM_EXECUTE to prevent IDA from seeing the section,
  // then dynamically add the executable flag back or VirtualProtect()
  // executable
  auto vm_section = section::CreateEmptySection(
      VM_LOADER_SECTION_NAME,
      IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE );

  InitializeVmSection( &interpreter_pe, original_pe_nt_headers,
                       original_pe_sections, &vm_section );

#if 0
  // TODO: Since we added support for dynamic base, we need to relocate it :O
  AddTlsCallbacks( original_pe, interpreter_pe,
                   vm_section_virtual_address, vm_section,
                   original_pe_nt_headers, header_data );
#endif

  std::string output_log = "";

  const auto text_section_header2 =
      original_pe_sections.GetSectionByName( ".text" );

  auto original_pe_text_section =
      original_pe_copy.CopySection( text_section_header2 );

  Stopwatch stopwatch;
  stopwatch.Start();

  auto text_section = original_pe_sections.GetSectionByName( ".text" );

  std::vector<uint32_t> offset_fixup_vm_section_to_text_section;
  std::vector<uint32_t> offset_fixup_vm_section_to_virtualized_code_section;
  std::vector<uint32_t> offset_fixup_text_section_to_vm_section;
  std::vector<uintptr_t> relocation_rvas_to_remove;

  std::vector<uintptr_t>
      vm_section_loader_shellcode_image_base_fixup_for_relocations;

  uint32_t total_virtualized_instructions = 0;
  uint32_t total_disassembled_instructions = 0;

  auto virtualized_code_section = section::CreateEmptySection(
      VM_CODE_SECTION_NAME, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE );

  std::vector<uintptr_t> original_pe_relocation_rvas;

  // Copy the relocations from the original pe into a unordered_set for fast
  // lookup later when determining whether
  original_pe_copy.EachRelocation( [&]( IMAGE_BASE_RELOCATION* reloc_block,
                                        const uintptr_t rva,
                                        Relocation* reloc ) {
    // From MSDN PE documentation:
    // reloc.type = IMAGE_REL_BASED_ABSOLUTE: The base relocation is
    // skipped. This type can be used to pad a block. Therefore we skip
    // relocating if the relocation is of that type to avoid issues
    if ( reloc->type != IMAGE_REL_BASED_ABSOLUTE ) {
      original_pe_relocation_rvas.push_back( rva );
    }
  } );

  std::sort( original_pe_relocation_rvas.begin(),
             original_pe_relocation_rvas.end() );

  const auto EachInstructionCallback = [&]( const cs_insn& instruction,
                                            const uint8_t* code ) {
    //  BELOW CODE CAUSES BAD PERFORMANCE ISSUES, sprintf_s call is doing
    //  every instruction
    /*
      char buf[ MAX_PATH ]{ 0 }; sprintf_s( buf, "0x%08I64x - %s
      %s\n", instruction.address, instruction.mnemonic, instruction.op_str );

      output_log += buf;
    */

    //original_pe_copy.GetPeData()

    {
      const auto instruction_text_section_offset = section::RvaToSectionOffset(
          text_section, static_cast<uint32_t>( instruction.address ) );

      // const auto text_section_data =
      //     original_pe_copy.GetPeImagePtr() +
      //     text_section->PointerToRawData;

      const auto text_section_data =
          original_pe_copy.GetPeImagePtr() + text_section->PointerToRawData;

      const auto first = text_section_data + instruction_text_section_offset;

      int test = 0;
    }

    const auto vm_opcode = virtualizer::GetVmOpcode( instruction );

    // if is virtualizable
    if ( virtualizer::IsVirtualizeable( instruction, vm_opcode ) ) {
      if ( instruction.detail->x86.eflags != 0 ) {
        throw std::runtime_error(
            "An instruction changing eflags was found, not supported" );
      }

      // check if the instruction is being relocated by default
      std::array<uint32_t, 16> relocations;
      const auto relocation_count = GetRelocationsWithinInstruction(
          instruction, original_pe_copy, &relocations,
          original_pe_relocation_rvas );

      // Must be less than 16 because that it the limit I have set myself
      assert( relocation_count < 16 );

      const uint32_t vm_opcode_encyption_key = RandomU32( 1000, 10000000 );

      // generate virtualized shellcode
      const auto virtualized_shellcode =
          virtualizer::CreateVirtualizedShellcode(
              instruction, vm_opcode, vm_opcode_encyption_key, relocation_count,
              relocations );

      const bool created_vm_code = virtualized_shellcode.GetBuffer().size() > 0;

      if ( created_vm_code ) {
        const auto virtualized_code_offset =
            virtualized_code_section.AppendCode(
                virtualized_shellcode.GetBuffer(),
                original_pe_nt_headers->OptionalHeader.SectionAlignment,
                original_pe_nt_headers->OptionalHeader.FileAlignment );

        // generate loader shellcode for the virtualized shellcode
        auto vm_code_loader_shellcode =
            virtualizer::GetLoaderShellcodeForVirtualizedCode(
                instruction, vm_opcode,
                original_pe_nt_headers->OptionalHeader.ImageBase );

        vm_code_loader_shellcode.ModifyValue( TEXT( "vm_opcode_encyption_key" ),
                                              vm_opcode_encyption_key );

        vm_code_loader_shellcode.ModifyValue<uintptr_t>(
            TEXT( "VmCodeAddr" ), virtualized_code_offset );

        const auto loader_shellcode_offset_before =
            vm_section.GetCurrentOffset();

        const auto vm_core_function_shellcode_offset =
            vm_code_loader_shellcode.GetNamedValueOffset(
                TEXT( "VmCoreFunction" ) );

        constexpr auto kCallInstructionSize = 5;

        // this value does not need to be fixed up as we did the others because
        // it it is a call to something in the SAME SECTION
        vm_code_loader_shellcode.ModifyValue<uint32_t>(
            TEXT( "VmCoreFunction" ),
            interpreter_function_offset - loader_shellcode_offset_before -
                kCallInstructionSize - vm_core_function_shellcode_offset + 1 );

        constexpr uint32_t kJmpInstructionSize = 5;

        const auto orig_addr_value_offset =
            vm_code_loader_shellcode.GetNamedValueOffset( TEXT( "OrigAddr" ) );

        const auto destination =
            static_cast<uint32_t>( instruction.address + instruction.size );

        const auto origin = static_cast<uint32_t>(
            loader_shellcode_offset_before + orig_addr_value_offset );

        vm_code_loader_shellcode.ModifyValue<uint32_t>(
            TEXT( "OrigAddr" ),
            destination - origin - kJmpInstructionSize + 1 );

        const auto loader_shellcode_offset = vm_section.AppendCode(
            vm_code_loader_shellcode.GetBuffer(),
            original_pe_nt_headers->OptionalHeader.SectionAlignment,
            original_pe_nt_headers->OptionalHeader.FileAlignment );

        // add to vector to modify the value later because the sections have no
        // VirtualAddress yet
        offset_fixup_vm_section_to_text_section.push_back(
            loader_shellcode_offset + orig_addr_value_offset );

        const auto vm_code_addr_offset =
            loader_shellcode_offset +
            vm_code_loader_shellcode.GetNamedValueOffset(
                TEXT( "VmCodeAddr" ) );

        offset_fixup_vm_section_to_virtualized_code_section.push_back(
            vm_code_addr_offset );

        const auto vm_var_section_shellcode_offset =
            vm_code_loader_shellcode.GetNamedValueOffset(
                TEXT( "VmVarSection" ) );

        // add fixup for the image base argument for interpreter call
        vm_section_loader_shellcode_image_base_fixup_for_relocations.push_back(
            loader_shellcode_offset + vm_var_section_shellcode_offset );

        // const auto vm_code_section_begin_offset =
        //     loader_shellcode_offset +
        //     vm_code_loader_shellcode.GetNamedValueOffset(
        //         TEXT( "VmVarSection" ) );
        //
        // offset_fixup_vm_section_to_virtualized_code_section.push_back(
        //     vm_code_section_begin_offset );

        const auto instruction_text_section_offset =
            section::RvaToSectionOffset(
                text_section, static_cast<uint32_t>( instruction.address ) );

        // const auto text_section_data =
        //     original_pe_copy.GetPeImagePtr() +
        //     text_section->PointerToRawData;

        const auto text_section_data = original_pe_copy.GetPeData().begin() +
                                       text_section->PointerToRawData;

        const auto first = text_section_data + instruction_text_section_offset;

        const auto last = first + instruction.size;
        const auto dest = first;

        // Fill the whole instruction with random bytes
        std::transform( first, last, dest,
                        []( uint8_t b ) { return /*RandomU8()*/ 0x90; } );

        constexpr uint8_t kJmpOpcode = 0xE9;

        *first = kJmpOpcode;

        const auto jmp_addr_offset = instruction_text_section_offset + 1;

        const uint32_t jmp_destination =
            static_cast<uint32_t>( loader_shellcode_offset -
                                   instruction.address ) -
            kJmpInstructionSize;

        // Cast the jump desination to a uint8_t array because the section data
        // is in uint8_t format
        const auto jmp_destination_as_uint8_array =
            reinterpret_cast<const uint8_t*>( &jmp_destination );

        std::copy(
            jmp_destination_as_uint8_array,
            jmp_destination_as_uint8_array +
                /*sizeof( jmp_destination_as_uint8_array )*/ sizeof( uint32_t ),
            text_section_data + jmp_addr_offset );

        // add to vector to modify the value later because the sections have no
        // VirtualAddress yet
        offset_fixup_text_section_to_vm_section.push_back( jmp_addr_offset );

        // if it was relocated, add it to a list to remove the relocation later
        // on from PE
        if ( relocation_count > 0 ) {
          for ( uint32_t i = 0; i < relocation_count; ++i ) {
            relocation_rvas_to_remove.push_back( relocations[ i ] );
          }
        }

        ++total_virtualized_instructions;
      }
    }

    ++total_disassembled_instructions;
  };

  const auto InvalidInstructionCallback =
      [&]( const uint64_t address, const SmallInstructionData ins_data ) {
        const auto text_section_offset =
            section::RvaToSectionOffset( text_section, address );

        const auto text_section_data =
            original_pe_copy.GetPeImagePtr() + text_section->PointerToRawData;

        auto original_pe_text_section_data = original_pe_text_section.GetData();

        // if the invalid instruction was virtualized, we reset it back here
        // below
        memcpy( text_section_data + text_section_offset,
                &( *original_pe_text_section_data )[ text_section_offset ],
                ins_data.instruction_size_ );

        char buf[ MAX_PATH ]{ 0 };
        sprintf_s( buf, "Resetting invalid instruction 0x%08I64x\n",
                   static_cast<uint64_t>( address ) );
        printf( "%s\n", buf );
      };

  pe_disassembler.DisassembleFromEntrypoint( EachInstructionCallback,
                                             InvalidInstructionCallback );

  stopwatch.Stop();

  auto nt_headers = original_pe_copy.GetNtHeaders();
  auto new_modified_sections = original_pe_copy.CopySections();

#if 0
  // IF WE ADD PADDING THIS LATE TO THE LAST SECTION the calculate
  // vm_section VA won't work, do it earlier

  SYSTEM_INFO si;
  GetSystemInfo( &si );

  // get last section
  auto& last_section = new_modified_sections.back();

  const auto last_section_size = last_section.GetSectionHeader().SizeOfRawData;

  std::vector<uint8_t> padding_data;

  if ( ( last_section_size % si.dwAllocationGranularity ) != 0 ) {
    const auto new_aligned_size =
        peutils::Align( last_section_size, si.dwAllocationGranularity );
    padding_data.resize( new_aligned_size - last_section_size );
  }

  for ( size_t i = 0; i < padding_data.size() - 1; ++i ) {
    padding_data[ i ] = rand() % 0xff;
  }

  last_section.AppendCode( padding_data,
                           nt_headers->OptionalHeader.SectionAlignment,
                           nt_headers->OptionalHeader.FileAlignment );
#endif

  auto& last_section = new_modified_sections.back();

  // Provided that the .reloc section is the last section, we can add
  // unlimited of relocations to it
  assert( last_section.GetName() == ".reloc" );

  // Save the block relocation count for use later to determine which are the
  // new reloc block to fixup the VirtualAddress of.
  const auto reloc_block_count = GetRelocationBlockCount( original_pe_copy );

  AddLoaderShellcodeRelocations(
      vm_section_loader_shellcode_image_base_fixup_for_relocations,
      original_pe_copy, last_section );

  // add the new sections to the new pe
  new_modified_sections.push_back( vm_section );
  new_modified_sections.push_back( virtualized_code_section );

  auto header_data = original_pe_copy.CopyHeaderData();

  auto new_pe = pe::Build( header_data, new_modified_sections );

  // After we have built the new pe, we now have virtual address of the vm
  // section, we use that to fix up the relocations to line up with that section
  FixupLoaderRelocationBlocks( reloc_block_count, new_pe );

  // AFTER we have fixed up the relocation blocks, THEN we remove the
  // relocations that are to be removed
  // If we did this before fixing the relocation blocks, then we would find
  // double of some RVA's and removing wrong relocations
#if 1
  for ( const auto reloc_rva : relocation_rvas_to_remove ) {
    // Remove the relocations that had instructions virtualized
    new_pe.EachRelocation( [&]( IMAGE_BASE_RELOCATION* reloc_block,
                                const uintptr_t rva, Relocation* reloc ) {
      // std::cout << "Reloc.offset:" << std::dec << rva << std::endl;

      // NOTE: We cannot compare the offsets because, a relocation may have
      // same offsets but different rva's due to adding the reloc block
      // virtual address. Therefore we compare with the RVA's.

      if ( reloc_rva == rva ) {
        reloc->type = IMAGE_REL_BASED_ABSOLUTE;

        // std::cout << "Remove relocation for offset: " << std::hex
        //           << reloc->offset << " rva: " << rva << std::endl;
      }
    } );
  }
#endif

  // A lazy fix to avoid the fact that some instructions that we virtualize
  // have an entry in the relocation table
  // If we disable the dynamic base address, there is no need to relocate
  // anything in the PE :D
  // new_pe.DisableASLR();

  auto new_pe_sections = new_pe.GetSectionHeaders();

  const auto new_pe_vm_section =
      new_pe_sections.GetSectionByName( VM_LOADER_SECTION_NAME );

  const auto new_pe_virtualized_code_section =
      new_pe_sections.GetSectionByName( VM_CODE_SECTION_NAME );

  for ( const uint32_t text_section_offset :
        offset_fixup_text_section_to_vm_section ) {
    const auto rva_rva =
        section::SectionOffsetToRva( text_section, text_section_offset );
    const auto file_offset = new_pe_sections.RvaToFileOffset( rva_rva );
    auto image_ptr = new_pe.GetPeImagePtr();

    uint32_t loader_shellcode_offset =
        *reinterpret_cast<uint32_t*>( image_ptr + file_offset );

    // Add the virtual address for that specific section to make it point to the
    // correct location
    *reinterpret_cast<uint32_t*>( image_ptr + file_offset ) =
        loader_shellcode_offset + new_pe_vm_section->VirtualAddress;
  }

  for ( const uint32_t vm_section_image_base_offset :
        offset_fixup_vm_section_to_virtualized_code_section ) {
    const auto rva_rva = section::SectionOffsetToRva(
        new_pe_vm_section, vm_section_image_base_offset );
    const auto file_offset = new_pe_sections.RvaToFileOffset( rva_rva );
    auto image_ptr = new_pe.GetPeImagePtr();

    uint32_t vm_code_offset =
        *reinterpret_cast<uint32_t*>( image_ptr + file_offset );

    // Add the virtual address for that specific section to make it point to the
    // correct location
    *reinterpret_cast<uint32_t*>( image_ptr + file_offset ) =
        vm_code_offset + new_pe_virtualized_code_section->VirtualAddress;
  }

  for ( const uint32_t text_section_offset :
        offset_fixup_vm_section_to_text_section ) {
    const auto rva_rva =
        section::SectionOffsetToRva( new_pe_vm_section, text_section_offset );
    const auto file_offset = new_pe_sections.RvaToFileOffset( rva_rva );
    auto image_ptr = new_pe.GetPeImagePtr();

    uint32_t loader_shellcode_offset =
        *reinterpret_cast<uint32_t*>( image_ptr + file_offset );

    // Add the virtual address for that specific section to make it point to the
    // correct location
    *reinterpret_cast<uint32_t*>( image_ptr + file_offset ) =
        loader_shellcode_offset - new_pe_vm_section->VirtualAddress;
  }

  // NOTE: This is not fully tested, may cause issues
  rtti_obfuscator::ObfuscateRTTI( &new_pe );

  const auto nullify_pe_directory = []( PortableExecutable* pe,
                                        IMAGE_NT_HEADERS* nt_headers,
                                        SectionHeaders& sections,
                                        const uint32_t directory_index ) {
    const auto rva = nt_headers->OptionalHeader.DataDirectory[ directory_index ]
                         .VirtualAddress;
    const auto size =
        nt_headers->OptionalHeader.DataDirectory[ directory_index ].Size;
    const auto directory_offset = sections.RvaToFileOffset( rva );

    auto pe_data = pe->GetPeImagePtr();

    memset( pe_data + directory_offset, 0, size );

    nt_headers->OptionalHeader.DataDirectory[ directory_index ].Size = 0;
    nt_headers->OptionalHeader.DataDirectory[ directory_index ].VirtualAddress =
        0;
  };

  auto new_nt_headers = new_pe.GetNtHeaders();

  nullify_pe_directory( &new_pe, new_nt_headers, new_pe_sections,
                        IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG );

  nullify_pe_directory( &new_pe, new_nt_headers, new_pe_sections,
                        IMAGE_DIRECTORY_ENTRY_DEBUG );

  // printf( "%s", output_log.c_str() );

  printf( "Total Disassembled Instructions: %d\n",
          total_disassembled_instructions );

  // i have just removed all use of custom_data

  printf( "Total Virtualized Instructions: %d\n",
          total_virtualized_instructions );

  printf( "Time spent: %f ms\n", stopwatch.GetElapsedMilliseconds() );

  return new_pe;
}
}  // namespace protector