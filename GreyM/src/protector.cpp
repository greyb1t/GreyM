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
#include "utils/console_log.h"
#include "utils/file_log.h"

#include "../../Interpreter/src/main.h"

#include "../pe/peutils.h"

namespace protector {

enum class FixupOperation {
  AddVmLoaderSectionVirtualAddress,
  SubtractVmLoaderSectionVirtualAddress,
  AddVirtualizedCodeSectionVirtualAddress,
};

// If the offset is relative to the specified section
// E.g. VmLoaderSection means that the offset is relative to the vm loader section
enum class FixupOffsetType {
  VmLoaderSection,
  TextSection,
  RelocSection,
  VirtualizedCodeSection,
};

struct FixupDescriptor {
  FixupOffsetType offset_type;
  // The size of the value to update, 4 or 8 bytes?
  uint8_t size;
  FixupOperation operation;
};

struct Fixup {
  uintptr_t offset;
  FixupDescriptor desc;
};

struct FixupContext {
  std::vector<uintptr_t> relocation_rvas_to_remove;

  // A list containing offset relative to vm section
  // that will be added to the relocation table in the PE
  std::vector<uintptr_t> vm_section_offsets_to_add_to_relocation_table;
  std::vector<uintptr_t>
      virtualized_code_section_offsets_to_add_to_relocation_table;

  std::vector<Fixup> fixups;
};

struct ProtectorContext {
  Section vm_loader_section;
  Section virtualized_code_section;
  Section new_text_section;

  FixupContext fixup_context;
};

std::vector<uintptr_t> GetRelocationsWithinInstruction(
    const cs_insn& instruction,
    const std::vector<uintptr_t>& relocations_to_search ) {
  std::vector<uintptr_t> reloc_rvas_result;

  auto it_found_result = relocations_to_search.cend();

  for ( int i = 0; i < instruction.size; ++i ) {
    const auto instruction_rva = instruction.address + i;
    auto it = std::lower_bound( relocations_to_search.cbegin(),
                                relocations_to_search.cend(), instruction_rva );

    // If we found that exact value
    if ( it != relocations_to_search.cend() && *it == instruction_rva ) {
      reloc_rvas_result.push_back( *it );
      it_found_result = it;

      // Break out and continue with the second loop to avoid binary searching the whole vector again
      break;
    }
  }

  if ( it_found_result != relocations_to_search.cend() ) {
    // If we found it, we don't need to binary search the whole vector again
    // continue iterating the found iterator above
    for ( auto it = it_found_result + 1; it != relocations_to_search.cend();
          ++it ) {
      const auto reloc_rva = *it;

      const bool is_reloc_within_instruction =
          ( reloc_rva >= instruction.address ) &&
          ( reloc_rva < ( instruction.address + instruction.size ) );

      // if the reloc rva was not within the current instructino, then we are
      // done because the relocations following this one are definitely not
      // within this instruction
      if ( !is_reloc_within_instruction )
        break;

      reloc_rvas_result.push_back( reloc_rva );
    }
  }

  return reloc_rvas_result;
}

PortableExecutable ReadInterpreterPe() {
  const std::wstring interpreter_filename = TEXT( "Interpreter.dll" );

  const auto interpreter_file_data =
      fileio::ReadBinaryFile( interpreter_filename );

  if ( interpreter_file_data.empty() )
    throw std::runtime_error( "Unable to read the content of Interpreter.dll" );

  return pe::Open( interpreter_file_data );
}

void AddInterpreterCodeToSection( const PortableExecutable& interpreter_pe,
                                  Section* section ) {
  auto section_headers = interpreter_pe.GetSectionHeaders();

  const auto interpreter_vm_section =
      section_headers.FromName( VM_FUNCTIONS_SECTION_NAME );

  auto temp_section_copy =
      interpreter_pe.CopySectionDeep( interpreter_vm_section );

  const auto nt_header = interpreter_pe.GetNtHeaders();

  section->AppendCode( *temp_section_copy.GetData(),
                       nt_header->OptionalHeader.SectionAlignment,
                       nt_header->OptionalHeader.FileAlignment );
}

uint32_t GetExportedFunctionOffsetRelativeToSection(
    const PortableExecutable& pe,
    const std::string& function_name ) {
  const auto exports = pe.GetExports();

  const auto export_found = std::find_if(
      exports.cbegin(), exports.cend(), [&]( const Export exprt ) {
        return exprt.function_name == function_name;
      } );

  if ( export_found == exports.end() ) {
    throw std::runtime_error( "Unable to find the" + function_name );
  }

  const auto section_headers = pe.GetSectionHeaders();

  const auto section_containing_interpreter =
      section_headers.FromRva( export_found->function_addr_rva );

  const auto interpreter_offset_relative_to_section =
      section::RvaToSectionOffset( *section_containing_interpreter,
                                   export_found->function_addr_rva );

  return interpreter_offset_relative_to_section;
}

void AddTlsCallbacks( const PortableExecutable& original_pe,
                      const PortableExecutable& interpreter_pe,
                      ProtectorContext* context ) {
  const auto original_pe_headers = original_pe.GetNtHeaders();

  if ( original_pe_headers->OptionalHeader
           .DataDirectory[ IMAGE_DIRECTORY_ENTRY_TLS ]
           .Size != 0 ) {
    // TODO: Copy the whole content of TLS to the vm section incase it already exists
    // TODO: Move the remove the original relocations, add the new ones

    throw std::runtime_error(
        "The target executable already has a TLS directory, not supported at "
        "the moment." );
  }

  const auto interpreter_tls_callback_offset =
      GetExportedFunctionOffsetRelativeToSection( interpreter_pe,
                                                  "TlsCallback" );

  // Add the address of callbacks array
  uintptr_t tls_callback_list[] = {
    DEFAULT_PE_BASE_ADDRESS + interpreter_tls_callback_offset, 0, 0, 0
  };

  uint8_t* tls_callback_list_ptr =
      reinterpret_cast<uint8_t*>( tls_callback_list );

  std::vector<uint8_t> tls_callbacks_list_data;
  tls_callbacks_list_data.assign(
      &tls_callback_list_ptr[ 0 ],
      &tls_callback_list_ptr[ sizeof( tls_callback_list ) ] );

  // Add the TLS callback addresses section
  const auto callback_list_offset =
      context->virtualized_code_section.AppendCode(
          tls_callbacks_list_data,
          original_pe_headers->OptionalHeader.SectionAlignment,
          original_pe_headers->OptionalHeader.FileAlignment );

  const auto fixup0 =
      callback_list_offset + 0 /* first offset in the tls callback list */;

  Fixup callback_addr_fixup;
  callback_addr_fixup.offset = fixup0;
  callback_addr_fixup.desc.offset_type =
      FixupOffsetType::VirtualizedCodeSection;
  callback_addr_fixup.desc.operation =
      FixupOperation::AddVmLoaderSectionVirtualAddress;
  callback_addr_fixup.desc.size = sizeof( uintptr_t );
  context->fixup_context.fixups.push_back( callback_addr_fixup );

  context->fixup_context
      .virtualized_code_section_offsets_to_add_to_relocation_table.push_back(
          fixup0 );

  IMAGE_TLS_DIRECTORY tls_directory;
  // The loader will copy the data between StartAddressOfRawData and
  // EndAddressOfRawData, make them zero to not copy anything
  // TODO: Consider using this to our advantage?
  tls_directory.StartAddressOfRawData = 0;
  tls_directory.EndAddressOfRawData = 0;

  // AddressOfIndex can simply just point to some data that is 0
  tls_directory.AddressOfIndex = DEFAULT_PE_BASE_ADDRESS +
                                 //vm_section_virtual_address +
                                 callback_list_offset + 8;

  tls_directory.AddressOfCallBacks = DEFAULT_PE_BASE_ADDRESS +
                                     //vm_section_virtual_address +
                                     callback_list_offset;

  tls_directory.SizeOfZeroFill = 0;

  // TODO: Which one is it? Probably the latter
  tls_directory.Characteristics = IMAGE_SCN_ALIGN_4BYTES;
  //tls_directory.Characteristics = IMAGE_SCN_ALIGN_8BYTES;

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
  const auto tls_directory_data_offset =
      context->virtualized_code_section.AppendCode(
          tls_directory_data,
          original_pe_headers->OptionalHeader.SectionAlignment,
          original_pe_headers->OptionalHeader.FileAlignment );

  const auto addr_of_index_offset =
      tls_directory_data_offset +
      offsetof( IMAGE_TLS_DIRECTORY, AddressOfIndex );

  Fixup addr_of_index_fixup;
  addr_of_index_fixup.offset = addr_of_index_offset;
  addr_of_index_fixup.desc.offset_type =
      FixupOffsetType::VirtualizedCodeSection;
  addr_of_index_fixup.desc.operation =
      FixupOperation::AddVirtualizedCodeSectionVirtualAddress;
  addr_of_index_fixup.desc.size = sizeof( uintptr_t );
  context->fixup_context.fixups.push_back( addr_of_index_fixup );
  context->fixup_context
      .virtualized_code_section_offsets_to_add_to_relocation_table.push_back(
          addr_of_index_offset );

  const auto addr_of_callbacks_offset =
      tls_directory_data_offset +
      offsetof( IMAGE_TLS_DIRECTORY, AddressOfCallBacks );

  Fixup addr_of_callbacks_fixup;
  addr_of_callbacks_fixup.offset = addr_of_callbacks_offset;
  addr_of_callbacks_fixup.desc.offset_type =
      FixupOffsetType::VirtualizedCodeSection;
  addr_of_callbacks_fixup.desc.operation =
      FixupOperation::AddVirtualizedCodeSectionVirtualAddress;
  addr_of_callbacks_fixup.desc.size = sizeof( uintptr_t );
  context->fixup_context.fixups.push_back( addr_of_callbacks_fixup );
  context->fixup_context
      .virtualized_code_section_offsets_to_add_to_relocation_table.push_back(
          addr_of_callbacks_offset );

  auto& tls_data_directory = original_pe_headers->OptionalHeader
                                 .DataDirectory[ IMAGE_DIRECTORY_ENTRY_TLS ];
  tls_data_directory.Size = sizeof( IMAGE_TLS_DIRECTORY );
  tls_data_directory.VirtualAddress = tls_directory_data_offset;
}

void RelocateInterpreterPe( PortableExecutable* interpreter_pe,
                            const uintptr_t new_image_base ) {
  const auto interpreter_sections = interpreter_pe->GetSectionHeaders();

  const auto vm_fun_section =
      interpreter_sections.FromName( VM_FUNCTIONS_SECTION_NAME );

  // Why is this 0?
  // Because we do not have the section RVA at the moment, instead we relocate it
  // once again when the whole PE is finished because we then have the section rva
  const auto vm_section_virtual_address = 0;

  // In this case, we remove the section rva completely.
  // 0 - value = -value
  const auto section_delta =
      vm_section_virtual_address - vm_fun_section->VirtualAddress;

  // The interpreter PE is a DLL, dll's have different default image bases compared to EXE's.
  const auto base_address_delta =
      new_image_base - interpreter_pe->GetNtHeaders()->OptionalHeader.ImageBase;

  // We relocate the whole interpreter in order to partly fix the jump/switch tables
  // There is still more to relocate, because we do not yet know the section rva.
  interpreter_pe->Relocate( base_address_delta + section_delta );
}

std::vector<uint8_t> CreateRelocationBlockBuffer(
    const uint32_t virtual_address,
    const std::vector<Relocation>& relocations ) {
  std::vector<uint8_t> relocation_block_bytes;

  // Required to be size of a WORD due to the PE format
  assert( sizeof( Relocation ) == sizeof( WORD ) );

  IMAGE_BASE_RELOCATION reloc_block;
  {
    reloc_block.VirtualAddress = virtual_address;
    reloc_block.SizeOfBlock = sizeof( IMAGE_BASE_RELOCATION ) +
                              relocations.size() * sizeof( Relocation );
  }

  const uint8_t* reloc_block_buf = reinterpret_cast<uint8_t*>( &reloc_block );

  relocation_block_bytes.insert( relocation_block_bytes.begin(),
                                 reloc_block_buf,
                                 reloc_block_buf + sizeof( reloc_block ) );

  for ( const auto& reloc : relocations ) {
    const uint8_t* reloc_buf = reinterpret_cast<const uint8_t*>( &reloc );

    relocation_block_bytes.insert( relocation_block_bytes.end(), reloc_buf,
                                   reloc_buf + sizeof( reloc ) );
  }

  return relocation_block_bytes;
}

uint32_t DetermineFirstRelocationBlockVirtualAddress(
    const std::vector<uintptr_t>& vm_section_offsets_to_add_to_relocation_table,
    const int highest_reloc_offset ) {
  assert( vm_section_offsets_to_add_to_relocation_table.size() > 0 );
  return peutils::AlignDown( vm_section_offsets_to_add_to_relocation_table[ 0 ],
                             highest_reloc_offset );
}

void TrimRelocSectionPadding( const IMAGE_NT_HEADERS* nt_headers,
                              Section* reloc_section ) {
  auto reloc_section_data = reloc_section->GetData();

  const auto& reloc_directory =
      nt_headers->OptionalHeader
          .DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];

  // TODO: Consider making this a section method

  // Trim the end of reloc section and remove the padding
  reloc_section_data->erase( reloc_section_data->begin() + reloc_directory.Size,
                             reloc_section_data->end() );
}

uintptr_t AppendRelocationBlock( const uintptr_t reloc_block_virtual_address,
                                 std::vector<Relocation>& relocations,
                                 IMAGE_NT_HEADERS* nt_headers,
                                 Section* reloc_section ) {
  // if the count of relocations are odd, we need to add one no-op with type
  // and type 0, offset 0 to align to 32 bit boundary
  if ( relocations.size() % 2 != 0 ) {
    relocations.push_back( Relocation{ 0 } );
  }

  std::vector<uint8_t> reloc_block_bytes =
      CreateRelocationBlockBuffer( reloc_block_virtual_address, relocations );

  const auto dest_offset = reloc_section->AppendCode(
      reloc_block_bytes, nt_headers->OptionalHeader.SectionAlignment,
      nt_headers->OptionalHeader.FileAlignment );

  auto reloc_directory = &nt_headers->OptionalHeader
                              .DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];

  reloc_directory->Size += reloc_block_bytes.size();

  return dest_offset;
}

// Adds relocations upon the relocation table that relocates
// the image base in the loader shellcode, also add the offsets
// of the relocation blocks to fixup the virtual address
void AddRelocations(
    const FixupDescriptor& fixup_desc,
    const std::vector<uintptr_t>& section_offsets_to_add_to_relocation_table,
    IMAGE_NT_HEADERS* nt_headers,
    Section* reloc_section,
    std::vector<Fixup>* fixups ) {
  if ( section_offsets_to_add_to_relocation_table.empty() ) {
    return;
  }

  // Required to be the .reloc section
  assert( reloc_section->GetName() == ".reloc" );

  // 0x1000 or 4096
  constexpr auto k4kPage = 1 << 12;

  auto reloc_block_virtual_address =
      DetermineFirstRelocationBlockVirtualAddress(
          section_offsets_to_add_to_relocation_table, k4kPage );

  TrimRelocSectionPadding( nt_headers, reloc_section );

  Fixup fixup;
  fixup.desc = fixup_desc;

  std::vector<Relocation> new_relocations;

  for ( const auto vm_section_offset_to_relocate :
        section_offsets_to_add_to_relocation_table ) {
    const auto delta_offset_from_reloc_block_va =
        vm_section_offset_to_relocate - reloc_block_virtual_address;

    Relocation relocation;
#ifdef _WIN64
    relocation.type = IMAGE_REL_BASED_DIR64;
#else
    relocation.type = IMAGE_REL_BASED_HIGHLOW;
#endif
    relocation.offset = delta_offset_from_reloc_block_va;

    // If the next relocation offset is bigger than the allowed value
    if ( delta_offset_from_reloc_block_va >= k4kPage ) {
      fixup.offset =
          AppendRelocationBlock( reloc_block_virtual_address, new_relocations,
                                 nt_headers, reloc_section );
      fixups->push_back( fixup );

      new_relocations.clear();

      // Align the reloc block to a 4k page value (4096)
      reloc_block_virtual_address =
          peutils::AlignDown( vm_section_offset_to_relocate, k4kPage );

      assert( ( vm_section_offset_to_relocate - reloc_block_virtual_address ) <
              k4kPage );

      // refresh the offset for the new block
      relocation.offset =
          vm_section_offset_to_relocate - reloc_block_virtual_address;
    }

    new_relocations.push_back( relocation );
  }

  // If there are still relocations left to add
  if ( new_relocations.size() > 0 ) {
    fixup.offset =
        AppendRelocationBlock( reloc_block_virtual_address, new_relocations,
                               nt_headers, reloc_section );
    fixups->push_back( fixup );
  }
}

void AddVirtualizedCodeSectionRelocations( IMAGE_NT_HEADERS* nt_headers,
                                           Section* reloc_section,
                                           FixupContext* fixup_context ) {
  FixupDescriptor fixup_desc;
  fixup_desc.offset_type = FixupOffsetType::RelocSection;
  fixup_desc.operation =
      FixupOperation::AddVirtualizedCodeSectionVirtualAddress;
  fixup_desc.size = sizeof( uintptr_t );

  AddRelocations(
      fixup_desc,
      fixup_context
          ->virtualized_code_section_offsets_to_add_to_relocation_table,
      nt_headers, reloc_section, &fixup_context->fixups );
}

void AddVmSectionRelocations( IMAGE_NT_HEADERS* nt_headers,
                              Section* reloc_section,
                              FixupContext* fixup_context ) {
  FixupDescriptor fixup_desc;
  fixup_desc.offset_type = FixupOffsetType::RelocSection;
  fixup_desc.operation = FixupOperation::AddVmLoaderSectionVirtualAddress;
  fixup_desc.size = sizeof( uint32_t );

  AddRelocations( fixup_desc,
                  fixup_context->vm_section_offsets_to_add_to_relocation_table,
                  nt_headers, reloc_section, &fixup_context->fixups );
}

void RemoveRelocations( const std::vector<uintptr_t>& relocation_rvas_to_remove,
                        PortableExecutable* pe ) {
  // The relocations to be removed are old relocations of the instruction that we have virtualized.
  // We handle the relocation ourselves, therefore we remove them to not fuck up the jmp to the virtualized code.
  for ( const auto reloc_rva : relocation_rvas_to_remove ) {
    pe->EachRelocation( [&]( IMAGE_BASE_RELOCATION* reloc_block,
                             const uintptr_t rva, Relocation* reloc ) {
      // NOTE: We cannot compare the offsets because, a relocation may have
      // same offsets but different rva's due to adding the reloc block
      // virtual address. Therefore we compare with the RVA's.
      if ( reloc_rva == rva ) {
        // Turn it into padding
        reloc->type = IMAGE_REL_BASED_ABSOLUTE;

        // Reset the offset as well to prevent this from being
        // used to determine some stuff for the badboy
        reloc->offset = 0;

        // std::cout << "Remove relocation for offset: " << std::hex
        //           << reloc->offset << " rva: " << rva << std::endl;
      }
    } );
  }
}

Section CreateVmSection( const PortableExecutable& interpreter_pe ) {
  // TODO: Remove IMAGE_SCN_MEM_EXECUTE to prevent IDA from seeing the section,
  // then dynamically add the executable flag back or VirtualProtect()
  // executable

  // Create the section that will contain the interpreter PE code and all the loader shellcode
  Section vm_section = section::CreateEmptySection(
      VM_LOADER_SECTION_NAME,
      IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE );

  // initialize the vm section with the required functions
  AddInterpreterCodeToSection( interpreter_pe, &vm_section );

  return vm_section;
}

// Returns all offsets relative to given section that has a relocation in the pe relocation table
std::vector<uint32_t> GetRelocationsWithinSectionAsSectionOffsets(
    const PortableExecutable& pe,
    const IMAGE_SECTION_HEADER& section ) {
  std::vector<uint32_t> offsets_result;

  pe.EachRelocationConst( [&]( const IMAGE_BASE_RELOCATION* reloc_block,
                               const uintptr_t rva, const Relocation* reloc ) {
    // We should not add relocations that are padding, we do that ourselves
    if ( reloc->type == IMAGE_REL_BASED_ABSOLUTE ) {
      return;
    }

    if ( section::IsRvaWithinSection( section, rva ) ) {
      const auto relocation_section_offset =
          section::RvaToSectionOffset( section, rva );

      offsets_result.push_back( relocation_section_offset );
    }
  } );

  return offsets_result;
}

// Returns a list containing all the relocation RVA values for the specified PE
// sorted for quick binary search lookup
std::vector<uintptr_t> GetRelocationRvas( const PortableExecutable& pe ) {
  std::vector<uintptr_t> relocation_rvas;

  // Copy the relocations from the original pe into a vector
  pe.EachRelocationConst( [&]( const IMAGE_BASE_RELOCATION* reloc_block,
                               const uintptr_t rva, const Relocation* reloc ) {
    // From MSDN PE documentation:
    // reloc.type = IMAGE_REL_BASED_ABSOLUTE: The base relocation is
    // skipped. This type can be used to pad a block. Therefore we skip
    // relocating if the relocation is of that type to avoid issues
    if ( reloc->type != IMAGE_REL_BASED_ABSOLUTE ) {
      relocation_rvas.push_back( rva );
    }
  } );

  return relocation_rvas;
}

void FixFinishedPe( PortableExecutable* pe,
                    const IMAGE_SECTION_HEADER& text_section,
                    const std::vector<Fixup>& fixups ) {
  // A lazy fix to avoid the fact that some instructions that we virtualize
  // have an entry in the relocation table
  // If we disable the dynamic base address, there is no need to relocate
  // anything in the PE :D
  //pe->DisableASLR();

  auto new_pe_section_headers = pe->GetSectionHeaders();

  const auto new_pe_vm_loader_section =
      new_pe_section_headers.FromName( VM_LOADER_SECTION_NAME );

  const auto new_pe_virtualized_code_section =
      new_pe_section_headers.FromName( VM_CODE_SECTION_NAME );

  const auto reloc_section = new_pe_section_headers.FromName( ".reloc" );

  for ( const auto fixup : fixups ) {
    IMAGE_SECTION_HEADER const* section_header = nullptr;

    switch ( fixup.desc.offset_type ) {
      case FixupOffsetType::VmLoaderSection:
        section_header = new_pe_vm_loader_section;
        break;
      case FixupOffsetType::TextSection:
        section_header = &text_section;
        break;
      case FixupOffsetType::RelocSection:
        section_header = reloc_section;
        break;
      case FixupOffsetType::VirtualizedCodeSection:
        section_header = new_pe_virtualized_code_section;
        break;
      default:
        assert( false && "bruh" );
        break;
    }

    const uintptr_t rva =
        section::SectionOffsetToRva( *section_header, fixup.offset );

    const auto file_offset = new_pe_section_headers.RvaToFileOffset( rva );
    const auto image_ptr_to_update = pe->GetPeImagePtr() + file_offset;

    switch ( fixup.desc.size ) {
      case sizeof( uint32_t ): {
        const auto value = *reinterpret_cast<uint32_t*>( image_ptr_to_update );

        switch ( fixup.desc.operation ) {
          case FixupOperation::AddVmLoaderSectionVirtualAddress:
            *reinterpret_cast<uint32_t*>( image_ptr_to_update ) =
                value + new_pe_vm_loader_section->VirtualAddress;
            break;

          case FixupOperation::AddVirtualizedCodeSectionVirtualAddress:
            *reinterpret_cast<uint32_t*>( image_ptr_to_update ) =
                value + new_pe_virtualized_code_section->VirtualAddress;
            break;

          case FixupOperation::SubtractVmLoaderSectionVirtualAddress:
            *reinterpret_cast<uint32_t*>( image_ptr_to_update ) =
                value - new_pe_vm_loader_section->VirtualAddress;
            break;

          default:
            throw std::runtime_error( "unsupported fixup operation" );
            break;
        }
      } break;

      case sizeof( uint64_t ): {
        const auto value = *reinterpret_cast<uint64_t*>( image_ptr_to_update );

        switch ( fixup.desc.operation ) {
          case FixupOperation::AddVmLoaderSectionVirtualAddress:
            *reinterpret_cast<uint64_t*>( image_ptr_to_update ) =
                value + new_pe_vm_loader_section->VirtualAddress;
            break;

          case FixupOperation::AddVirtualizedCodeSectionVirtualAddress:
            *reinterpret_cast<uint64_t*>( image_ptr_to_update ) =
                value + new_pe_virtualized_code_section->VirtualAddress;
            break;

          case FixupOperation::SubtractVmLoaderSectionVirtualAddress:
            *reinterpret_cast<uint64_t*>( image_ptr_to_update ) =
                value - new_pe_vm_loader_section->VirtualAddress;
            break;

          default:
            throw std::runtime_error( "unsupported fixup operation" );
            break;
        }
      } break;

      default:
        throw std::runtime_error( "unsupported fixup size" );
        break;
    }
  }

  // NOTE: This is not fully tested, may cause issues
  rtti_obfuscator::ObfuscateRTTI( pe );

  const auto nullify_pe_directory = []( PortableExecutable* pe,
                                        IMAGE_NT_HEADERS* nt_headers,
                                        SectionHeaders& section_headers,
                                        const uint32_t directory_index ) {
    const auto rva = nt_headers->OptionalHeader.DataDirectory[ directory_index ]
                         .VirtualAddress;
    const auto size =
        nt_headers->OptionalHeader.DataDirectory[ directory_index ].Size;
    const auto directory_offset = section_headers.RvaToFileOffset( rva );

    auto pe_data = pe->GetPeImagePtr();

    memset( pe_data + directory_offset, 0, size );

    nt_headers->OptionalHeader.DataDirectory[ directory_index ].Size = 0;
    nt_headers->OptionalHeader.DataDirectory[ directory_index ].VirtualAddress =
        0;
  };

  auto new_nt_headers = pe->GetNtHeaders();

  nullify_pe_directory( pe, new_nt_headers, new_pe_section_headers,
                        IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG );

  nullify_pe_directory( pe, new_nt_headers, new_pe_section_headers,
                        IMAGE_DIRECTORY_ENTRY_DEBUG );

#if ENABLE_TLS_CALLBACKS
  // Temporary solution
  auto& tls_data_directory =
      new_nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_TLS ];
  tls_data_directory.Size = sizeof( IMAGE_TLS_DIRECTORY );
  tls_data_directory.VirtualAddress +=
      new_pe_virtualized_code_section->VirtualAddress;
#endif

  auto section = IMAGE_FIRST_SECTION( new_nt_headers );

  // After everything is done, rename the sections.
  // We cannot do earlier because all code are dependant on the section names
  for ( int i = 0; i < new_nt_headers->FileHeader.NumberOfSections; ++i ) {
    strcpy( reinterpret_cast<char*>( section[ i ].Name ), "dicky" );
  }
}

void AddInterpreterRelocationsToFixup( PortableExecutable& interpreter_pe,
                                       ProtectorContext* context ) {
  const auto vm_fun_section_header =
      interpreter_pe.GetSectionHeaders().FromName( VM_FUNCTIONS_SECTION_NAME );

  // Get relocations in interpreter as section offsets
  const auto vm_fun_section_offsets_that_has_relocations =
      GetRelocationsWithinSectionAsSectionOffsets( interpreter_pe,
                                                   *vm_fun_section_header );

  Fixup fixup;
  fixup.desc.offset_type = FixupOffsetType::VmLoaderSection;
  fixup.desc.operation = FixupOperation::AddVmLoaderSectionVirtualAddress;
  fixup.desc.size = sizeof( uint32_t );

  for ( const auto& relocation_section_offset :
        vm_fun_section_offsets_that_has_relocations ) {
    // Add the section offset to vector to later add to the new PE relocation table
    context->fixup_context.vm_section_offsets_to_add_to_relocation_table
        .push_back( relocation_section_offset );

    // Add the offset to the fixups as well to ensure that we add the vm loader virtual address
    fixup.offset = relocation_section_offset;

    context->fixup_context.fixups.push_back( fixup );
  }
}

PortableExecutable AssembleNewPe( const PortableExecutable& original_pe,
                                  ProtectorContext* context ) {
  auto new_sections = original_pe.CopySectionsDeep();

  // Replace the original text section with our modified one
  std::transform( new_sections.begin(), new_sections.end(),
                  new_sections.begin(), [&]( Section& section ) {
                    if ( section.GetName() == ".text" ) {
                      return context->new_text_section;
                    }

                    return section;
                  } );

  auto& reloc_section = new_sections.back();

  // Provided that the .reloc section is the last section, we can add
  // unlimited of relocations to it
  assert( reloc_section.GetName() == ".reloc" );

  auto new_header_data = original_pe.CopyHeaderData();

  IMAGE_NT_HEADERS* new_header_nt_header =
      peutils::GetNtHeaders( new_header_data.data() );

  AddVmSectionRelocations( new_header_nt_header, &reloc_section,
                           &context->fixup_context );

#if ENABLE_TLS_CALLBACKS
  AddVirtualizedCodeSectionRelocations( new_header_nt_header, &reloc_section,
                                        &context->fixup_context );
#endif

  // add the new sections to the new pe
  new_sections.push_back( context->vm_loader_section );
  new_sections.push_back( context->virtualized_code_section );

  return pe::Build( new_header_data, new_sections );
}

PortableExecutable Protect( PortableExecutable original_pe ) {
  PeDisassemblyEngine pe_disassembler( original_pe );

  // todo make the section sizes aligned with the remap
  // be aware, that remap will not work if protected with vmprotect

  PortableExecutable interpreter_pe = ReadInterpreterPe();

  if ( !interpreter_pe.IsValid() ) {
    throw std::runtime_error( "Interpreter is not valid portable executable" );
  }

  const auto interpreter_function_offset =
      GetExportedFunctionOffsetRelativeToSection( interpreter_pe,
                                                  "VmInterpreter" );

  const auto original_pe_nt_headers = *original_pe.GetNtHeaders();

  // When having a jump table in the interpreter, it has a pointer to th jump table
  // that contains the address to locations. Those locatino are being relocated by default.
  // Therefore we need to relocate them as well in order to be able to use them.
  RelocateInterpreterPe( &interpreter_pe,
                         original_pe_nt_headers.OptionalHeader.ImageBase );

  ProtectorContext context;

  context.vm_loader_section = CreateVmSection( interpreter_pe );

  context.virtualized_code_section = section::CreateEmptySection(
      VM_CODE_SECTION_NAME, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE |
                                IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE );

#if ENABLE_TLS_CALLBACKS
  AddTlsCallbacks( original_pe, interpreter_pe, &context );
#endif

  const auto original_text_section_header =
      *original_pe.GetSectionHeaders().FromName( ".text" );

  // Save the text section before modifying it for use later
  // when an invalid instruction has been virtualized to reset the instruction
  const auto original_text_section_copy =
      original_pe.CopySectionDeep( &original_text_section_header );

  // The text section that will be modified with jumps
  context.new_text_section =
      original_pe.CopySectionDeep( &original_text_section_header );

  Stopwatch stopwatch;
  stopwatch.Start();

  AddInterpreterRelocationsToFixup( interpreter_pe, &context );

  uint32_t total_virtualized_instructions = 0;
  uint32_t total_disassembled_instructions = 0;

  std::vector<uintptr_t> original_pe_relocation_rvas =
      GetRelocationRvas( original_pe );

  // Sort for quick binary search
  std::sort( original_pe_relocation_rvas.begin(),
             original_pe_relocation_rvas.end() );

  const auto EachInstructionCallback = [&]( const cs_insn& instruction,
                                            const uint8_t* ) {
    const auto vm_opcode = virtualizer::GetVmOpcode( instruction );

    if ( virtualizer::IsVirtualizeable( instruction, vm_opcode ) ) {
      if ( instruction.detail->x86.eflags != 0 ) {
        // NOTE: Consider using this eflags to describe what eflags
        // it changes when virtualizing the instructions for the interpreter
        throw std::runtime_error(
            "An instruction changing eflags was found, not supported at the "
            "moment" );
      }

      // Get the relocations within the instruction, if any exists
      const auto relocations_rva_within_instruction =
          GetRelocationsWithinInstruction( instruction,
                                           original_pe_relocation_rvas );

      const uint32_t vm_opcode_encyption_key = RandomU32( 1000, 10000000 );

      const auto virtualized_shellcode =
          virtualizer::CreateVirtualizedShellcode(
              instruction, vm_opcode, vm_opcode_encyption_key,
              relocations_rva_within_instruction );

      const bool created_vm_code = virtualized_shellcode.GetBuffer().size() > 0;

      if ( created_vm_code ) {
        const auto virtualized_code_offset =
            context.virtualized_code_section.AppendCode(
                virtualized_shellcode.GetBuffer(),
                original_pe_nt_headers.OptionalHeader.SectionAlignment,
                original_pe_nt_headers.OptionalHeader.FileAlignment );

        // generate loader shellcode for the virtualized shellcode
        auto vm_code_loader_shellcode =
            virtualizer::GetLoaderShellcodeForVirtualizedCode(
                instruction, vm_opcode,
                original_pe_nt_headers.OptionalHeader.ImageBase );

        vm_code_loader_shellcode.ModifyVariable( VmOpcodeEncryptionKeyVariable,
                                                 vm_opcode_encyption_key );

        vm_code_loader_shellcode.ModifyVariable<uintptr_t>(
            VmCodeAddrVariable, virtualized_code_offset );

        const auto loader_shellcode_offset_before =
            context.vm_loader_section.GetCurrentOffset();

        const auto vm_core_function_shellcode_offset =
            vm_code_loader_shellcode.GetNamedValueOffset(
                VmCoreFunctionVariable );

        constexpr auto kCallInstructionSize = 5;

        // this value does not need to be fixed up as we did the others because
        // it it is a call to something in the SAME SECTION
        vm_code_loader_shellcode.ModifyVariable<uint32_t>(
            VmCoreFunctionVariable,
            interpreter_function_offset - loader_shellcode_offset_before -
                kCallInstructionSize - vm_core_function_shellcode_offset + 1 );

        constexpr uint32_t kJmpInstructionSize = 5;

        const auto orig_addr_value_offset =
            vm_code_loader_shellcode.GetNamedValueOffset( OrigAddrVariable );

        const auto destination =
            static_cast<uint32_t>( instruction.address + instruction.size );

        const auto origin = static_cast<uint32_t>(
            loader_shellcode_offset_before + orig_addr_value_offset );

        vm_code_loader_shellcode.ModifyVariable<uint32_t>(
            OrigAddrVariable, destination - origin - kJmpInstructionSize + 1 );

        const auto loader_shellcode_offset =
            context.vm_loader_section.AppendCode(
                vm_code_loader_shellcode.GetBuffer(),
                original_pe_nt_headers.OptionalHeader.SectionAlignment,
                original_pe_nt_headers.OptionalHeader.FileAlignment );

        Fixup jmp_back_addr_fixup;
        jmp_back_addr_fixup.offset =
            loader_shellcode_offset + orig_addr_value_offset;
        jmp_back_addr_fixup.desc.offset_type = FixupOffsetType::VmLoaderSection;
        jmp_back_addr_fixup.desc.operation =
            FixupOperation::SubtractVmLoaderSectionVirtualAddress;
        jmp_back_addr_fixup.desc.size = sizeof( uint32_t );
        context.fixup_context.fixups.push_back( jmp_back_addr_fixup );

        const auto vm_code_addr_offset =
            loader_shellcode_offset +
            vm_code_loader_shellcode.GetNamedValueOffset( VmCodeAddrVariable );

        Fixup virtualized_code_addr_fixup;
        virtualized_code_addr_fixup.offset = vm_code_addr_offset;
        virtualized_code_addr_fixup.desc.offset_type =
            FixupOffsetType::VmLoaderSection;
        virtualized_code_addr_fixup.desc.operation =
            FixupOperation::AddVirtualizedCodeSectionVirtualAddress;
        virtualized_code_addr_fixup.desc.size = sizeof( uint32_t );
        context.fixup_context.fixups.push_back( virtualized_code_addr_fixup );

        const auto vm_var_section_shellcode_offset =
            vm_code_loader_shellcode.GetNamedValueOffset( ImageBaseVariable );

        // add fixup for the image base argument for interpreter call
        context.fixup_context.vm_section_offsets_to_add_to_relocation_table
            .push_back( loader_shellcode_offset +
                        vm_var_section_shellcode_offset );

        const auto instruction_text_section_offset =
            section::RvaToSectionOffset(
                original_text_section_header,
                static_cast<uint32_t>( instruction.address ) );

        const auto text_section_data =
            context.new_text_section.GetData()->data();

        const auto first = text_section_data + instruction_text_section_offset;

        const auto last = first + instruction.size;
        const auto dest = first;

        // Fill the whole instruction with random bytes
        std::transform( first, last, dest,
                        []( uint8_t b ) { return RandomU8(); } );

        constexpr uint8_t kJmpOpcode = 0xE9;

        // Write the jump
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

        // Write the jump destination
        std::copy( jmp_destination_as_uint8_array,
                   jmp_destination_as_uint8_array + sizeof( jmp_destination ),
                   text_section_data + jmp_addr_offset );

        Fixup jmp_to_vm_loader_fixup;
        jmp_to_vm_loader_fixup.offset = jmp_addr_offset;
        jmp_to_vm_loader_fixup.desc.offset_type = FixupOffsetType::TextSection;
        jmp_to_vm_loader_fixup.desc.operation =
            FixupOperation::AddVmLoaderSectionVirtualAddress;
        jmp_to_vm_loader_fixup.desc.size = sizeof( uint32_t );
        context.fixup_context.fixups.push_back( jmp_to_vm_loader_fixup );

        // if it was relocated, add it to a list to remove the relocation later
        // on from PE because when we virtualize an instruction, we handle the relocation ourselve
        for ( const auto reloc_rva : relocations_rva_within_instruction ) {
          context.fixup_context.relocation_rvas_to_remove.push_back(
              reloc_rva );
        }

        ++total_virtualized_instructions;

        file_log::Info( "Virtualized 0x%08I64x, %s %s", instruction.address,
                        instruction.mnemonic, instruction.op_str );
      }
    }

    ++total_disassembled_instructions;
  };

  // Because the disassembler can get it wrong sometimes, we add a callback to reset
  // the virtualized instruction if it notices that it disassembled invalid instructions
  const auto InvalidInstructionCallback =
      [&]( const uint64_t address, const SmallInstructionData ins_data ) {
        const auto text_section_offset = section::RvaToSectionOffset(
            original_text_section_header, address );

        // NOTE: THERE IS MORE WE NEED TO DO HERE I THINK
        assert( false && "verify if the changes made here are correct" );

        //const auto text_section_data =
        //    original_pe.GetPeImagePtr() +
        //    original_text_section_header.PointerToRawData;
        const auto text_section_data =
            context.new_text_section.GetData()->data();

        auto original_pe_text_section_data =
            original_text_section_copy.GetData();

        // TODO: replace with std::copy
        // if the invalid instruction was virtualized, we reset it back here
        // below
        memcpy( text_section_data + text_section_offset,
                &( *original_pe_text_section_data )[ text_section_offset ],
                ins_data.instruction_size_ );

        // Do this disgusting hack for now, change later
        cs_insn temp_instruction;
        temp_instruction.size = ins_data.instruction_size_;
        temp_instruction.address = address;

        // Get the relocations within the instruction, if any exists
        const auto relocations_rva_within_instruction =
            GetRelocationsWithinInstruction( temp_instruction,
                                             original_pe_relocation_rvas );

        // Remove the relocations from the remove-list
        // In other words, restore the relocations that were previously removed
        for ( const auto& reloc_rva : relocations_rva_within_instruction ) {
          const auto it_result = std::find(
              context.fixup_context.relocation_rvas_to_remove.cbegin(),
              context.fixup_context.relocation_rvas_to_remove.cend(),
              reloc_rva );

          const bool found =
              it_result !=
              context.fixup_context.relocation_rvas_to_remove.end();

          if ( found ) {
            context.fixup_context.relocation_rvas_to_remove.erase( it_result );
          }
        }

        char buf[ MAX_PATH ]{ 0 };
        sprintf_s( buf, "Resetting invalid instruction 0x%08I64x\n",
                   static_cast<uint64_t>( address ) );
        printf( "%s\n", buf );
      };

  pe_disassembler.DisassembleFromEntrypoint( EachInstructionCallback,
                                             InvalidInstructionCallback );

  stopwatch.Stop();

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

  // Require the text section size to be the same as the original, we
  // cannot change a section size that is in the middle between other sections
  assert( context.new_text_section.GetSectionHeader().SizeOfRawData ==
          original_text_section_header.SizeOfRawData );

  // We remove the relocations before assembling it. Otherwise it can by mistake
  // remove one of our own relocations because it us using RVA and they have not yet been fixed up.
  RemoveRelocations( context.fixup_context.relocation_rvas_to_remove,
                     &original_pe );

  auto new_pe = AssembleNewPe( original_pe, &context );

  FixFinishedPe( &new_pe, original_text_section_header,
                 context.fixup_context.fixups );

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