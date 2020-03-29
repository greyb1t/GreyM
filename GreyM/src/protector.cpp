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
      section::RvaToSectionOffset( section_containing_interpreter,
                                   export_found->function_addr_rva );

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

uint32_t GetRelocationBlockCount( const PortableExecutable& pe ) {
  uint32_t last_default_reloc_block_index = 0;

  IMAGE_BASE_RELOCATION const* prev_reloc_block = nullptr;

  pe.EachRelocationConst( [&]( const IMAGE_BASE_RELOCATION* reloc_block,
                               const uintptr_t rva, const Relocation* reloc ) {
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

  // TODO: Consider making this a section method

  // Trim the end of reloc section and remove the padding
  reloc_section_data->erase( reloc_section_data->begin() + reloc_directory.Size,
                             reloc_section_data->end() );
}

void AppendRelocationBlock( const uintptr_t reloc_block_virtual_address,
                            std::vector<Relocation>& relocations,
                            IMAGE_NT_HEADERS* nt_headers,
                            Section& reloc_section ) {
  // if the count of relocations are odd, we need to add one no-op with type
  // and type 0, offset 0 to align to 32 bit boundary
  if ( relocations.size() % 2 != 0 ) {
    relocations.push_back( Relocation{ 0 } );
  }

  std::vector<uint8_t> reloc_block_bytes =
      CreateRelocationBlockBuffer( reloc_block_virtual_address, relocations );

  reloc_section.AppendCode( reloc_block_bytes,
                            nt_headers->OptionalHeader.SectionAlignment,
                            nt_headers->OptionalHeader.FileAlignment );

  auto reloc_directory = &nt_headers->OptionalHeader
                              .DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];

  reloc_directory->Size += reloc_block_bytes.size();
}

// Adds relocations upon the relocation table that relocates
// the image base in the loader shellcode
void AddVmSectionRelocations(
    const std::vector<uintptr_t>& vm_section_offsets_to_relocate,
    IMAGE_NT_HEADERS* nt_headers,
    Section& reloc_section ) {
  // Required to be the .reloc section
  assert( reloc_section.GetName() == ".reloc" );

  constexpr auto kHighestNumberFrom12Bits = 1 << 12;

  auto reloc_block_virtual_address =
      DetermineFirstRelocationBlockVirtualAddress(
          vm_section_offsets_to_relocate, kHighestNumberFrom12Bits );

  TrimRelocSectionPadding( nt_headers, reloc_section );

  std::vector<Relocation> new_relocations;

  for ( const auto vm_section_offset_to_relocate :
        vm_section_offsets_to_relocate ) {
    const auto delta_offset_from_reloc_block_va =
        vm_section_offset_to_relocate - reloc_block_virtual_address;

    // We cannot add a relocation that has the offset 0, it was previously padding
    // Please filter out the relocations to make sure they are not padding, we
    // add the padding outselves and cannot use the one provided in the vector
    // I THINK, NOT SURE THO
    assert( delta_offset_from_reloc_block_va );

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

      // If the next relocation offset is bigger than the allowed value, then we need to
      // adjust the reloc block virtual address until the relocation fits the relocation block
      while ( ( vm_section_offset_to_relocate - reloc_block_virtual_address ) >=
              kHighestNumberFrom12Bits ) {
        // aligned to 4k page (4096)
        reloc_block_virtual_address += 0x1000;
      }

      // refresh the offset for the new block
      relocation.offset =
          vm_section_offset_to_relocate - reloc_block_virtual_address;
    }

    new_relocations.push_back( relocation );
  }

  // If there are still relocations left to add
  if ( new_relocations.size() > 0 ) {
    AppendRelocationBlock( reloc_block_virtual_address, new_relocations,
                           nt_headers, reloc_section );
  }
}

void FixupLoaderRelocationBlocks( const uint32_t previous_reloc_block_count,
                                  PortableExecutable* new_pe ) {
  const auto new_pe_vm_section_rva = new_pe->GetSectionHeaders()
                                         .FromName( VM_LOADER_SECTION_NAME )
                                         ->VirtualAddress;

  uint32_t reloc_block_counter = 0;

  IMAGE_BASE_RELOCATION* prev_reloc_block = nullptr;

  new_pe->EachRelocation( [&]( IMAGE_BASE_RELOCATION* reloc_block,
                               const uintptr_t rva, Relocation* reloc ) {
    // For each relocation block, fixup the virtual address with the vm section rva
    if ( prev_reloc_block != nullptr ) {
      if ( reloc_block->VirtualAddress != prev_reloc_block->VirtualAddress ) {
        ++reloc_block_counter;
        prev_reloc_block = reloc_block;

        // If the reloc block is created by us, then, fix it up
        if ( reloc_block_counter > previous_reloc_block_count ) {
          reloc_block->VirtualAddress += new_pe_vm_section_rva;
        }
      }
    } else {
      prev_reloc_block = reloc_block;
      ++reloc_block_counter;

      // If the reloc block is created by us, then, fix it up
      if ( reloc_block_counter > previous_reloc_block_count ) {
        reloc_block->VirtualAddress += new_pe_vm_section_rva;
      }
    }
  } );
}

Section CreateVmSection( PortableExecutable* interpreter_pe,
                         const uintptr_t new_image_base ) {
  // TODO: Remove IMAGE_SCN_MEM_EXECUTE to prevent IDA from seeing the section,
  // then dynamically add the executable flag back or VirtualProtect()
  // executable

  // Create the section that will contain the interpreter PE code and all the loader shellcode
  Section vm_section = section::CreateEmptySection(
      VM_LOADER_SECTION_NAME,
      IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE );

  // When having a jump table in the interpreter, it has a pointer to th jump table
  // that contains the address to locations. Those locatino are being relocated by default.
  // Therefore we need to relocate them as well in order to be able to use them.
  RelocateInterpreterPe( interpreter_pe, new_image_base );

  // initialize the vm section with the required functions
  AddInterpreterCodeToSection( *interpreter_pe, &vm_section );

  return vm_section;
}

// Returns all offsets relative to given section that has a relocation in the pe relocation table
std::vector<uint32_t> GetRelocationsWithinSectionAsSectionOffsets(
    PortableExecutable& pe,
    const IMAGE_SECTION_HEADER& section ) {
  std::vector<uint32_t> offsets_result;

  pe.EachRelocation( [&]( IMAGE_BASE_RELOCATION* reloc_block,
                          const uintptr_t rva, Relocation* reloc ) {
    // We should not add relocations that are padding, we do that ourselves
    if ( reloc->type == IMAGE_REL_BASED_ABSOLUTE ) {
      return;
    }

    if ( section::IsRvaWithinSection( &section, rva ) ) {
      const auto relocation_section_offset =
          section::RvaToSectionOffset( &section, rva );

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

  std::sort( relocation_rvas.begin(), relocation_rvas.end() );

  return relocation_rvas;
}

struct FixupContext {
  std::vector<uintptr_t> relocation_rvas_to_remove;
  std::vector<uint32_t> offset_fixup_text_section_to_vm_section;
  std::vector<uint32_t> offset_fixup_vm_section_to_virtualized_code_section;
  std::vector<uint32_t> offset_fixup_vm_section_to_text_section;

  // List that contains vm section offsets that should be
  // relocated (modified) by adding the section RVA to them.
  std::vector<uint32_t> vm_section_offsets_to_relocate;

  // A list containing offset relative to vm section
  // that will be added to the relocation table in the PE
  std::vector<uintptr_t> vm_section_offsets_to_add_to_relocation_table;
};

void FixFinishedPe( PortableExecutable* pe,
                    const FixupContext& fixup_context,
                    const IMAGE_SECTION_HEADER& text_section,
                    const uintptr_t previous_reloc_block_count ) {
  // After we have built the new pe, we now have virtual address of the vm
  // section, we use that to fix up the relocations to line up with that section
  FixupLoaderRelocationBlocks( previous_reloc_block_count, pe );

  // AFTER we have fixed up the relocation blocks, THEN we remove the
  // relocations that have to be removed
  // The relocations to be removed are old relocations of the instruction that we have virtualized.
  // We handle the relocation ourselves, therefore we remove them to not fuck up the jmp to the virtualized code.
  // If we do this before fixing the relocation blocks, then we would find
  // double of some RVA's and removing wrong relocations
  for ( const auto reloc_rva : fixup_context.relocation_rvas_to_remove ) {
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

  // A lazy fix to avoid the fact that some instructions that we virtualize
  // have an entry in the relocation table
  // If we disable the dynamic base address, there is no need to relocate
  // anything in the PE :D
  //new_pe.DisableASLR();

  auto new_pe_sections = pe->GetSectionHeaders();

  const auto new_pe_vm_section =
      new_pe_sections.FromName( VM_LOADER_SECTION_NAME );

  const auto new_pe_virtualized_code_section =
      new_pe_sections.FromName( VM_CODE_SECTION_NAME );

  for ( const uint32_t text_section_offset :
        fixup_context.offset_fixup_text_section_to_vm_section ) {
    const auto rva_rva =
        section::SectionOffsetToRva( &text_section, text_section_offset );
    const auto file_offset = new_pe_sections.RvaToFileOffset( rva_rva );
    auto image_ptr = pe->GetPeImagePtr();

    uint32_t loader_shellcode_offset =
        *reinterpret_cast<uint32_t*>( image_ptr + file_offset );

    // Add the virtual address for that specific section to make it point to the
    // correct location
    *reinterpret_cast<uint32_t*>( image_ptr + file_offset ) =
        loader_shellcode_offset + new_pe_vm_section->VirtualAddress;
  }

  for ( const uint32_t vm_section_image_base_offset :
        fixup_context.offset_fixup_vm_section_to_virtualized_code_section ) {
    const auto rva_rva = section::SectionOffsetToRva(
        new_pe_vm_section, vm_section_image_base_offset );
    const auto file_offset = new_pe_sections.RvaToFileOffset( rva_rva );
    auto image_ptr = pe->GetPeImagePtr();

    uint32_t vm_code_offset =
        *reinterpret_cast<uint32_t*>( image_ptr + file_offset );

    // Add the virtual address for that specific section to make it point to the
    // correct location
    *reinterpret_cast<uint32_t*>( image_ptr + file_offset ) =
        vm_code_offset + new_pe_virtualized_code_section->VirtualAddress;
  }

  for ( const uint32_t text_section_offset :
        fixup_context.offset_fixup_vm_section_to_text_section ) {
    const auto rva_rva =
        section::SectionOffsetToRva( new_pe_vm_section, text_section_offset );
    const auto file_offset = new_pe_sections.RvaToFileOffset( rva_rva );
    auto image_ptr = pe->GetPeImagePtr();

    uint32_t loader_shellcode_offset =
        *reinterpret_cast<uint32_t*>( image_ptr + file_offset );

    // Add the virtual address for that specific section to make it point to the
    // correct location
    *reinterpret_cast<uint32_t*>( image_ptr + file_offset ) =
        loader_shellcode_offset - new_pe_vm_section->VirtualAddress;
  }

  // Add the vm_section RVA to each of the values that should be relocated
  for ( const uint32_t vm_section_interpreter_offset :
        fixup_context.vm_section_offsets_to_relocate ) {
    const auto rva_rva = section::SectionOffsetToRva(
        new_pe_vm_section, vm_section_interpreter_offset );
    const auto file_offset = new_pe_sections.RvaToFileOffset( rva_rva );
    auto image_ptr = pe->GetPeImagePtr();

    uint32_t loader_shellcode_offset =
        *reinterpret_cast<uint32_t*>( image_ptr + file_offset );

    // Add the virtual address for that specific section to make it point to the
    // correct location
    *reinterpret_cast<uint32_t*>( image_ptr + file_offset ) =
        loader_shellcode_offset + new_pe_vm_section->VirtualAddress;
  }

  // NOTE: This is not fully tested, may cause issues
  rtti_obfuscator::ObfuscateRTTI( pe );

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

  auto new_nt_headers = pe->GetNtHeaders();

  nullify_pe_directory( pe, new_nt_headers, new_pe_sections,
                        IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG );

  nullify_pe_directory( pe, new_nt_headers, new_pe_sections,
                        IMAGE_DIRECTORY_ENTRY_DEBUG );
}

void AddInterpreterRelocationsToFixup( PortableExecutable& interpreter_pe,
                                       FixupContext* fixup_context ) {
  const auto vm_fun_section_header =
      interpreter_pe.GetSectionHeaders().FromName( VM_FUNCTIONS_SECTION_NAME );

  // Get relocations in interpreter as section offsets
  const auto vm_fun_section_offsets_that_has_relocations =
      GetRelocationsWithinSectionAsSectionOffsets( interpreter_pe,
                                                   *vm_fun_section_header );

  for ( const auto& relocation_section_offset :
        vm_fun_section_offsets_that_has_relocations ) {
    // Add the section offset to vector to later add to the new PE relocation table
    fixup_context->vm_section_offsets_to_add_to_relocation_table.push_back(
        relocation_section_offset );

    // Add section offset to vector to later do a modification on the value in that offset
    fixup_context->vm_section_offsets_to_relocate.push_back(
        relocation_section_offset );
  }
}

PortableExecutable AssembleNewPe( const PortableExecutable& original_pe,
                                  const FixupContext& fixup_context,
                                  const Section& new_text_section,
                                  const Section& vm_loader_section,
                                  const Section& virtualized_code_section ) {
  auto new_sections = original_pe.CopySections();

  // Replace the original text section with our modified one
  std::transform( new_sections.begin(), new_sections.end(),
                  new_sections.begin(), [&]( Section& section ) {
                    if ( section.GetName() == ".text" ) {
                      return new_text_section;
                    }

                    return section;
                  } );

  auto& last_section = new_sections.back();

  // Provided that the .reloc section is the last section, we can add
  // unlimited of relocations to it
  assert( last_section.GetName() == ".reloc" );

  auto new_header_data = original_pe.CopyHeaderData();

  IMAGE_NT_HEADERS* new_header_nt_header =
      peutils::GetNtHeaders( new_header_data.data() );

  // The relocation vector holds offsets relative to the section
  // below in the FixupLoaderRelocationBlocks() call, we later fix up those relocations
  AddVmSectionRelocations(
      fixup_context.vm_section_offsets_to_add_to_relocation_table,
      new_header_nt_header, last_section );

  // add the new sections to the new pe
  new_sections.push_back( vm_loader_section );
  new_sections.push_back( virtualized_code_section );

  return pe::Build( new_header_data, new_sections );
}

PortableExecutable Protect( const PortableExecutable original_pe ) {
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

  auto vm_loader_section = CreateVmSection(
      &interpreter_pe, original_pe_nt_headers.OptionalHeader.ImageBase );

#if 0
  // TODO: Since we added support for dynamic base, we need to relocate it :O
  AddTlsCallbacks( original_pe, interpreter_pe,
                   vm_section_virtual_address, vm_section,
                   original_pe_nt_headers, header_data );
#endif

  std::string output_log = "";

  const auto original_text_section_header =
      *original_pe.GetSectionHeaders().FromName( ".text" );

  // Save the text section before modifying it for use later
  // when an invalid instruction has been virtualized to reset the instruction
  const auto original_text_section_copy =
      original_pe.CopySectionDeep( &original_text_section_header );

  // The text section that will be modified with jumps
  auto new_text_section =
      original_pe.CopySectionDeep( &original_text_section_header );

  Stopwatch stopwatch;
  stopwatch.Start();

  FixupContext fixup_context;

  AddInterpreterRelocationsToFixup( interpreter_pe, &fixup_context );

  auto virtualized_code_section = section::CreateEmptySection(
      VM_CODE_SECTION_NAME, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE );

  uint32_t total_virtualized_instructions = 0;
  uint32_t total_disassembled_instructions = 0;

  std::vector<uintptr_t> original_pe_relocation_rvas =
      GetRelocationRvas( original_pe );

  const auto EachInstructionCallback = [&]( const cs_insn& instruction,
                                            const uint8_t* code ) {
    //  BELOW CODE CAUSES BAD PERFORMANCE ISSUES, sprintf_s call is doing
    //  every instruction
    /*
      char buf[ MAX_PATH ]{ 0 }; sprintf_s( buf, "0x%08I64x - %s
      %s\n", instruction.address, instruction.mnemonic, instruction.op_str );

      output_log += buf;
    */

    const auto vm_opcode = virtualizer::GetVmOpcode( instruction );

    // if is virtualizable
    if ( virtualizer::IsVirtualizeable( instruction, vm_opcode ) ) {
      if ( instruction.detail->x86.eflags != 0 ) {
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
            virtualized_code_section.AppendCode(
                virtualized_shellcode.GetBuffer(),
                original_pe_nt_headers.OptionalHeader.SectionAlignment,
                original_pe_nt_headers.OptionalHeader.FileAlignment );

        // generate loader shellcode for the virtualized shellcode
        auto vm_code_loader_shellcode =
            virtualizer::GetLoaderShellcodeForVirtualizedCode(
                instruction, vm_opcode,
                original_pe_nt_headers.OptionalHeader.ImageBase );

        vm_code_loader_shellcode.ModifyValue( TEXT( "vm_opcode_encyption_key" ),
                                              vm_opcode_encyption_key );

        vm_code_loader_shellcode.ModifyValue<uintptr_t>(
            TEXT( "VmCodeAddr" ), virtualized_code_offset );

        const auto loader_shellcode_offset_before =
            vm_loader_section.GetCurrentOffset();

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

        const auto loader_shellcode_offset = vm_loader_section.AppendCode(
            vm_code_loader_shellcode.GetBuffer(),
            original_pe_nt_headers.OptionalHeader.SectionAlignment,
            original_pe_nt_headers.OptionalHeader.FileAlignment );

        // add to vector to modify the value later because the sections have no
        // VirtualAddress yet
        fixup_context.offset_fixup_vm_section_to_text_section.push_back(
            loader_shellcode_offset + orig_addr_value_offset );

        const auto vm_code_addr_offset =
            loader_shellcode_offset +
            vm_code_loader_shellcode.GetNamedValueOffset(
                TEXT( "VmCodeAddr" ) );

        fixup_context.offset_fixup_vm_section_to_virtualized_code_section
            .push_back( vm_code_addr_offset );

        const auto vm_var_section_shellcode_offset =
            vm_code_loader_shellcode.GetNamedValueOffset(
                TEXT( "VmVarSection" ) );

        // add fixup for the image base argument for interpreter call
        fixup_context.vm_section_offsets_to_add_to_relocation_table.push_back(
            loader_shellcode_offset + vm_var_section_shellcode_offset );

        const auto instruction_text_section_offset =
            section::RvaToSectionOffset(
                &original_text_section_header,
                static_cast<uint32_t>( instruction.address ) );

        //const auto text_section_data =
        //    original_pe.GetPeData().begin() +
        //    original_text_section_header.PointerToRawData;

        // TODO: Add check to see whehter it is inside .text section

        const auto text_section_data = new_text_section.GetData()->data();

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
        fixup_context.offset_fixup_text_section_to_vm_section.push_back(
            jmp_addr_offset );

        // if it was relocated, add it to a list to remove the relocation later
        // on from PE because when we virtualize an instruction, we handle the relocation ourselve
        for ( const auto reloc_rva : relocations_rva_within_instruction ) {
          fixup_context.relocation_rvas_to_remove.push_back( reloc_rva );
        }

        ++total_virtualized_instructions;
      }
    }

    ++total_disassembled_instructions;
  };

  // Because the disassembler can get it wrong sometimes, we add a callback to reset
  // the virtualized instruction if it notices that it disassembled invalid instructions
  const auto InvalidInstructionCallback =
      [&]( const uint64_t address, const SmallInstructionData ins_data ) {
        const auto text_section_offset = section::RvaToSectionOffset(
            &original_text_section_header, address );

        assert( false && "verify if the changes made here are correct" );

        //const auto text_section_data =
        //    original_pe.GetPeImagePtr() +
        //    original_text_section_header.PointerToRawData;
        const auto text_section_data = new_text_section.GetData()->data();

        auto original_pe_text_section_data =
            original_text_section_copy.GetData();

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

  // Save the block relocation count for use later to determine which are the
  // new reloc block to fixup the VirtualAddress of.
  // If we do not properly fixup the reloc blocks in the finished PE, the EXE will
  // still work, but the loader will always load it at the default image base address
  const auto previous_reloc_block_count =
      GetRelocationBlockCount( original_pe );

  // Require the text section size to be the same as the original, we
  // cannot change a section size that is in the middle between other sections
  assert( new_text_section.GetSectionHeader().SizeOfRawData ==
          original_text_section_header.SizeOfRawData );

  auto new_pe = AssembleNewPe( original_pe, fixup_context, new_text_section,
                               vm_loader_section, virtualized_code_section );

  // Do the finishing touches
  FixFinishedPe( &new_pe, fixup_context, original_text_section_header,
                 previous_reloc_block_count );

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