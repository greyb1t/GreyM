#include "pch.h"
#include "section.h"
#include "portable_executable.h"
#include "peutils.h"

Section::Section( const IMAGE_SECTION_HEADER& section_header,
                  std::vector<uint8_t> pe_data )
    : section_header_( section_header ) {
  // We use SizeOfRawData because it has to be aligned in the executable (file)
  data_ =
      std::vector<uint8_t>( pe_data.begin() + section_header.PointerToRawData,
                            pe_data.begin() + section_header.PointerToRawData +
                                section_header_.SizeOfRawData );
}

uintptr_t Section::AppendCode( const std::vector<uint8_t>& code,
                               const uint32_t section_alignment,
                               const uint32_t file_alignment ) {
  const auto current_offset = data_.size();

  data_.insert( data_.end(), code.cbegin(), code.cend() );

  section_header_.SizeOfRawData =
      peutils::AlignUp( data_.size(), file_alignment );

  section_header_.Misc.VirtualSize =
      peutils::AlignUp( data_.size(), section_alignment );

  return current_offset;
}

std::string Section::GetName() const {
  return std::string( reinterpret_cast<const char*>( section_header_.Name ) );
}

const IMAGE_SECTION_HEADER& Section::GetSectionHeader() const {
  return section_header_;
}

std::vector<uint8_t>* Section::GetData() {
  return &data_;
}

uint32_t Section::GetCurrentOffset() const {
  return data_.size();
}

Section section::CreateEmptySection( const std::string& name,
                                     const DWORD characteristics ) {
  Section section;

  // TODO: Consider adding an option to modify the characteristics to ones
  // preference, but cannot bother atm...fock it
  section.section_header_.Characteristics = characteristics;
  // IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE |
  // IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA |
  // IMAGE_SCN_CNT_UNINITIALIZED_DATA;

  memcpy( section.section_header_.Name, name.c_str(),
          sizeof( section.section_header_.Name ) );

  return section;
}

const bool section::IsRvaWithinSection(
    const IMAGE_SECTION_HEADER* section_header,
    const uintptr_t rva ) {
  if ( rva >= section_header->VirtualAddress &&
       rva <
           section_header->VirtualAddress + section_header->Misc.VirtualSize ) {
    return true;
  }

  return false;
}

uint32_t section::RvaToSectionOffset(
    const IMAGE_SECTION_HEADER* section_header,
    const uint64_t rva ) {
  return static_cast<uint32_t>( rva - section_header->VirtualAddress );
}

uint32_t section::SectionOffsetToRva(
    const IMAGE_SECTION_HEADER* section_header,
    const uint32_t offset ) {
  return section_header->VirtualAddress + offset;
}