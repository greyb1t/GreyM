#include "pch.h"
#include "section.h"
#include "portable_executable.h"
#include "peutils.h"

Section::Section( const IMAGE_SECTION_HEADER& section_header,
                  const std::vector<uint8_t> pe_data )
    : section_header_( section_header ) {
  // We use SizeOfRawData because it has to be aligned in the executable (file)
  data_ =
      std::vector<uint8_t>( pe_data.cbegin() + section_header.PointerToRawData,
                            pe_data.cbegin() + section_header.PointerToRawData +
                                section_header_.SizeOfRawData );
}

uintptr_t Section::AppendCode( const std::vector<uint8_t>& code,
                               const uint32_t section_alignment,
                               const uint32_t file_alignment ) {
  return AppendCode( &code[ 0 ], code.size(), file_alignment );
}

uintptr_t Section::AppendCode( const uint8_t* buffer,
                               const uintptr_t size,
                               const uint32_t file_alignment ) {
  const auto current_offset = data_.size();

  data_.insert( data_.end(), buffer, buffer + size );

  section_header_.SizeOfRawData =
      peutils::AlignUp( data_.size(), file_alignment );

  // Is this alignment required? Probably not.
  //section_header_.Misc.VirtualSize =
  //    peutils::AlignUp( data_.size(), section_alignment );
  section_header_.Misc.VirtualSize = data_.size();

  return current_offset;
}

std::string Section::GetName() const {
  return std::string( reinterpret_cast<const char*>( section_header_.Name ) );
}

void Section::SetName( const std::string& name ) {
  assert( name.size() <= 8 );

  memcpy( section_header_.Name, name.c_str(), sizeof( section_header_.Name ) );
}

const IMAGE_SECTION_HEADER& Section::GetSectionHeader() const {
  return section_header_;
}

std::vector<uint8_t>* Section::GetData() {
  return &data_;
}

const std::vector<uint8_t>* Section::GetData() const {
  return &data_;
}

uint32_t Section::GetCurrentOffset() const {
  return data_.size();
}

Section section::CreateEmptySection( const std::string& name,
                                     const DWORD characteristics ) {
  Section section;

  section.section_header_.Characteristics = characteristics;

  section.SetName( name );

  return section;
}

const bool section::IsRvaWithinSection(
    const IMAGE_SECTION_HEADER& section_header,
    const uintptr_t rva ) {
  if ( rva >= section_header.VirtualAddress &&
       rva < section_header.VirtualAddress + section_header.Misc.VirtualSize ) {
    return true;
  }

  return false;
}

uintptr_t section::RvaToSectionOffset(
    const IMAGE_SECTION_HEADER& section_header,
    const uint64_t rva ) {
  return static_cast<uint32_t>( rva - section_header.VirtualAddress );
}

uintptr_t section::SectionOffsetToRva(
    const IMAGE_SECTION_HEADER& section_header,
    const uint32_t offset ) {
  return section_header.VirtualAddress + offset;
}