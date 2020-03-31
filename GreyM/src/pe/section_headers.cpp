#include "pch.h"
#include "section_headers.h"
#include "section.h"

IMAGE_SECTION_HEADER* SectionHeaders::FromName(
    const std::string& name ) const {
  for ( auto& section_header : headers_ ) {
    if ( strcmp( reinterpret_cast<const char*>( section_header->Name ),
                 name.c_str() ) == 0 )
      return section_header;
  }

  return nullptr;
}

uintptr_t SectionHeaders::RvaToFileOffset( const uintptr_t rva ) const {
  const auto section_header = FromRva( rva );

  if ( !section_header )
    return 0;

  // if the section is empty
  if ( strcmp( reinterpret_cast<const char*>( section_header->Name ), "" ) ==
       0 )
    return 0;

  return section_header->PointerToRawData +
         ( rva - section_header->VirtualAddress );
}

IMAGE_SECTION_HEADER* SectionHeaders::FromRva(
    const uintptr_t rva ) const {
  for ( auto& section_header : headers_ ) {
    if ( section::IsRvaWithinSection( section_header, rva ) ) {
      return section_header;
    }
  }

  return nullptr;
}
