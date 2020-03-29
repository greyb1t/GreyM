#pragma once

class SectionHeaders {
 public:
  std::vector<IMAGE_SECTION_HEADER*> headers;

  IMAGE_SECTION_HEADER* FromName( const std::string& name ) const;

  uintptr_t RvaToFileOffset( const uintptr_t rva ) const;

  IMAGE_SECTION_HEADER* FromRva( const uintptr_t rva ) const;
};