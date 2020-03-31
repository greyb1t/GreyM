#pragma once

class SectionHeaders {
 public:
  SectionHeaders( std::vector<IMAGE_SECTION_HEADER*>& headers )
      : headers_( headers ) {}

  IMAGE_SECTION_HEADER* FromName( const std::string& name ) const;

  uintptr_t RvaToFileOffset( const uintptr_t rva ) const;

  IMAGE_SECTION_HEADER* FromRva( const uintptr_t rva ) const;

 private:
  std::vector<IMAGE_SECTION_HEADER*> headers_;
};