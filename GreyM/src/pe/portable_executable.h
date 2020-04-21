#pragma once

#include "section.h"
#include "section_headers.h"

class PortableExecutable;

namespace pe {

PortableExecutable Open( const std::vector<uint8_t>& pe_data );
PortableExecutable Build( const std::vector<uint8_t>& header,
                          const std::vector<Section>& sections );

}  // namespace pe

struct Export {
  std::string function_name;
  uint32_t function_addr_rva;
};

struct Import {
  std::string associated_module;
  std::string function_name;
  DWORD function_addr_rva;
};

struct Relocation {
  WORD offset : 12;
  WORD type : 4;
};

using EachRelocationCallback_t = void ( * )( IMAGE_BASE_RELOCATION* reloc_block,
                                             uintptr_t rva,
                                             Relocation* reloc );

using EachRelocationConstCallback_t =
    void ( * )( const IMAGE_BASE_RELOCATION* reloc_block,
                const uintptr_t rva,
                const Relocation* reloc );

class PortableExecutable {
 private:
  PortableExecutable( const std::vector<uint8_t>& pe_data );

 public:
  // Delete the constructor, force user to only be able to use the pe:: namespace
  PortableExecutable() = delete;

  // Copy constructor
  PortableExecutable( const PortableExecutable& rhs );

  // Check whether or not the PE is valid throug the headers
  bool IsValid() const;

  // Copies all of the sections deeply, that includes the data assocated with the section
  std::vector<Section> CopySectionsDeep() const;

  // Copies all of the sections deeply, that includes the data assocated with the section
  Section CopySectionDeep( const IMAGE_SECTION_HEADER* section_header ) const;

  SectionHeaders GetSectionHeaders() const;

  std::vector<Import> GetImports() const;

  std::vector<uintptr_t> GetTlsCallbacklist() const;

  // I previously used a std::function for the callback, but using a templated
  // function supports capturing variable in the lambda as well and has
  // extremely good performance compared to std::function
  // TFunc: void callback(IMAGE_BASE_RELOCATION *reloc_block, uintptr_t rva, Relocation* reloc)
  template <typename TFunc = EachRelocationCallback_t>
  void EachRelocation( const TFunc& callback );

  // TFuncConst: void callback(const IMAGE_BASE_RELOCATION *reloc_block,
  //                      const uintptr_t rva, const Relocation* reloc)
  template <typename TFuncConst = EachRelocationConstCallback_t>
  void EachRelocationConst( const TFuncConst& callback ) const;

  std::vector<Export> GetExports() const;

  void DisableASLR();
  void Relocate( const uintptr_t new_image_base_address );

  std::vector<uint8_t> CopyHeaderData() const;

  uint8_t* GetPeImagePtr();
  const uint8_t* GetPeImagePtr() const;

  const std::vector<uint8_t>& GetPeData() const;
  std::vector<uint8_t>& GetPeData();

  IMAGE_NT_HEADERS* GetNtHeaders() const;

 private:
  std::vector<uint8_t> pe_data_;

  IMAGE_NT_HEADERS* nt_headers_;
  IMAGE_DOS_HEADER* dos_headers_;

  friend PortableExecutable pe::Open( const std::vector<uint8_t>& pe_data );

  friend PortableExecutable pe::Build( const std::vector<uint8_t>& header,
                                       const std::vector<Section>& sections );
};

template <typename TFunc>
void PortableExecutable::EachRelocation( const TFunc& callback ) {
  const auto pe_data_ptr = &pe_data_[ 0 ];

  const auto sections = GetSectionHeaders();

  const auto& reloc_directory =
      nt_headers_->OptionalHeader
          .DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];

  auto reloc_block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
      pe_data_ptr +
      sections.RvaToFileOffset( reloc_directory.VirtualAddress ) );

  uint32_t relocation_size_read = 0;

  // Iterate each relocation block
  while ( relocation_size_read < reloc_directory.Size ) {
    const DWORD reloc_list_count =
        ( reloc_block->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) /
        sizeof( WORD );

    WORD* reloc_list =
        reinterpret_cast<WORD*>( reinterpret_cast<size_t>( reloc_block ) +
                                 sizeof( IMAGE_BASE_RELOCATION ) );

    for ( size_t i = 0; i < reloc_list_count; ++i ) {
      Relocation* reloc = reinterpret_cast<Relocation*>( &reloc_list[ i ] );

      const auto rva = reloc->offset + reloc_block->VirtualAddress;

      callback( reloc_block, rva, reloc );
    }

    relocation_size_read += reloc_block->SizeOfBlock;

    reloc_block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
        reinterpret_cast<size_t>( reloc_block ) + reloc_block->SizeOfBlock );
  }
}

template <typename TFuncConst>
void PortableExecutable::EachRelocationConst(
    const TFuncConst& callback ) const {
  // This callback wrapped enforces the const part in the arguments of the callback
  const auto callback_wrapper =
      [=]( const IMAGE_BASE_RELOCATION* reloc_block, const uintptr_t rva,
           const Relocation* reloc ) { callback( reloc_block, rva, reloc ); };

  // DISGUSTING, but recommended by Meyer according to stackoverflow lol
  const auto one = static_cast<const PortableExecutable&>( *this );
  auto two = const_cast<PortableExecutable&>( one );

  two.EachRelocation( callback_wrapper );
}