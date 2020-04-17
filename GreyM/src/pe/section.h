#pragma once

class PortableExecutable;
class Section;

namespace section {

Section CreateEmptySection( const std::string& name,
                            const DWORD characteristics );

const bool IsRvaWithinSection( const IMAGE_SECTION_HEADER& section_header,
                               const uintptr_t rva );

uintptr_t RvaToSectionOffset( const IMAGE_SECTION_HEADER& section_header,
                              const uint64_t rva );

uintptr_t SectionOffsetToRva( const IMAGE_SECTION_HEADER& section_header,
                              const uint32_t offset );

}  // namespace section

namespace pe {

PortableExecutable Build( const std::vector<uint8_t>& header,
                          const std::vector<Section>& sections );

}  // namespace pe

class Section {
 public:
  Section() : section_header_{ 0 }, data_{} {}

  Section( const IMAGE_SECTION_HEADER& section_header,
           const std::vector<uint8_t> pe_data );

  // AppendCode returns the new code offset relative to the section beginning
  // in other words, if offset is 0, it is on the beginning of the section
  uintptr_t AppendCode( const std::vector<uint8_t>& code,
                        const uint32_t section_alignment,
                        const uint32_t file_alignment );

  std::string GetName() const;
  void SetName(const std::string& name);

  const IMAGE_SECTION_HEADER& GetSectionHeader() const;

  std::vector<uint8_t>* GetData();
  const std::vector<uint8_t>* GetData() const;

  uint32_t GetCurrentOffset() const;

 private:
  IMAGE_SECTION_HEADER section_header_;
  std::vector<uint8_t> data_;

  friend Section section::CreateEmptySection( const std::string& name,
                                              const DWORD characteristics );

  friend PortableExecutable pe::Build( const std::vector<uint8_t>& header,
                                       const std::vector<Section>& sections );
};