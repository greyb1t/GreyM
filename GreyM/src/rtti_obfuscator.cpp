#include "pch.h"
#include "rtti_obfuscator.h"
#include "pe/portable_executable.h"
#include "utils/random.h"

namespace rtti_obfuscator {

void ObfuscateRTTI( PortableExecutable* pe ) {
  constexpr int kMaxTypenameLength = 255;

  std::array<uint8_t, kMaxTypenameLength> buffer{ 0 };

  auto& pe_data = pe->GetPeData();

  std::vector<uint8_t> pattern = { '.', '?', 'A', 'V' };

  for ( size_t i = 0; i < pe_data.size() - pattern.size(); ++i ) {
    const auto current_it = pe_data.begin() + i;
    const auto current_it_end = current_it + pattern.size();
    // check if the iterator is equal to the pattern .?AV
    if ( std::equal( current_it, current_it_end, pattern.begin() ) ) {
      const auto max_chars_to_search_for_end_it =
          current_it_end + kMaxTypenameLength;
      // find the end of the string, if no found, the string is longer than 255
      // or not a string at all in that case, we do not want to do anything with
      // it
      const auto typename_end =
          std::find_if( current_it_end, max_chars_to_search_for_end_it,
                        []( uint8_t value ) { return value == '\0'; } );
      if ( typename_end != pe_data.end() ) {
        const auto typename_str_length =
            std::distance( current_it, typename_end );
        // replace the typename string with 3 random bytes
        GenerateRandomBytes( buffer, 3 );
        std::copy( buffer.begin(), buffer.begin() + typename_str_length,
                   current_it );
      }
    }
  }
}

}  // namespace rtti_obfuscator