#include "pch.h"
#include "peutils.h"

namespace peutils {

uintptr_t AlignUp( const uintptr_t value, const uintptr_t alignment ) {
  // return ( ( ( value + alignment - 1 ) / alignment ) * alignment );
  const auto remainder = value % alignment;

  // is it already aligned?
  if ( remainder == 0 )
    return value;

  return value + ( alignment - remainder );
}

uintptr_t AlignDown( const uintptr_t value, const uintptr_t alignment ) {
  return value - ( value % alignment );
}

IMAGE_DOS_HEADER* GetDosHeader( uint8_t* data ) {
  return reinterpret_cast<IMAGE_DOS_HEADER*>( data );
}

IMAGE_NT_HEADERS* GetNtHeaders( uint8_t* data ) {
  auto dos_headers_ = GetDosHeader( data );
  auto nt_headers =
      reinterpret_cast<IMAGE_NT_HEADERS*>( data + dos_headers_->e_lfanew );

  return nt_headers;
}

}  // namespace peutils