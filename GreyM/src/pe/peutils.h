#pragma once

namespace peutils {

uintptr_t AlignUp( const uintptr_t value, const uintptr_t alignment );
uintptr_t AlignDown( const uintptr_t value, const uintptr_t alignment );

IMAGE_DOS_HEADER* GetDosHeader( uint8_t* data );
IMAGE_NT_HEADERS* GetNtHeaders( uint8_t* data );

}  // namespace peutils