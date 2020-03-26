#pragma once

inline uint8_t RandomU8() {
  return rand() % 0xff;
}

template <int N>
inline void GenerateRandomBytes( std::array<uint8_t, N>& buffer,
                                 const uint32_t length ) {
  for ( uint32_t i = 0; i < length; ++i ) {
    buffer[ i ] = RandomU8();
  }
}

inline uint32_t RandomU32( const int min, const int max ) {
  return rand() % max + min;
}