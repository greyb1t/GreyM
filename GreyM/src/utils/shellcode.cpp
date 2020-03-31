#include "pch.h"
#include "shellcode.h"
#include "../utils/string_utils.h"

void Shellcode::AddByte( const uint8_t value ) {
  buffer_.push_back( value );
}

void Shellcode::AddBytes( const std::initializer_list<uint8_t> bytes ) {
  buffer_.insert( buffer_.end(), bytes );
}

int32_t Shellcode::GetNamedValueOffset( const std::wstring& value_name ) {
  for ( const auto& named_value : named_value_offsets_ ) {
    if ( named_value.first == value_name ) {
      return named_value.second;
    }
  }

  throw std::runtime_error( string_utils::WideToAnsi( value_name ) +
                            " was not found in the shellcode" );
}

void Shellcode::Reserve( const size_t capacity ) {
  buffer_.reserve( capacity );
}

const std::vector<uint8_t>& Shellcode::GetBuffer() const {
  return buffer_;
}
