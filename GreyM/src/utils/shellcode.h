#pragma once

#include <string>
#include <algorithm>

class Shellcode {
 public:
  void AddByte( const uint8_t value );
  void AddBytes( const std::initializer_list<uint8_t> bytes );

  template <typename T>
  void AddValue( const T& value, const std::wstring& value_name = TEXT( "" ) ) {
    if ( !value_name.empty() ) {
      const auto current_buffer_offset = buffer_.size();
      named_value_offsets_.insert(
          std::make_pair( value_name, current_buffer_offset ) );
    }

    const uint8_t* buf = reinterpret_cast<const uint8_t*>( &value );

    std::copy( &buf[ 0 ], &buf[ sizeof( value ) ],
               std::back_inserter( buffer_ ) );
  }

  template <typename T>
  void ModifyValue( const std::wstring& value_name, const T& value ) {
    const auto buf_offset = GetNamedValueOffset( value_name );

    if ( buf_offset != -1 ) {
      const uint8_t* buf = reinterpret_cast<const uint8_t*>( &value );
      std::copy( &buf[ 0 ], &buf[ sizeof( value ) ],
                 buffer_.begin() + buf_offset );
    }
  }

  int32_t GetNamedValueOffset( const std::wstring& value_name );

  void Reserve( const size_t capacity );

  const std::vector<uint8_t>& GetBuffer() const {
    return buffer_;
  }

 private:
  std::vector<uint8_t> buffer_;
  std::unordered_map<std::wstring, uint32_t> named_value_offsets_;
};