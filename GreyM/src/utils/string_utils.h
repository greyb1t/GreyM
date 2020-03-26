#pragma once

#include <string>
#include <Windows.h>

namespace string_utils {

static std::string WideToAnsi( const std::wstring wide_string ) {
  std::string ansi_string;
  ansi_string.resize( wide_string.size() );

  char fail_convert_char_replacement = '?';

  WideCharToMultiByte( CP_ACP, 0, wide_string.c_str(), wide_string.size(),
                       ansi_string.data(),
                       ansi_string.size() * sizeof( std::string::value_type ),
                       &fail_convert_char_replacement, NULL );

  ansi_string.shrink_to_fit();

  return ansi_string;
}

}  // namespace string_utils