#pragma once

#include <string>
#include <stdarg.h>
#include <windows.h>

namespace console {

inline void Print( const char* format, ... ) {
  va_list args;
  va_start( args, format );

  vprintf( format, args );
  printf( "\n" );

  va_end( args );
}

}  // namespace console