#pragma once

/*
  Not thread safe, tried to make as fast as possible, 
  hence the use of C api and not C++ shit
*/

#include <stdarg.h>

namespace file_log {

void Info( const char* format, ... );

}  // namespace file_log