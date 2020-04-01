#include "pch.h"
#include "file_log.h"

static std::ofstream file( "log.txt", std::ofstream::out );

// to avoid allocations each time, use the same buffer all the time
static char g_log_buffer[ 1024 + 1 ];

void LogFormat( const uintptr_t offset,
                          const char* format,
                          va_list args ) {
  const auto chars_written_count =
      vsprintf( g_log_buffer + offset, format, args );

  // add newline
  g_log_buffer[ offset + chars_written_count ] = '\n';
  // null terminate it
  g_log_buffer[ offset + chars_written_count + 1 ] = '\0';

  file << g_log_buffer;

  // Reset the log buffer
  g_log_buffer[ 0 ] = '\0';
}

void file_log::Info( const char* format, ... ) {
  strcat( g_log_buffer, "[INFO] \0" );

  va_list args;

  va_start( args, format );

  LogFormat( strlen( g_log_buffer ), format, args );

  va_end( args );
}
