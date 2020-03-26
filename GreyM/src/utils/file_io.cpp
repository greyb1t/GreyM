#include "pch.h"
#include "file_io.h"
#include "string_utils.h"

std::vector<uint8_t> fileio::ReadBinaryFile( const std::wstring& filename ) {
  std::ifstream file( filename, std::ifstream::in | std::ifstream::binary );

  if ( !file.is_open() )
    throw std::runtime_error( "Unable to open file " +
                              string_utils::WideToAnsi( filename ) );

  file.seekg( 0, std::ifstream::end );
  const auto length = static_cast<size_t>( file.tellg() );
  file.seekg( 0, std::ifstream::beg );

  std::vector<uint8_t> output;
  output.resize( length );

  file.read( reinterpret_cast<char*>( output.data() ), length );

  if ( file.bad() || file.fail() )
    throw std::runtime_error( "Error occured while trying to read the file " +
                              string_utils::WideToAnsi( filename ) );

  file.close();

  return std::move( output );
}

bool fileio::WriteFileData( const std::wstring& filename,
                            const std::vector<uint8_t>& buf ) {
  std::ofstream file( filename, std::ofstream::out | std::ofstream::binary );

  file.write( reinterpret_cast<const char*>( buf.data() ), buf.size() );

  file.close();

  return !file.bad() || !file.fail();
}
