#include "pch.h"

#include "pe/portable_executable.h"
#include "utils/file_io.h"
#include "protector.h"

#include "utils/console_log.h"

#pragma comment( lib, "capstone.lib" )

int main( int argc, char* argv[] ) {
  try {
    srand( static_cast<unsigned int>( time( 0 ) ) );

    const std::string current_dir = argv[ 0 ];

    const std::string parent_dir =
        current_dir.substr( 0, current_dir.find_last_of( '\\' ) + 1 );

    const std::wstring parent_dir_wide =
        std::wstring( parent_dir.begin(), parent_dir.end() );

    const auto target_file_data = fileio::ReadBinaryFile(
        parent_dir_wide + TEXT( "Test Executable.exe" ) );

    if ( target_file_data.empty() ) {
      console::Print( "Unable to open the target file." );
      std::cin.get();
      return -1;
    }

    auto target_pe = pe::Open( target_file_data );

    if ( target_pe.IsValid() ) {
      const auto new_protected_pe = protector::Protect( target_pe );
      if ( !fileio::WriteFileData(
               parent_dir_wide + TEXT( "Test Executable Out.exe" ),
               new_protected_pe.GetPeData() ) ) {
        console::Print( "Unable to write output file" );
      }
    } else {
      console::Print( "The PE is not valid." );
      std::cin.get();
      return -1;
    }

  } catch ( std::exception ex ) {
    console::Print( ex.what() );
  }

  std::cin.get();

  return 0;
}