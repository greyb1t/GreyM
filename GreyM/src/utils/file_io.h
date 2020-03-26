#pragma once

namespace fileio {

// ReadFileData returns an empty vector if failed
std::vector<uint8_t> ReadBinaryFile( const std::wstring& filename );

bool WriteFileData( const std::wstring& filename,
                    const std::vector<uint8_t>& buf );

}  // namespace fileio