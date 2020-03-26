#pragma once

class PortableExecutable;

namespace rtti_obfuscator {

// Obfuscates the runtime type information information
void ObfuscateRTTI( PortableExecutable* pe );

}  // namespace rtti_obfuscator