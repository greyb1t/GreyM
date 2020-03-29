#pragma once

#define VM_LOADER_SECTION_NAME (".dick")
#define VM_CODE_SECTION_NAME (".dick2")

class PortableExecutable;

namespace protector {

PortableExecutable Protect( const PortableExecutable pe );

}  // namespace protector
