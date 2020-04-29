#pragma once

#include "../../Interpreter/src/main.h"

class Shellcode;

const std::wstring VmOpcodeEncryptionKeyVariable =
    TEXT( "VmOpcodeEncryptionKey" );

const std::wstring VmCodeAddrVariable = TEXT( "VmCodeAddr" );

const std::wstring ImageBaseVariable = TEXT( "ImageBase" );

const std::wstring OrigAddrVariable = TEXT( "OrigAddr" );

const std::wstring VmCoreFunctionVariable = TEXT( "VmCoreFunction" );

namespace virtualizer {

bool IsVirtualizeable( const cs_insn& instruction, const VmOpcodes vm_opcode );
VmOpcodes GetVmOpcode( const cs_insn& instruction );

Shellcode CreateVirtualizedShellcode(
    const cs_insn& instruction,
    const VmOpcodes vm_opcode,
    const uint32_t vm_opcode_encyption_key,
    const std::vector<uintptr_t>& relocations_within_instruction, const uintptr_t default_image_base );

Shellcode GetLoaderShellcodeForVirtualizedCode( const cs_insn& instruction,
                                                const VmOpcodes vm_opcode,
                                                const uintptr_t image_base );

}  // namespace virtualizer