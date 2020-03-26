#include "pch.h"
#include "safe_instruction.h"

SafeInstructions::SafeInstructions( const size_t disasm_instruction_count )
    : instructions_( nullptr ),
      disasm_instruction_count_( disasm_instruction_count ) {}

SafeInstructions::~SafeInstructions() {
  if ( instructions_ )
    cs_free( instructions_, disasm_instruction_count_ );
}

void SafeInstructions::SetInstructions( cs_insn* instructions ) {
  instructions_ = instructions;
}

size_t SafeInstructions::GetDisassembledInstructionCount() const {
  return disasm_instruction_count_;
}
