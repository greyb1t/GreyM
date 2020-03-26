#pragma once

class SafeInstructions {
 public:
  SafeInstructions( const size_t disasm_instruction_count );

  ~SafeInstructions();

  void SetInstructions( cs_insn* instructions );

  size_t GetDisassembledInstructionCount() const;

 private:
  cs_insn* instructions_;
  size_t disasm_instruction_count_;
};