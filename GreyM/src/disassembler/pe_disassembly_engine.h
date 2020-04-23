#pragma once

#include "../pe/portable_executable.h"

struct SmallInstructionData {
 public:
  SmallInstructionData( uint16_t instruction_size, const uint8_t* code )
      : instruction_size_( instruction_size ), code_ptr_( code ) {}

  uint16_t instruction_size_;
  const uint8_t* code_ptr_;
};

using tDisassemblingCallback = void ( * )( const cs_insn& instruction,
                                           const uint8_t* code,
                                           void* data );

using tDisassemblingInvalidInstructionCallback =
    void ( * )( const uint64_t address,
                const SmallInstructionData ins_data,
                void* data );

enum class DisassemblyAction {
  // Disassemble the next instruction
  NextInstruction,

  // Continue disassembling on a address from the saved stack
  NextDisassemblyPoint,
};

struct DisassemblyPoint {
  uintptr_t rva;
  const uint8_t* code;

  bool operator<( const DisassemblyPoint& rhs ) const {
    return rva < rhs.rva;
  }
};

struct AddressRange {
  uintptr_t begin_address;
  uintptr_t end_address;
};

class PeDisassemblyEngine {
 public:
  PeDisassemblyEngine( const PortableExecutable pe );

  void DisassembleFromEntrypoint(
      const tDisassemblingCallback& disassembly_callback,
      const tDisassemblingInvalidInstructionCallback&
          invalid_instruction_callback,
      void* data );

  void AddDisassemblyPoint( const DisassemblyPoint& disasm_point );

  void BeginDisassembling( const tDisassemblingCallback& disassembly_callback,
                           const tDisassemblingInvalidInstructionCallback&
                               invalid_instruction_callback,
                           void* data );

  void SetDisassemblyPoint( const DisassemblyPoint& disasm_point,
                            const size_t disasm_buffer_size );

 private:
  // Only used for internal use for the invalid instruction checking part
  template <typename TFunc = tDisassemblingCallback,
            typename TFunc2 = tDisassemblingInvalidInstructionCallback>
  void BeginDisassemblingMinimal( const TFunc& disassembly_callback,
                                  const TFunc2& invalid_instruction_callback );

  bool IsAddressWithinDataSectionOfCode( const uint64_t address );

  bool IsFunction( const DisassemblyPoint& disasm_point );
  bool IsFunctionX86( const DisassemblyPoint& disasm_point,
                      int recursion_counter );
  bool IsFunctionX64( const DisassemblyPoint& disasm_point );
  bool IsFunctionX64Prolog( const DisassemblyPoint& disasm_point );

  DisassemblyAction ParseInstruction( const cs_insn& instruction );

  bool IsVTableOrFunction( const cs_x86_op& operand1,
                           const cs_x86_op& operand2 );

  bool IsJumpTable( const cs_insn& instruction,
                    const uint8_t* code,
                    const uint64_t rva );
  bool IsJumpTableX86( const cs_insn& instruction, const cs_x86_op& operand );
  bool IsJumpTableX64( const cs_insn& instruction,
                       const cs_x86_op& operand1,
                       const cs_x86_op& operand2,
                       const uint8_t* code,
                       const uint64_t rva );

  DisassemblyPoint GetOperandDestinationValueDisassasemblyPoint(
      const cs_insn& instruction,
      const uint8_t* instruction_code_ptr,
      const uintptr_t rva );
  void ParseJumpTable( const cs_insn& instruction, const cs_x86_op& operand );

  // ContinueFromRedirectionInstructions returns false if no more instructions
  // are found
  bool ContinueFromDisassemblyPoints();

  // Finds all the virtual functions in the rdata section
  void ParseRDataSection();

  // Adds each of the TLS callback to the disassembly points
  void ParseTlsCallbacks();

 private:
  const PortableExecutable pe_;

  csh disassembler_handle_;

  const uint8_t* code_;
  uint32_t current_code_index_;

  // is the code of the current instruction because capstone modifies code_
  // itself
  const uint8_t* current_instruction_code_;

  size_t code_buf_size_;
  uint64_t address_;
  std::vector<DisassemblyPoint> disassembly_points_;

  // keeps track of each disassembly point that was added to avoid duplicates
  std::unordered_set<uint64_t> disassembly_points_cache_;

  // keeps track of all disassembled instructions to avoid disassembling them
  // again
  // first: address, second: instruction size
  std::unordered_map<uintptr_t, SmallInstructionData>
      disassembled_instructions_;

  // represents an area/range that is data and not code
  // example: jump table, that is data and not code
  std::vector<AddressRange> data_ranges_;

  const uintptr_t pe_image_base_;

  const SectionHeaders pe_section_headers_;
  const IMAGE_SECTION_HEADER* pe_text_section_header_;
};

template <typename TFunc, typename TFunc2>
void PeDisassemblyEngine::BeginDisassemblingMinimal(
    const TFunc& disassembly_callback,
    const TFunc2& invalid_instruction_callback ) {
  bool finished = false;

  // allocate memory for one instruction and use this memory for all instruction
  // to increate performance
  cs_insn* instruction = cs_malloc( disassembler_handle_ );

  while ( !finished ) {
    // are we outside the buffer?
    if ( ( code_buf_size_ - current_code_index_ ) <= 0 ) {
      // try to continue from the saved disassembly points
      if ( !ContinueFromDisassemblyPoints() ) {
        finished = true;
        break;
      }
    }

    // save the code pointer because capstone modifies it to next instruction
    // when disassembling an instruction
    current_instruction_code_ = code_;

    if ( !cs_disasm_iter( disassembler_handle_, &code_, &code_buf_size_,
                          &address_, instruction ) ) {
      // failed to disassemble instruction
      // stop disassembly and continue on another address on the stack / set
      // this usually means that we've reached an invalid instruction, meaning
      // parsing of the instruction flow has been incorrect
      // assert( false );
      // continue disassembling instructions from the saved redirection
      // instructions

      if ( !ContinueFromDisassemblyPoints() ) {
        finished = true;
        break;
      }

      continue;
    }

    current_code_index_ += instruction->size;

    // try virtualize it
    // parse it to further see if should continue disassembly
    disassembly_callback( *instruction, current_instruction_code_ );

    const auto next_disasm_action = ParseInstruction( *instruction );

    // returns the next instruction to disassemble
    switch ( next_disasm_action ) {
      case DisassemblyAction::NextInstruction: {
        // we do not need to change the code or address values because capstone
        // does it for us
      } break;

      case DisassemblyAction::NextDisassemblyPoint: {
        if ( !ContinueFromDisassemblyPoints() ) {
          finished = true;
          break;
        }
      } break;
      default:
        assert( false );
        break;
    }
  }
}