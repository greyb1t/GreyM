#pragma once
#include <cstdint>

#define VM_LOADER_SECTION_NAME ( ".dick" )
#define VM_CODE_SECTION_NAME ".dick2"

#define VM_FUNCTIONS_SECTION_NAME "vmfun"
#define VM_INTERPRETER_STACK_ALLOCATION_SIZE_BYTES 200

#define ENABLE_TLS_CALLBACKS TRUE

#define DLL 0

// TODO: Read the default pe base address from the header instead of hard-coding
#ifdef _WIN64
#if DLL
constexpr uintptr_t DEFAULT_PE_BASE_ADDRESS = 0x180000000;
#else
constexpr uintptr_t DEFAULT_PE_BASE_ADDRESS = 0x140000000;
#endif
#else
#if DLL
constexpr uintptr_t DEFAULT_PE_BASE_ADDRESS = 0x10000000;
#else
constexpr uintptr_t DEFAULT_PE_BASE_ADDRESS = 0x400000;
#endif
#endif

// The data at the beginning of the vm code section
struct VmCodeSectionData {
  // A bunch of zeroed data for the import data directory to point to
  uint8_t zeroed_data_for_import_directory[ sizeof( IMAGE_IMPORT_DESCRIPTOR ) ];

  char friendly_message[ 80 ];

  IMAGE_DATA_DIRECTORY import_data_directory;

  // How many imports does the PE have
  uint32_t import_count;

#ifdef _WIN64
  uint8_t import_redirect_shellcode[ 27 ] = {
    // push rax
    0x50,

    // pushfq
    0x9C,

    // push rax
    0x50,

    // movabs rax, 64 bit value
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // xor rax, 0
    0x48, 0x35, 0x00, 0x00, 0x00, 0x00,

    // mov [rsp + 0x10], rax
    0x48, 0x89, 0x44, 0x24, 0x10,

    // pop rax
    0x58,

    // popfq
    0x9D,
    // ret
    0xC3
  };
#else
  /*
    // Allocate space for call destination
	  // Why push eax? Because we cannot use sub because it changes eflags before we saved them
	  push eax

	  // Save eflags because we change them due to usage of xor
	  pushfd

	  // Save eax to use it
	  push eax
	
	  mov eax, 0x1337 (encrypted addr)
	
	  xor eax, 0xDEAD (xor with key)
	
	  // Set the allocated stack to the call destination
	  mov [esp + (8 or 16)], eax
	
	  // Restore the saved eax
	  pop eax
	
	  // Restore the saved eflags
	  popfd
	
	  // Jump to call destination
	  ret
  */
  uint8_t import_redirect_shellcode[ 20 ] = {
    // push eax
    0x50,

    // pushfd
    0x9C,

    // push eax
    0x50,

    // mov eax, 0x1337
    0xB8, 0x37, 0x13, 0x00, 0x00,

    // xor eax, 0
    0x35, 0x00, 0x00, 0x00, 0x00,

    // mov [esp + 8], eax
    0x89, 0x44, 0x24, 0x08,

    // pop eax
    0x58,

    // popfd
    0x9D,
    // ret
    0xC3
  };
#endif
};

enum class VmOpcodes : uint32_t {
  // mov reg, 0x0
  MOV_REGISTER_IMMEDIATE = 0x74F91AA0,

  // mov reg, reg
  MOV_REGISTER_REGISTER = 0xB9C115AB,

  // mov eax, dword ptr [0x7d6610]
  MOV_REGISTER_MEMORY_IMMEDIATE = 0x19BFE12B,

  // mov ecx, dword ptr [eax + 0x84]
  MOV_REGISTER_MEMORY_REG_OFFSET = 0x4278BEA1,

  // mov [reg + 0x0], reg
  MOV_MEMORY_REG_OFFSET_REG = 0x1927BA1F,

  // mov [reg + 0x0], imm
  MOV_MEMORY_REG_OFFSET_IMM = 0x0F0B255A,

  SUB_REGISTER_IMMEDIATE = 0xFE126DF1,
  SUB_REGISTER_MEMORY_REG_OFFSET = 0x200B01B0,
  CALL_IMMEDIATE = 0x437BDFA1,
  CALL_MEMORY = 0xB2988BE1,

  // call qword ptr [rip + 0x25bec] (default on x64 call for a winapi call)
  CALL_MEMORY_RIP_RELATIVE = 0xCBBB223A,

  // lea r8, ds:[0x00007FF757401AE8]
  LEA_REG_MEMORY_IMMEDIATE_RIP_RELATIVE = 0xAD5F1BB1,

  PUSH_IMM = 0x31CBE5B1,
  PUSH_REGISTER_MEMORY_REG_OFFSET = 0x0BBF011A,  // push dword ptr [eax + 0x9c]

  // jmp imm
  JMP_IMM = 0xCA38B49B,

  NO_OPCODE = 0x0
};

struct VmRegister {
  uint32_t register_offset;
  uint32_t register_size;
};

using XMM = uint64_t[ 2 ];

struct VmRegisters {
#if _WIN64
  uintptr_t r15;
  uintptr_t r14;
  uintptr_t r13;
  uintptr_t r12;
  uintptr_t r11;
  uintptr_t r10;
  uintptr_t r9;
  uintptr_t r8;

  XMM xmm0;
  XMM xmm1;
  XMM xmm2;
  XMM xmm3;
  XMM xmm4;
  XMM xmm5;
  XMM xmm6;
  XMM xmm7;
#endif

  uintptr_t edi;
  uintptr_t esi;
  uintptr_t ebp;
  uintptr_t edx;
  uintptr_t ecx;
  uintptr_t ebx;
  uintptr_t eax;

  uintptr_t pushfd;
};

struct VmContext {
  // esp is in here because it is added straight after the
  // pushes were allocated in loader code
  uintptr_t esp;

  // store registers after the virtual stack otherwise we'll
  // overwrite the pointer when we push on the virtual stack
  VmRegisters* registers;
};

typedef struct _UNICODE_STRING {
  WORD Length;
  WORD MaximumLength;
  WORD* Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
  ULONG Flags;
  WORD LoadCount;
  WORD TlsIndex;
  union {
    LIST_ENTRY HashLinks;
    struct {
      PVOID SectionPointer;
      ULONG CheckSum;
    };
  };
  union {
    ULONG TimeDateStamp;
    PVOID LoadedImports;
  };
  _ACTIVATION_CONTEXT* EntryPointActivationContext;
  PVOID PatchInformation;
  LIST_ENTRY ForwarderLinks;
  LIST_ENTRY ServiceTagLinks;
  LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
  ULONG Length;
  UCHAR Initialized;
  PVOID SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
  PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

struct PEB {
  BOOLEAN InheritedAddressSpace;
  BOOLEAN ReadImageFileExecOptions;
  BOOLEAN BeingDebugged;
  union {
    BOOLEAN BitField;
    struct {
      BOOLEAN ImageUsesLargePages : 1;
      BOOLEAN IsProtectedProcess : 1;
      BOOLEAN IsLegacyProcess : 1;
      BOOLEAN IsImageDynamicallyRelocated : 1;
      BOOLEAN SkipPatchingUser32Forwarders : 1;
      BOOLEAN IsPackagedProcess : 1;
      BOOLEAN IsAppContainer : 1;
      BOOLEAN SpareBits : 1;
    };
  };
  HANDLE Mutant;
  PVOID ImageBaseAddress;
  PPEB_LDR_DATA Ldr;
};