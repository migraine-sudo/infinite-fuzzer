#include <unicorn/unicorn.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>

#include <vector>
#include <algorithm>

// memory address where emulation starts
#define BASE 0x400000
#define STACK 0x0
#define STACK_SIZE 1024*1024
#define START 0x4004E0
#define END 0x400575

// list of instruction address to skip
int instructions_skip_list[] = {0x00000000004004EF, 0x00000000004004F6, 0x0000000000400502, 0x000000000040054F};

// Hook the code block
void hook_code(uc_engine* uc, uint64_t addr, uint32_t size, void* user_data)
{
    //printf("HOOK_CODE: 0x%" PRIx64 ", 0x%x\n", addr, size);
    std::vector<int> vec(instructions_skip_list, instructions_skip_list + sizeof(instructions_skip_list)/sizeof(int));
    auto it = find(vec.begin(),vec.end(),addr);
    
    // Skip the instruction
    if(it != vec.end()) 
    {
      long r_rip = addr + size ;
      uc_reg_write(uc, UC_X86_REG_RIP, &r_rip); 
    }

    // if "call put" , use cout to print
    else if(addr == 0x400560)
    {
      long r_rdi,r_rip=addr + size;
      uc_reg_write(uc, UC_X86_REG_RIP, &r_rip); 
      uc_reg_read(uc, UC_X86_REG_RDI, &r_rdi);
      std::cout << ">>> " << static_cast<char>(r_rdi) << std::endl;
    }
}

int main(int argc, char **argv, char **envp)
{
  uc_engine *uc;
  uc_err err;
  int size;                           // size of binary
  long r_rsp = STACK + STACK_SIZE -1 ; // RSP register
  char *bin_buffer ;                  // store the binary
  std::stringstream stringflow;       // init stringstream
  
  // load the Binary file
  std::ifstream in("test/fibonacci",std::ios::in | std::ios::binary);
  if(!in.is_open())
  {
    std::cout << "Error opening file";
    exit(1);
  }

  stringflow << in.rdbuf();
  std::string file_flow(stringflow.str() );

  size = file_flow.length();
  bin_buffer = new char[size];
  memcpy(bin_buffer,file_flow.c_str(),size-1);

  printf("Emulate amd64 code\n");

  // Initialize emulator in X86-32bit mode
  err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
  if (err != UC_ERR_OK) {
    printf("Failed on uc_open() with error returned: %u\n", err);
    return -1;
  }

  // map 2MB memory for this emulation
  uc_mem_map(uc, BASE, 2 * 1024 * 1024, UC_PROT_ALL);
  uc_mem_map(uc, STACK, STACK_SIZE , UC_PROT_ALL);

  // write machine code to be emulated to memory
  if (uc_mem_write(uc, BASE, bin_buffer, size - 1)) {
    printf("Failed to write emulation code to memory, quit!\n");
    return -1;
  }

  // initialize machine registers
  uc_reg_write(uc, UC_X86_REG_RSP, &r_rsp);
  
  // add hook code
  uc_hook code_hook;
  //uc_hook_add(uc, &code_hook, UC_HOOK_CODE, hook_code, NULL, 1, 0);
  err = uc_hook_add(uc, &code_hook, UC_HOOK_CODE, reinterpret_cast<void *>(hook_code), NULL, 1, 0);
  if(err)
    std::cout << "hook add error" << std::endl;

  // emulate code in infinite time & unlimited instructions
  err=uc_emu_start(uc, START, END , 0, 0);
  if (err) {
    printf("Failed on uc_emu_start() with error returned %u: %s\n",
      err, uc_strerror(err));
  }

  // now Emulation done
  printf("Emulation done. \n");

  uc_close(uc);

  return 0;
}