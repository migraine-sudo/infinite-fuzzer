#include <unicorn/unicorn.h>

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>

#include <vector>
#include <algorithm>

#define BASE 0x400000
#define STACK 0x0
#define STACK_SIZE 1024*100
#define START 0x401100
#define END 0x40117C
#define DATA 0x4000
#define NEXT 0x500
#define PCS_N (1 << 12)

bool LLVMFuzzerInit(uint8_t *data1, size_t size, uint8_t *data2);


extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
    //VulnerableFunctionx(data,size,data);
    LLVMFuzzerInit(data,size,data);
    return 0;
}

__attribute__((section("__libfuzzer_extra_counters")))
uint8_t Counters[PCS_N];

size_t global_size1;

// Hook the code (for crash check)
void hook_code(uc_engine* uc, uint64_t addr, uint32_t size, void* user_data)
{
    char canary1,canary2;
    uc_mem_read(uc ,DATA+global_size1, &canary1, 1);
    uc_mem_read(uc ,DATA+NEXT+global_size1, &canary2, 1);
    //printf("canary=0x%x ",canary);
    if(canary1!='X' || canary2 != 'Y')
    {
      //printf("wrong canary=%d || %d ",canary1, canary2);
      fprintf(stderr, "========= ERROR:InfiniteSanitizer: stack overflow on address 0x%lx at pc 0x%lx bp  sp  \n",(DATA+global_size1),addr);
      abort();
    }

    //printf("HOOK_CODE: 0x%" PRIx64 ", 0x%x\n", addr, size);
    /*
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
    */
}

// Hook the block (for code coverage)
void hook_block(uc_engine* uc, uint64_t addr, uint32_t size, void* user_data)
{
    //printf("HOOK_BLOCK: 0x%" PRIx64 ", 0x%x\n", addr, size);
    Counters[addr]++;
}


bool LLVMFuzzerInit(uint8_t *data1, size_t size1, uint8_t *data2)
{
    uc_engine *uc;
    uc_err err;
    int size;                             // size of binary
    long r_rsp = STACK + STACK_SIZE -1 ;  // RSP register
    auto r_rdi = data1 ;                   // ARG register
    auto r_rdx = data2 ;
    auto r_rsi = size1 ;
    global_size1 =size1;
    char *bin_buffer ;                    // store the binary
    std::stringstream stringflow;         // init stringstream

    std::ifstream in("vuln.so",std::ios::in | std::ios::binary);
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

  //printf("Emulate amd64 code\n");

  // Initialize emulator in X86-32bit mode
  err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
  if (err != UC_ERR_OK) {
    printf("Failed on uc_open() with error returned: %u\n", err);
    return -1;
  }

  // map 2MB memory for this emulation
  uc_mem_map(uc, BASE, 2 * 1024 * 1024, UC_PROT_ALL);
  uc_mem_map(uc, STACK, STACK_SIZE , UC_PROT_ALL);
  uc_mem_map(uc, DATA, size1 , UC_PROT_ALL);
  uc_mem_map(uc, DATA+NEXT, size1 , UC_PROT_ALL);

  // write machine code to be emulated to memory
  if (uc_mem_write(uc, BASE, bin_buffer, size - 1)) {
    printf("Failed to write emulation code to memory, quit!\n");
    return -1;
  }
  //printf("rsi=%lu\n",r_rsi);
  //printf("*rdi=%s",r_rdi);
  uc_mem_write(uc, DATA, r_rdi, size1 - 1); 
  uc_mem_write(uc, DATA+NEXT, r_rdx, size1 - 1); 
  
  //test
  char canary='X';
  uc_mem_write(uc, DATA+size1, &canary, 1);
  canary='Y';
  uc_mem_write(uc, DATA+NEXT+size1, &canary, 1);
  //uint8_t data[size1-1];
  //uc_mem_read(uc, DATA , data, size1 -1);
  //printf("size=%zu,data=%s",size1,data);

  // store the dynamic data（Warning）
  auto r_rdi_mem = (long)DATA;
  auto r_rdx_mem = (long)DATA+NEXT;

  //printf ("rdi=%ld\n",r_rdi_mem);
  //printf ("rdx=%ld\n",r_rdx_mem);
  //std::cout << "rdi=" << r_rdi_mem << std::endl;
  // initialize machine registers
  uc_reg_write(uc, UC_X86_REG_RSP, &r_rsp);
  uc_reg_write(uc, UC_X86_REG_RDI, &r_rdi_mem);
  uc_reg_write(uc, UC_X86_REG_RSI, &r_rsi);
  uc_reg_write(uc, UC_X86_REG_RDX, &r_rdx_mem);

  //  check memory and register
  long rdi,rdx;
  uint8_t byte[size1];
  uc_reg_read(uc ,UC_X86_REG_RDI,&rdi);
  uc_reg_read(uc ,UC_X86_REG_RDX,&rdx);
  //printf("size=%zu,rdi=0x%lx,rdx=0x%lx\n",size1,rdi,rdx);
  uc_mem_read(uc ,rdi,byte,size1-1);
  //printf("byts=%s",byte);
  
  // add hook code
  uc_hook code_hook,block_hook;
  err = uc_hook_add(uc, &code_hook, UC_HOOK_CODE, reinterpret_cast<void *>(hook_code), NULL, 1, 0);
  err = uc_hook_add(uc, &block_hook, UC_HOOK_BLOCK, reinterpret_cast<void *>(hook_block), NULL, 1, 0);
  if(err)
    std::cout << "hook add error" << std::endl;


  // emulate code in infinite time & unlimited instructions
  err=uc_emu_start(uc, START, END , 0, 0);
  if (err) {
    printf("Failed on uc_emu_start() with error returned %u: %s\n",
      err, uc_strerror(err));
      //if(err != 6) // ignore read error
        abort();
  }

  // now Emulation done
  //printf("Emulation done. \n");
  delete[] bin_buffer;
  uc_close(uc);
  return true;
}