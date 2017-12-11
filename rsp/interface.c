//
// rsp/interface.c: RSP interface.
//
// CEN64: Cycle-Accurate Nintendo 64 Emulator.
// Copyright (C) 2015, Tyler J. Stachecki.
//
// This file is subject to the terms and conditions defined in
// 'LICENSE', which is part of this source code package.
//

#include "common.h"
#include "bus/address.h"
#include "bus/controller.h"
#include "rsp/cp0.h"
#include "rsp/cpu.h"
#include "rsp/interface.h"

#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

cen64_cold uint32_t si_crc32(const uint8_t *data, size_t size);

static char* lowercase_mnemonic(const char* x)
{
  static char buffer[17];
  int i = 0;
  do
  {
    buffer[i] = tolower(x[i]);
    i++;
  }
  while (i < 16 && x[i] != 0);
  buffer[i] = 0;
  return buffer;
}

// target = address of the instruction to go to (in words inside IMEM)
static bool compute_target(uint32_t word, uint32_t pc,
    const struct rsp_opcode* op, uint32_t* target)
{
  if (op->id != RSP_OPCODE_JR && op->id != RSP_OPCODE_JALR)
  {
    if (op->id == RSP_OPCODE_J || op->id == RSP_OPCODE_JAL)
    {
      *target = word & 0x3FF;
    }
    else
    {
      uint32_t ex = word & 0xFFFF;
      int16_t offset = (int16_t)ex;
      *target = pc + offset + 1; 
    }
    return *target < 1024;
  }
  return false;
}

static void dump_disasm(const uint32_t buffer[0x400],
    uint32_t start, uint32_t end)
{
  uint32_t length = end - start;
  uint32_t crc = si_crc32((uint8_t*)buffer, length);

  static char filename[256];
  snprintf(filename, 256, "ucode_%08x.asm", crc);
  FILE* f = fopen(filename, "r");
  if (f != NULL)
  {
    fclose(f);
    return;
  }

  fprintf(stderr, "Dumping %08x from %x (%d)\n", crc, start, length);

  // decode and build labels
  static const struct rsp_opcode* decoded[1024];
  static bool labels[1024];
  memset(labels, 0, sizeof(labels));
  for (uint32_t i = 0; i < 0x400; i++)
  {
    uint32_t word = buffer[i];
    decoded[i] = rsp_decode_instruction(word);
    if (decoded[i]->flags & OPCODE_INFO_BRANCH)
    {
      uint32_t target;
      if (compute_target(word, i, decoded[i], &target))
	labels[target] = true;
    }
  }

  f = fopen(filename, "w");
  fprintf(f, "// start=%Xh(%d) length=%d(%Xh)\n",
    start, start, length, length);

  // dump ops
  start = start / 4 - 0x400;
  end = end / 4 - 0x400;
  for (uint32_t i = 0; i < 0x400; i++)
  {
    if (i == start)
      fprintf(f, "start:\n");
    if (i == end)
      fprintf(f, "end:\n");

    if (labels[i])
      fprintf(f, "label_%x:\n", i);

    int line_len = 0;

    uint32_t word = buffer[i];
    if (word != 0)
    {
      const struct rsp_opcode* op = decoded[i];
      const char** table = (op->flags & OPCODE_INFO_VECTOR)
	? rsp_vector_opcode_mnemonics : rsp_opcode_mnemonics;
      line_len += fprintf(f, "\t%s", lowercase_mnemonic(table[op->id]));

      uint32_t rt = GET_RT(word); // starting bit 16
      uint32_t rs = GET_RS(word); // starting bit 21
      uint32_t rd = GET_RD(word); // starting bit 11
      uint32_t vd = GET_VD(word); // starting bit 6
      uint32_t el = GET_EL(word); // starting bit 7
      uint32_t e = GET_E(word); // starting bit 21

      if ((op->flags & OPCODE_INFO_VECTOR) == 0)
      {
	switch (op->id)
	{
	  case RSP_OPCODE_MFC0:
	  case RSP_OPCODE_MTC0:
	  {
	    static const char* cp0_ctrl_reg[] =
	    {
	      "DMA_CACHE", "DMA_DRAM", "DMA_READ_LENGTH", "DMA_WRITE_LENGTH",
	      "SP_STATUS", "DMA_FULL", "DMA_BUSY", "SP_RESERVED", "CMD_START",
	      "CMD_END", "CMD_CURRENT", "CMD_STATUS", "CMD_CLOCK", "CMD_BUSY",
	      "CMD_PIPE_BUSY", "CMD_TMEM_BUSY"
	    };
	    line_len += fprintf(f, " r%d, %s", rt, cp0_ctrl_reg[rd]);
	    break;
	  }

	  case RSP_OPCODE_CFC2:
	  case RSP_OPCODE_CTC2:
	  {
	    static const char* cp2_ctrl_reg[] = { "VCO", "VCC", "VCE" };
	    line_len += fprintf(f, " r%d, %s", rt, cp2_ctrl_reg[rd]);
	    break;
	  }

	  case RSP_OPCODE_MFC2:
	  case RSP_OPCODE_MTC2:
	  {
	    line_len += fprintf(f, " r%d, v%d[e%d]", rt, rd, el / 2);
	    break;
	  }

	  case RSP_OPCODE_LBV:
	  case RSP_OPCODE_LDV:
	  case RSP_OPCODE_LLV:
	  case RSP_OPCODE_LPV:
	  case RSP_OPCODE_LQV:
	  case RSP_OPCODE_LRV:
	  case RSP_OPCODE_LSV:
	  case RSP_OPCODE_LTV:
	  case RSP_OPCODE_LUV:
	  case RSP_OPCODE_SBV:
	  case RSP_OPCODE_SDV:
	  case RSP_OPCODE_SLV:
	  case RSP_OPCODE_SPV:
	  case RSP_OPCODE_SQV:
	  case RSP_OPCODE_SRV:
	  case RSP_OPCODE_SSV:
	  case RSP_OPCODE_STV:
	  case RSP_OPCODE_SUV:
	  case RSP_OPCODE_SWV:
	  {
	    int32_t ofs = word & 0x7F;
	    if (ofs >= 128)
	      ofs = 127 - ofs;
	    if (ofs < 0)
	      line_len += fprintf(f, " v%d[e%d], %d(r%d)", rt, el / 2, ofs, e);
	    else
	      line_len += fprintf(f, " v%d[e%d], $%x(r%d)", rt, el / 2, ofs, e);
	    break;
	  }

	  case RSP_OPCODE_LB:
	  case RSP_OPCODE_LBU:
	  case RSP_OPCODE_LH:
	  case RSP_OPCODE_LHU:
	  case RSP_OPCODE_LW:
	  case RSP_OPCODE_SB:
	  case RSP_OPCODE_SH:
	  case RSP_OPCODE_SW:
	  {
	    int16_t ofs = (int16_t)(word & 0xFFFF);
	    if (ofs < 0)
	      line_len += fprintf(f, " r%d, %d(r%d)", rt, ofs, rs);
	    else
	      line_len += fprintf(f, " r%d, $%x(r%d)", rt, ofs, rs);
	    break;
	  }

	  case RSP_OPCODE_LUI:
	  {
	    uint32_t imm = word & 0xFFFF;
	    line_len += fprintf(f, " r%d, %d", rt, imm);
	    break;
	  }

	  case RSP_OPCODE_ADDIU:
	  case RSP_OPCODE_ANDI:
	  case RSP_OPCODE_ORI:
	  case RSP_OPCODE_SLTI:
	  case RSP_OPCODE_SLTIU:
	  case RSP_OPCODE_XORI:
	  {
	    uint32_t imm = word & 0xFFFF;
	    line_len += fprintf(f, " r%d, r%d, $%X", rt, rs, imm);
	    break;
	  }

	  case RSP_OPCODE_ADDU:
	  case RSP_OPCODE_AND:
	  case RSP_OPCODE_NOR:
	  case RSP_OPCODE_OR:
	  case RSP_OPCODE_SLT:
	  case RSP_OPCODE_SLTU:
	  case RSP_OPCODE_SUBU:
	  case RSP_OPCODE_XOR:
	  {
	    line_len += fprintf(f, " r%d, r%d, r%d", rd, rs, rt);
	    break;
	  }

	  case RSP_OPCODE_SLLV:
	  case RSP_OPCODE_SRAV:
	  case RSP_OPCODE_SRLV:
	  {
	    line_len += fprintf(f, " r%d, r%d, r%d", rd, rt, rs);
	    break;
	  }

	  case RSP_OPCODE_JALR:
	  {
	    line_len += fprintf(f, " r%d, r%d", rd, rs);
	    break;
	  }

	  case RSP_OPCODE_JR:
	  {
	    line_len += fprintf(f, " r%d", rs);
	    break;
	  }

	  case RSP_OPCODE_SLL:
	  case RSP_OPCODE_SRA:
	  case RSP_OPCODE_SRL:
	  {
	    line_len += fprintf(f, " r%d, r%d, %d", rd, rt, vd);
	    break;
	  }

	  case RSP_OPCODE_BEQ:
	  case RSP_OPCODE_BNE:
	  {
	    line_len += fprintf(f, " r%d, r%d,", rs, rt);
	    break;
	  }

	  case RSP_OPCODE_BGEZ:
	  case RSP_OPCODE_BGEZAL:
	  case RSP_OPCODE_BGTZ:
	  case RSP_OPCODE_BLEZ:
	  case RSP_OPCODE_BLTZ:
	  case RSP_OPCODE_BLTZAL:
	  {
	    line_len += fprintf(f, " r%d,", rs);
	    break;
	  }
	}
      }
      else
      {
	switch (op->id)
	{
	  case RSP_OPCODE_VABS:
	  case RSP_OPCODE_VADD:
	  case RSP_OPCODE_VADDC: 
	  case RSP_OPCODE_VAND:
	  case RSP_OPCODE_VCH:
	  case RSP_OPCODE_VCL:
	  case RSP_OPCODE_VCR:
	  case RSP_OPCODE_VEQ:
	  case RSP_OPCODE_VGE:
	  case RSP_OPCODE_VLT:
	  case RSP_OPCODE_VMACF:
	  case RSP_OPCODE_VMACQ:
	  case RSP_OPCODE_VMACU:
	  case RSP_OPCODE_VMADH:
	  case RSP_OPCODE_VMADL:
	  case RSP_OPCODE_VMADM:
	  case RSP_OPCODE_VMADN:
	  case RSP_OPCODE_VMRG:
	  case RSP_OPCODE_VMUDH:
	  case RSP_OPCODE_VMUDL:
	  case RSP_OPCODE_VMUDM:
	  case RSP_OPCODE_VMUDN:
	  case RSP_OPCODE_VMULF:
	  case RSP_OPCODE_VMULQ:
	  case RSP_OPCODE_VMULU:
	  case RSP_OPCODE_VNAND:
	  case RSP_OPCODE_VNE:
	  case RSP_OPCODE_VNOR:
	  case RSP_OPCODE_VNULL:
	  case RSP_OPCODE_VNXOR:
	  case RSP_OPCODE_VOR:
	  case RSP_OPCODE_VRNDN:
	  case RSP_OPCODE_VRNDP:
	  case RSP_OPCODE_VSAR:
	  case RSP_OPCODE_VSUB:
	  case RSP_OPCODE_VSUBC:
	  case RSP_OPCODE_VXOR: 
	  {
	    line_len += fprintf(f, " v%d, v%d, v%d", vd, rd, rt);
	    if (e > 0)
	      line_len += fprintf(f, "[e%d]", e / 2);
	    break;
	  }

	  case RSP_OPCODE_VMOV:
	  case RSP_OPCODE_VRCP:
	  case RSP_OPCODE_VRCPH:
	  case RSP_OPCODE_VRCPL:
	  case RSP_OPCODE_VRSQ:
	  case RSP_OPCODE_VRSQH:
	  case RSP_OPCODE_VRSQL:
	  {
	    line_len += fprintf(f, " v%d[e%d], v%d[e%d]", vd, rd, rt, e / 2);
	    break;
	  }
	}
      }

      if (decoded[i]->flags & OPCODE_INFO_BRANCH)
      {
	uint32_t target;
	if (compute_target(word, i, decoded[i], &target))
	  line_len += fprintf(f, " label_%x", target);
      }
    }
    else
    {
      line_len += fprintf(f, "\tnop");
    }

    for (int i = 32 - line_len; i > 0; i--)
      fputc(' ', f);
    fprintf(f, "// %02X %02X %02X %02X",
	(word >> 24) & 0xFF, (word >> 16) & 0xFF,
	(word >> 8) & 0xFF, word & 0xFF);

    fputc('\n', f);
  }
  
  if (end == 0x400)
    fprintf(f, "end:\n");

  fclose(f);
}

// DMA into the RSP's memory space.
void rsp_dma_read(struct rsp *rsp) {
  uint32_t length = (rsp->regs[RSP_CP0_REGISTER_DMA_READ_LENGTH] & 0xFFF) + 1;
  uint32_t skip = rsp->regs[RSP_CP0_REGISTER_DMA_READ_LENGTH] >> 20 & 0xFFF;
  unsigned count = rsp->regs[RSP_CP0_REGISTER_DMA_READ_LENGTH] >> 12 & 0xFF;
  unsigned j, i = 0;

  // Force alignment.
  length = (length + 0x7) & ~0x7;
  rsp->regs[RSP_CP0_REGISTER_DMA_CACHE] &= ~0x3;
  rsp->regs[RSP_CP0_REGISTER_DMA_DRAM] &= ~0x7;

  // Check length.
  if (((rsp->regs[RSP_CP0_REGISTER_DMA_CACHE] & 0xFFF) + length) > 0x1000)
    length = 0x1000 - (rsp->regs[RSP_CP0_REGISTER_DMA_CACHE] & 0xFFF);

  uint32_t cache_start = rsp->regs[RSP_CP0_REGISTER_DMA_CACHE] & 0x1FFC;

  do {
    uint32_t source = rsp->regs[RSP_CP0_REGISTER_DMA_DRAM] & 0x7FFFFC;
    uint32_t dest = rsp->regs[RSP_CP0_REGISTER_DMA_CACHE] & 0x1FFC;
    j = 0;

    do {
      uint32_t source_addr = (source + j) & 0x7FFFFC;
      uint32_t dest_addr = (dest + j) & 0x1FFC;
      uint32_t word;

      bus_read_word(rsp, source_addr, &word);

      // Update opcode cache.
      if (dest_addr & 0x1000) {
        rsp->opcode_cache[(dest_addr - 0x1000) >> 2] =
          *rsp_decode_instruction(word);
      } else {
        word = byteswap_32(word);
      }

      memcpy(rsp->mem + dest_addr, &word, sizeof(word));
      j += 4;
    } while (j < length);

    rsp->regs[RSP_CP0_REGISTER_DMA_DRAM] += length + skip;
    rsp->regs[RSP_CP0_REGISTER_DMA_CACHE] += length;
  } while(++i <= count);

  if (cache_start & 0x1000)
  {
    dump_disasm((const uint32_t*)(rsp->mem + 0x1000), cache_start,
	cache_start + length * (count + 1));
  }
}

// DMA from the RSP's memory space.
void rsp_dma_write(struct rsp *rsp) {
  uint32_t length = (rsp->regs[RSP_CP0_REGISTER_DMA_WRITE_LENGTH] & 0xFFF) + 1;
  uint32_t skip = rsp->regs[RSP_CP0_REGISTER_DMA_WRITE_LENGTH] >> 20 & 0xFFF;
  unsigned count = rsp->regs[RSP_CP0_REGISTER_DMA_WRITE_LENGTH] >> 12 & 0xFF;
  unsigned j, i = 0;

  // Force alignment.
  length = (length + 0x7) & ~0x7;
  rsp->regs[RSP_CP0_REGISTER_DMA_CACHE] &= ~0x3;
  rsp->regs[RSP_CP0_REGISTER_DMA_DRAM] &= ~0x7;

  // Check length.
  if (((rsp->regs[RSP_CP0_REGISTER_DMA_CACHE] & 0xFFF) + length) > 0x1000)
    length = 0x1000 - (rsp->regs[RSP_CP0_REGISTER_DMA_CACHE] & 0xFFF);

  do {
    uint32_t dest = rsp->regs[RSP_CP0_REGISTER_DMA_DRAM] & 0x7FFFFC;
    uint32_t source = rsp->regs[RSP_CP0_REGISTER_DMA_CACHE] & 0x1FFC;
    j = 0;

    do {
      uint32_t source_addr = (source + j) & 0x1FFC;
      uint32_t dest_addr = (dest + j) & 0x7FFFFC;
      uint32_t word;

      memcpy(&word, rsp->mem + source_addr, sizeof(word));

      if (!(source_addr & 0x1000))
        word = byteswap_32(word);

      bus_write_word(rsp, dest_addr, word, ~0U);
      j += 4;
    } while (j < length);

    rsp->regs[RSP_CP0_REGISTER_DMA_CACHE] += length;
    rsp->regs[RSP_CP0_REGISTER_DMA_DRAM] += length + skip;
  } while (++i <= count);
}

// Reads a word from the SP memory MMIO register space.
int read_sp_mem(void *opaque, uint32_t address, uint32_t *word) {
  struct rsp *rsp = (struct rsp *) opaque;
  unsigned offset = address & 0x1FFC;

  memcpy(word, rsp->mem + offset, sizeof(*word));

  if (!(offset & 0x1000))
    *word = byteswap_32(*word);

  return 0;
}

// Reads a word from the SP MMIO register space.
int read_sp_regs(void *opaque, uint32_t address, uint32_t *word) {
  struct rsp *rsp = (struct rsp *) opaque;
  uint32_t offset = address - SP_REGS_BASE_ADDRESS;
  enum sp_register reg = (offset >> 2);

  *word = rsp_read_cp0_reg(rsp, reg);
  debug_mmio_read(sp, sp_register_mnemonics[reg], *word);
  return 0;
}

// Reads a word from the (high) SP MMIO register space.
int read_sp_regs2(void *opaque, uint32_t address, uint32_t *word) {
  struct rsp *rsp = (struct rsp *) opaque;
  uint32_t offset = address - SP_REGS2_BASE_ADDRESS;
  enum sp_register reg = (offset >> 2) + SP_PC_REG;

  if (reg == SP_PC_REG)
    *word = rsp->pipeline.dfwb_latch.common.pc;

  else
    abort();

  debug_mmio_read(sp, sp_register_mnemonics[reg], *word);
  return 0;
}

// Writes a word to the SP memory MMIO register space.
int write_sp_mem(void *opaque, uint32_t address, uint32_t word, uint32_t dqm) {
  struct rsp *rsp = (struct rsp *) opaque;
  unsigned offset = address & 0x1FFC;
  uint32_t orig_word;

  memcpy(&orig_word, rsp->mem + offset, sizeof(orig_word));
  orig_word = byteswap_32(orig_word) & ~dqm;
  word = orig_word | word;

  // Update opcode cache.
  if (offset & 0x1000) {
    rsp->opcode_cache[(offset - 0x1000) >> 2] = *rsp_decode_instruction(word);
  } else {
    word = byteswap_32(word);
  }

  memcpy(rsp->mem + offset, &word, sizeof(word));
  return 0;
}

// Writes a word to the SP MMIO register space.
int write_sp_regs(void *opaque, uint32_t address, uint32_t word, uint32_t dqm) {
  struct rsp *rsp = (struct rsp *) opaque;
  uint32_t offset = address - SP_REGS_BASE_ADDRESS;
  enum sp_register reg = (offset >> 2);

  debug_mmio_write(sp, sp_register_mnemonics[reg], word, dqm);
  rsp_write_cp0_reg(rsp, reg, word);

  if (reg + SP_REGISTER_OFFSET == RSP_CP0_REGISTER_SP_STATUS
      && (word & SP_STATUS_HALT))
  {
    dump_disasm((const uint32_t*)(rsp->mem + 0x1000), 0x1000, 0x2000);
  }


  return 0;
}

// Writes a word to the (high) SP MMIO register space.
int write_sp_regs2(void *opaque, uint32_t address, uint32_t word, uint32_t dqm) {
  struct rsp *rsp = (struct rsp *) opaque;
  uint32_t offset = address - SP_REGS2_BASE_ADDRESS;
  enum sp_register reg = (offset >> 2) + SP_PC_REG;

  debug_mmio_write(sp, sp_register_mnemonics[reg], word, dqm);

  if (reg == SP_PC_REG)
    rsp->pipeline.ifrd_latch.pc = word & 0xFFC;

  else
    abort();

  return 0;
}


