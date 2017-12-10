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
static bool compute_target(uint32_t start, uint32_t word, uint32_t pc,
    const struct rsp_opcode* op, uint32_t* target)
{
  if (op->id != RSP_OPCODE_JR && op->id != RSP_OPCODE_JALR)
  {
    if (op->id == RSP_OPCODE_J || op->id == RSP_OPCODE_JAL)
    {
      *target = (word & 0x3FF) - (start - 0x1000) / 4;
    }
    else
    {
      uint32_t ex = word & 0xFFFF;
      int16_t offset = (int16_t)ex;
      *target = pc + offset + 1; 
    }
    return true;
  }
  return false;
}

static void dump_disasm(const uint32_t* buffer, uint32_t length,
    uint32_t start_addr)
{
  uint32_t crc = si_crc32((uint8_t*)buffer, length);

  static char filename[256];
  snprintf(filename, 256, "ucode_%08x.asm", crc);
  FILE* f = fopen(filename, "r");
  if (f != NULL)
  {
    fclose(f);
    return;
  }

  fprintf(stderr, "Dumping %08x from %x (%d)\n", crc, start_addr, length);

  length /= 4;

  // decode and build labels
  static const struct rsp_opcode* decoded[1024];
  static bool labels[1024];
  memset(labels, 0, sizeof(labels));
  for (uint32_t i = 0; i < length; i++)
  {
    uint32_t word = buffer[i];
    decoded[i] = rsp_decode_instruction(word);
    if (decoded[i]->flags & OPCODE_INFO_BRANCH)
    {
      uint32_t target;
      if (compute_target(start_addr, word, i, decoded[i], &target)
	  && target < 1024)
	labels[target] = true;
    }
  }

  // dump ops
  f = fopen(filename, "w");
  fprintf(f, "; start=%Xh(%d) length=%d(%Xh)\n",
    start_addr, start_addr, length, length);
  for (uint32_t i = 0; i < length; i++)
  {
    if (labels[i])
      fprintf(f, "label_%X:\n", i);

    int line_len = 0;

    uint32_t word = buffer[i];
    if (word != 0)
    {
      const struct rsp_opcode* op = decoded[i];
      const char** table = (op->flags & OPCODE_INFO_VECTOR)
	? rsp_vector_opcode_mnemonics : rsp_opcode_mnemonics;
      fprintf(f, "\t%s", lowercase_mnemonic(table[op->id]));
      line_len += 8 + strlen(table[op->id]);

      uint32_t rt = GET_RT(word); // starting bit 16
      uint32_t rs = GET_RS(word); // starting bit 21
      uint32_t rd = GET_RD(word); // starting bit 11
      uint32_t vd = GET_VD(word); // starting bit 6
      uint32_t el = GET_EL(word); // starting bit 7
      uint32_t e = GET_E(word); // starting bit 21

      if (op->id == RSP_OPCODE_MFC0 || op->id == RSP_OPCODE_MTC0)
      {
	fprintf(f, " r%d, c%d", rt, rd);
	line_len += 7;
	if (rt > 10) line_len++;
	if (rd > 10) line_len++;
      }
      else if (op->id == RSP_OPCODE_MFC2 || op->id == RSP_OPCODE_MTC2)
      {
	fprintf(f, " r%d, v%d[e%d]", rt, rd, el / 2);
	line_len += 11;
	if (rt > 10) line_len++;
	if (rd > 10) line_len++;
	if (el > 10) line_len++;
      }
      else if (op->flags & OPCODE_INFO_VECTOR)
      {
	switch (op->id)
	{
	  case RSP_OPCODE_VNOP:
	    break;

	  case RSP_OPCODE_VMOV:
	  case RSP_OPCODE_VRCP:
	  case RSP_OPCODE_VRCPH:
	  case RSP_OPCODE_VRCPL:
	  case RSP_OPCODE_VRSQ:
	  case RSP_OPCODE_VRSQH:
	  case RSP_OPCODE_VRSQL:
	    fprintf(f, " v%d[e%d], v%d[e%d]", vd, rd, rt, e / 2);
	    line_len += 15;
	    if (vd > 10) line_len++;
	    if (rd > 10) line_len++;
	    if (rt > 10) line_len++;
	    if (e > 10) line_len++;
	    break;

	  default:
	    fprintf(f, " v%d, v%d, v%d[e%d]", vd, rd, rt, e / 2);
	    line_len += 15;
	    if (vd > 10) line_len++;
	    if (rd > 10) line_len++;
	    if (rt > 10) line_len++;
	    if (e > 10) line_len++;
	    break;
	}
      }
      else
      {
	if (op->flags & OPCODE_INFO_NEEDRS)
	{
	  fprintf(f, " rs=%c%d",
	      op->flags & OPCODE_INFO_VECTOR ? 'v' : 'r', GET_RS(word));
	  line_len += 6;
	  if (GET_RS(word) > 10)
	    line_len++;
	}

	if (op->flags & OPCODE_INFO_NEEDRT)
	{
	  fprintf(f, " rt=%c%d",
	      op->flags & OPCODE_INFO_VECTOR ? 'v' : 'r', GET_RT(word));
	  line_len += 6;
	  if (GET_RT(word) > 10)
	    line_len++;
	}
      }

      if (decoded[i]->flags & OPCODE_INFO_BRANCH)
      {
	uint32_t target;
	if (compute_target(start_addr, word, i, decoded[i], &target))
	{
	  fprintf(f, " label_%X", target);
	  line_len += 8;
	  if (target > 0x10)
	    line_len++;
	  if (target > 0x100)
	    line_len++;
	  if (target > 0x1000)
	    line_len++;
	}
      }
    }
    else
    {
      fprintf(f, "\tnop");
      line_len += 11;
    }

    for (int i = 40 - line_len; i > 0; i--)
      fputc(' ', f);
    fprintf(f, " ; %02X %02X %02X %02X",
	(word >> 24) & 0xFF, (word >> 16) & 0xFF,
	(word >> 8) & 0xFF, word & 0xFF);

    fputc('\n', f);
  }
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

  if (rsp->regs[RSP_CP0_REGISTER_DMA_CACHE] & 0x1000)
  {
    uint32_t total = (count + 1) * length;
    assert(total <= 4096);
    static uint32_t buffer[1024];
    for (uint32_t i = 0; i <= count; i++) {
    	for (uint32_t j = 0; j < length; j+=4) {
	    uint32_t src = ((rsp->regs[RSP_CP0_REGISTER_DMA_DRAM] & 0x7FFFFC) + i * (length + skip) + j) & 0x7FFFFC;
	    bus_read_word(rsp, src, buffer + i * length + j / 4);
	}
    }
    dump_disasm(buffer, total, rsp->regs[RSP_CP0_REGISTER_DMA_CACHE] & 0x1FFC);
  }

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


