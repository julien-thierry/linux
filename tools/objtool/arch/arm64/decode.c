// SPDX-License-Identifier: GPL-2.0-or-later

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <linux/frame.h>

/* Hack needed to avoid depending on brk-imm.h */
#define FAULT_BRK_IMM	0x100

#include <asm/aarch64-insn.h>
#include <asm/unwind_hints.h>

#include "cfi_regs.h"

#include "../../check.h"
#include "../../arch.h"
#include "../../elf.h"
#include "../../warn.h"

/* Hack needed to avoid depending on kprobes.h */
#ifndef __kprobes
#define __kprobes
#endif

#include "../../../arch/arm64/lib/aarch64-insn.c"

static unsigned long sign_extend(unsigned long x, int nbits)
{
	unsigned long sign_bit = (x >> (nbits - 1)) & 1;

	return ((~0UL + (sign_bit ^ 1)) << nbits) | x;
}

static bool stack_related_reg(int reg)
{
	return reg == CFI_SP || reg == CFI_BP;
}

struct insn_loc {
	struct section *sec;
	unsigned long offset;
	struct hlist_node hnode;
};

DEFINE_HASHTABLE(unknown_opcodes, 16);
DEFINE_HASHTABLE(lit_constants, 16);

int arch_post_process_file(struct objtool_file *file)
{
	struct hlist_node *tmp;
	struct insn_loc *loc;
	unsigned int bkt;
	int res = 0;

	/*
	 * Data placed in code sections could turn out to be a valid aarch64
	 * opcode.
	 * If that is the case, change the insn type to invalid as it should
	 * never be reached by the execution flow.
	 */
	hash_for_each_safe(lit_constants, bkt, tmp, loc, hnode) {
		struct instruction *insn;

		insn = find_insn(file, loc->sec, loc->offset);
		if (insn)
			mark_data(insn);

		hash_del(&loc->hnode);
		free(loc);
	}

	/* Check for unknown instructions */
	hash_for_each_safe(unknown_opcodes, bkt, tmp, loc, hnode) {
		struct instruction *insn;

		insn = find_insn(file, loc->sec, loc->offset);
		if (insn) {
			/* This can be padding added by the compiler */
			if (*(u32 *)(insn->sec->data->d_buf + insn->offset) == 0x0)
				mark_data(insn);
			if (!insn->data)
				WARN_FUNC("Unknown opcode", loc->sec, loc->offset);
		}
		hash_del(&loc->hnode);
		free(loc);
	}

	return res;
}

bool arch_callee_saved_reg(unsigned char reg)
{
	switch (reg) {
	case AARCH64_INSN_REG_19:
	case AARCH64_INSN_REG_20:
	case AARCH64_INSN_REG_21:
	case AARCH64_INSN_REG_22:
	case AARCH64_INSN_REG_23:
	case AARCH64_INSN_REG_24:
	case AARCH64_INSN_REG_25:
	case AARCH64_INSN_REG_26:
	case AARCH64_INSN_REG_27:
	case AARCH64_INSN_REG_28:
	case AARCH64_INSN_REG_FP:
	case AARCH64_INSN_REG_LR:
		return true;
	default:
		return false;
	}
}

void arch_initial_func_cfi_state(struct cfi_state *state)
{
	int i;

	for (i = 0; i < CFI_NUM_REGS; i++) {
		state->regs[i].base = CFI_UNDEFINED;
		state->regs[i].offset = 0;
	}

	/* initial CFA (call frame address) */
	state->cfa.base = CFI_UNDEFINED;
	state->cfa.offset = 0;
}

unsigned long arch_dest_rela_offset(int addend)
{
	return addend;
}

unsigned long arch_jump_destination(struct instruction *insn)
{
	return insn->offset + insn->immediate;
}

int arch_decode_insn_hint(struct instruction *insn, struct unwind_hint *hint)
{
	struct insn_state *state = &insn->state;
	int i = 0;

	if (hint->type == UNWIND_HINT_TYPE_SAVE) {
		insn->save = true;
		return 0;

	} else if (hint->type == UNWIND_HINT_TYPE_RESTORE) {
		insn->restore = true;
		insn->hint = true;
		return 0;
	}

	insn->hint = true;

	if (hint->sp_reg == UNWIND_HINT_REG_UNDEFINED)
		state->cfa.base = CFI_UNDEFINED;
	else
		state->cfa.base = hint->sp_reg;

	state->cfa.offset = hint->sp_offset;

	state->hint_type = hint->type;
	state->end = hint->end;

	if (hint->type == UNWIND_HINT_TYPE_PT_REGS) {
		for (i = 0; i < CFI_NUM_REGS; ++i) {
			if (!arch_callee_saved_reg(i))
				continue;
			state->regs[i].base = CFI_CFA;
			state->regs[i].offset = (8 * i) - state->cfa.offset;
		}

		/* No-one needs to know */
		state->hint_type = UNWIND_HINT_TYPE_CALL;
	}

	return 0;
}

static int is_arm64(struct elf *elf)
{
	switch (elf->ehdr.e_machine) {
	case EM_AARCH64: //0xB7
		return 1;
	default:
		WARN("unexpected ELF machine type %x",
		     elf->ehdr.e_machine);
		return 0;
	}
}

static struct stack_op *arm_make_store_op(enum aarch64_insn_register base,
					  enum aarch64_insn_register reg,
					  int offset)
{
	struct stack_op *op;

	op = calloc(1, sizeof(*op));
	op->dest.type = OP_DEST_REG_INDIRECT;
	op->dest.reg = base;
	op->dest.offset = offset;
	op->src.type = OP_SRC_REG;
	op->src.reg = reg;
	op->src.offset = 0;

	return op;
}

static struct stack_op *arm_make_load_op(enum aarch64_insn_register base,
					 enum aarch64_insn_register reg,
					 int offset)
{
	struct stack_op *op;

	op = calloc(1, sizeof(*op));
	op->dest.type = OP_DEST_REG;
	op->dest.reg = reg;
	op->dest.offset = 0;
	op->src.type = OP_SRC_REG_INDIRECT;
	op->src.reg = base;
	op->src.offset = offset;

	return op;
}

static struct stack_op *arm_make_add_op(enum aarch64_insn_register dest,
					enum aarch64_insn_register src,
					int val)
{
	struct stack_op *op;

	op = calloc(1, sizeof(*op));
	op->dest.type = OP_DEST_REG;
	op->dest.reg = dest;
	op->src.reg = src;
	op->src.type = val != 0 ? OP_SRC_ADD : OP_SRC_REG;
	op->src.offset = val;

	return op;
}

static struct stack_op *arm_make_mov_op(enum aarch64_insn_register dest,
					enum aarch64_insn_register src)
{
	return arm_make_add_op(dest, src, 0);
}

static bool arm_decode_load_store(u32 insn, enum insn_type *type,
				  unsigned long *immediate,
				  struct list_head *ops_list)
{
	enum aarch64_insn_register base;
	enum aarch64_insn_register rt;
	struct stack_op *op;
	int size;
	int offset;


	if (aarch64_insn_is_store_single(insn) ||
	    aarch64_insn_is_load_single(insn))
		size = 1 << ((insn & GENMASK(31,30)) >> 30);
	else
		size = 4 << ((insn >> 31) & 1);

	if (aarch64_insn_is_store_imm(insn) || aarch64_insn_is_load_imm(insn))
		*immediate = size * aarch64_insn_decode_immediate(AARCH64_INSN_IMM_12,
								  insn);
	else if (aarch64_insn_is_store_pre(insn) ||
		 aarch64_insn_is_load_pre(insn) ||
		 aarch64_insn_is_store_post(insn) ||
		 aarch64_insn_is_load_post(insn))
		*immediate = sign_extend(aarch64_insn_decode_immediate(AARCH64_INSN_IMM_9,
								       insn),
					 9);
	else if (aarch64_insn_is_stp(insn) || aarch64_insn_is_ldp(insn) ||
		 aarch64_insn_is_stp_pre(insn) ||
		 aarch64_insn_is_ldp_pre(insn) ||
		 aarch64_insn_is_stp_post(insn) ||
		 aarch64_insn_is_ldp_post(insn))
		*immediate = size * sign_extend(aarch64_insn_decode_immediate(AARCH64_INSN_IMM_7,
									      insn),
						7);
	else
		return false;

	base = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RN, insn);
	if (!stack_related_reg(base)) {
		*type = INSN_OTHER;
		return true;
	} else {
		*type = INSN_STACK;
	}

	if (aarch64_insn_is_store_post(insn) || aarch64_insn_is_load_post(insn) ||
	    aarch64_insn_is_stp_post(insn) || aarch64_insn_is_ldp_post(insn))
		offset = 0;
	else
		offset = *immediate;

	/* First register */
	rt = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RT, insn);
	if (aarch64_insn_is_store_single(insn) ||
	    aarch64_insn_is_store_pair(insn))
		op = arm_make_store_op(base, rt, offset);
	else
		op = arm_make_load_op(base, rt, offset);
	list_add_tail(&op->list, ops_list);

	/* Second register (if present) */
	if (aarch64_insn_is_store_pair(insn) ||
	    aarch64_insn_is_load_pair(insn)) {
		rt = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RT2,
						  insn);
		if (aarch64_insn_is_store_pair(insn))
			op = arm_make_store_op(base, rt, offset + size);
		else
			op = arm_make_load_op(base, rt, offset + size);
		list_add_tail(&op->list, ops_list);
	}

	/* Handle write-back */
	if (aarch64_insn_is_store_pre(insn) || aarch64_insn_is_load_pre(insn) ||
	    aarch64_insn_is_ldp_pre(insn) || aarch64_insn_is_stp_pre(insn) ||
	    aarch64_insn_is_store_post(insn) || aarch64_insn_is_load_post(insn) ||
	    aarch64_insn_is_stp_post(insn) || aarch64_insn_is_ldp_post(insn)) {
		op = arm_make_add_op(base, base, *immediate);
		list_add_tail(&op->list, ops_list);
	}

	return true;
}

static void arm_decode_add_sub_imm(u32 instr, bool set_flags,
				   enum insn_type *type,
				   unsigned long *immediate,
				   struct list_head *ops_list)
{
	u32 rd = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RD, instr);
	u32 rn = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RN, instr);

	*type = INSN_OTHER;
	*immediate = aarch64_insn_decode_immediate(AARCH64_INSN_IMM_12, instr);

	if (instr & AARCH64_INSN_LSL_12)
		*immediate <<= 12;

	if ((!set_flags && rd == AARCH64_INSN_REG_SP) ||
	    rd == AARCH64_INSN_REG_FP || stack_related_reg(rn)) {
		struct stack_op *op;
		int value;

		*type = INSN_STACK;
		if (aarch64_insn_is_subs_imm(instr) || aarch64_insn_is_sub_imm(instr))
			value = -*immediate;
		else
			value = *immediate;

		op = arm_make_add_op(rd, rn, value);
		list_add_tail(&op->list, ops_list);
	}
}

/*
 * Arm A64 Instruction set' decode groups (based on op0 bits[28:25]):
 * Ob0000 - Reserved
 * 0b0001/0b001x - Unallocated
 * 0b100x - Data Processing -- Immediate
 * 0b101x - Branch, Exception Gen., System Instructions.
 * 0bx1x0 - Loads and Stores
 * 0bx101 - Data Processing -- Registers
 * 0bx111 - Data Processing -- Scalar Floating-Points, Advanced SIMD
 */

int arch_decode_instruction(struct elf *elf, struct section *sec,
			    unsigned long offset, unsigned int maxlen,
			    unsigned int *len, enum insn_type *type,
			    unsigned long *immediate,
			    struct list_head *ops_list)
{
	u32 insn;

	*len = AARCH64_INSN_SIZE;
	*immediate = 0;

	//test architucture (make sure it is arm64)
	if (!is_arm64(elf))
		return -1;

	//retrieve instruction (from sec->data->offset)
	insn = *(u32 *)(sec->data->d_buf + offset);

	switch (aarch64_get_insn_class(insn)) {
	case AARCH64_INSN_CLS_UNKNOWN:
	{
		struct insn_loc *loc;

		/*
		 * There are a few reasons we might have non-valid opcodes in
		 * code sections:
		 * - For load literal, assembler can generate the data to be
		 *   loaded in the code section
		 * - Compiler/assembler can generate zeroes to pad function that
		 *   do not end on 8-byte alignment
		 * - Hand written assembly code might contain constants in the
		 *   code section
		 */
		loc = malloc(sizeof(*loc));
		loc->sec = sec;
		loc->offset = offset;
		hash_add(unknown_opcodes, &loc->hnode, loc->offset);

		*type = INSN_OTHER;

		break;
	}
	case AARCH64_INSN_CLS_DP_IMM:
		/* Mov register to and from SP are aliases of add_imm */
		if (aarch64_insn_is_add_imm(insn) ||
		    aarch64_insn_is_sub_imm(insn)) {
			arm_decode_add_sub_imm(insn, false, type, immediate,
					       ops_list);
		}
		else if (aarch64_insn_is_adds_imm(insn) ||
			 aarch64_insn_is_subs_imm(insn)) {
			arm_decode_add_sub_imm(insn, true, type, immediate,
					       ops_list);
		} else if (aarch64_insn_is_adr(insn) || aarch64_insn_is_adrp(insn)) {
			*immediate = sign_extend(aarch64_insn_decode_immediate(AARCH64_INSN_IMM_ADR, insn),
				                 21);
			if (aarch64_insn_is_adrp(insn))
				*immediate *= 4096;
			*type = INSN_OTHER;
		} else {
			*type = INSN_OTHER;
		}
		break;
	case AARCH64_INSN_CLS_DP_REG:
		/* mov reg1, reg2 is an alias of orr */
		if (aarch64_insn_is_mov_reg(insn)) {
			enum aarch64_insn_register rd;
			enum aarch64_insn_register rm;

			rd = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RD, insn);
			rm = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RM, insn);
			if (rd == AARCH64_INSN_REG_FP || rm == AARCH64_INSN_REG_FP) {
				struct stack_op *op;

				op = arm_make_mov_op(rd, rm);
				list_add_tail(&op->list, ops_list);
				*type = INSN_STACK;
				break;
			}
		}
		*type = INSN_OTHER;
		break;
	case AARCH64_INSN_CLS_BR_SYS:
		// TODO hvc/smc should either be INSN_CALL or CTX_SWITCH
		if (aarch64_insn_is_ret(insn) &&
		    aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RN, insn) == AARCH64_INSN_REG_LR) {
			*type = INSN_RETURN;
		} else if (aarch64_insn_is_bl(insn)) {
			*type = INSN_CALL;
			*immediate = aarch64_get_branch_offset(insn);
		} else if (aarch64_insn_is_blr(insn)) {
			*type = INSN_CALL_DYNAMIC;
		} else if (aarch64_insn_is_b(insn)) {
			*type = INSN_JUMP_UNCONDITIONAL;
			*immediate = aarch64_get_branch_offset(insn);
		} else if (aarch64_insn_is_br(insn)) {
			*type = INSN_JUMP_DYNAMIC;
		} else if (aarch64_insn_is_branch_imm(insn)) {
			/* Remaining branch opcodes are conditional */
			*type = INSN_JUMP_CONDITIONAL;
			*immediate = aarch64_get_branch_offset(insn);
		} else if (aarch64_insn_is_eret(insn)) {
			*type = INSN_CONTEXT_SWITCH;
		} else if (aarch64_insn_is_nop(insn) ||
			   aarch64_insn_is_barrier(insn)) {
			*type = INSN_NOP;
		} else if (aarch64_insn_is_brk(insn)) {
			*immediate = aarch64_insn_decode_immediate(AARCH64_INSN_IMM_16, insn);
			*type = INSN_BUG;
		} else {
			*type = INSN_OTHER;
		}
		break;
	case AARCH64_INSN_CLS_LDST:
		if (arm_decode_load_store(insn, type, immediate, ops_list))
			break;
		if (aarch64_insn_is_ldr_lit(insn)) {
			struct insn_loc *loc;
			long pc_offset;

			pc_offset = insn & GENMASK(23, 5);
			/* Sign extend and multiply by 4 */
			pc_offset = (pc_offset << (64 - 23));
			pc_offset = ((pc_offset >> (64 - 23)) >> 5) << 2;

			loc = malloc(sizeof(*loc));
			loc->sec = sec;
			loc->offset = offset + pc_offset;
			hash_add(lit_constants, &loc->hnode, loc->offset);

			/* 64-bit literal */
			if (insn & BIT(30)) {
				loc = malloc(sizeof(*loc));
				loc->sec = sec;
				loc->offset = offset + pc_offset + 4;
				hash_add(lit_constants, &loc->hnode, loc->offset);
			}
		}
		*type = INSN_OTHER;
		break;
	default:
		*type = INSN_OTHER;
		break;
	}

	return 0;
}
