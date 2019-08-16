// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdlib.h>

#include "../../special.h"
#include "../../builtin.h"
#include "../../warn.h"

void arch_handle_alternative(unsigned short feature, struct special_alt *alt)
{
	switch (feature) {
	case X86_FEATURE_SMAP:
		/*
		 * If UACCESS validation is enabled; force that alternative;
		 * otherwise force it the other way.
		 *
		 * What we want to avoid is having both the original and the
		 * alternative code flow at the same time, in that case we can
		 * find paths that see the STAC but take the NOP instead of
		 * CLAC and the other way around.
		 */
		if (uaccess)
			alt->skip_orig = true;
		else
			alt->skip_alt = true;
		break;
	case X86_FEATURE_POPCNT:
		/*
		 * It has been requested that we don't validate the !POPCNT
		 * feature path which is a "very very small percentage of
		 * machines".
		 */
		alt->skip_orig = true;
		break;
	default:
		break;
	}
}

bool arch_support_alt_relocation(struct special_alt *special_alt,
				 struct instruction *insn,
				 struct rela *rela)
{
	/*
	 * The x86 alternatives code adjusts the offsets only when it
	 * encounters a branch instruction at the very beginning of the
	 * replacement group.
	 */
	return insn->offset == special_alt->new_off &&
	       (insn->type == INSN_CALL || is_static_jump(insn));
}

int arch_add_jump_table_dests(struct objtool_file *file,
			      struct instruction *insn)
{
	struct rela *table = insn->jump_table;
	struct rela *rela = table;
	struct instruction *dest_insn;
	struct alternative *alt;
	struct symbol *pfunc = insn->func->pfunc;
	unsigned int prev_offset = 0;

	/*
	 * Each @rela is a switch table relocation which points to the target
	 * instruction.
	 */
	list_for_each_entry_from(rela, &table->sec->rela_list, list) {

		/* Check for the end of the table: */
		if (rela != table && rela->jump_table_start)
			break;

		/* Make sure the table entries are consecutive: */
		if (prev_offset && rela->offset != prev_offset + 8)
			break;

		/* Detect function pointers from contiguous objects: */
		if (rela->sym->sec == pfunc->sec &&
		    rela->addend == pfunc->offset)
			break;

		dest_insn = find_insn(file, rela->sym->sec, rela->addend);
		if (!dest_insn)
			break;

		/* Make sure the destination is in the same function: */
		if (!dest_insn->func || dest_insn->func->pfunc != pfunc)
			break;

		alt = malloc(sizeof(*alt));
		if (!alt) {
			WARN("malloc failed");
			return -1;
		}

		alt->insn = dest_insn;
		list_add_tail(&alt->list, &insn->alts);
		prev_offset = rela->offset;
	}

	if (!prev_offset) {
		WARN_FUNC("can't find switch jump table",
			  insn->sec, insn->offset);
		return -1;
	}

	return 0;
}

/*
 * There are 3 basic jump table patterns:
 *
 * 1. jmpq *[rodata addr](,%reg,8)
 *
 *    This is the most common case by far.  It jumps to an address in a simple
 *    jump table which is stored in .rodata.
 *
 * 2. jmpq *[rodata addr](%rip)
 *
 *    This is caused by a rare GCC quirk, currently only seen in three driver
 *    functions in the kernel, only with certain obscure non-distro configs.
 *
 *    As part of an optimization, GCC makes a copy of an existing switch jump
 *    table, modifies it, and then hard-codes the jump (albeit with an indirect
 *    jump) to use a single entry in the table.  The rest of the jump table and
 *    some of its jump targets remain as dead code.
 *
 *    In such a case we can just crudely ignore all unreachable instruction
 *    warnings for the entire object file.  Ideally we would just ignore them
 *    for the function, but that would require redesigning the code quite a
 *    bit.  And honestly that's just not worth doing: unreachable instruction
 *    warnings are of questionable value anyway, and this is such a rare issue.
 *
 * 3. mov [rodata addr],%reg1
 *    ... some instructions ...
 *    jmpq *(%reg1,%reg2,8)
 *
 *    This is a fairly uncommon pattern which is new for GCC 6.  As of this
 *    writing, there are 11 occurrences of it in the allmodconfig kernel.
 *
 *    As of GCC 7 there are quite a few more of these and the 'in between' code
 *    is significant. Esp. with KASAN enabled some of the code between the mov
 *    and jmpq uses .rodata itself, which can confuse things.
 *
 *    TODO: Once we have DWARF CFI and smarter instruction decoding logic,
 *    ensure the same register is used in the mov and jump instructions.
 *
 *    NOTE: RETPOLINE made it harder still to decode dynamic jumps.
 */
struct rela *arch_find_switch_table(struct objtool_file *file,
				    struct instruction *insn)
{
	struct rela *text_rela, *rodata_rela;
	struct section *table_sec;
	unsigned long table_offset;

	/* look for a relocation which references .rodata */
	text_rela = find_rela_by_dest_range(file->elf, insn->sec,
					    insn->offset, insn->len);
	if (!text_rela || text_rela->sym->type != STT_SECTION ||
	    !text_rela->sym->sec->rodata)
		return NULL;

	table_offset = text_rela->addend;
	table_sec = text_rela->sym->sec;

	if (text_rela->type == R_X86_64_PC32)
		table_offset += 4;

	/*
	 * Make sure the .rodata address isn't associated with a
	 * symbol.  GCC jump tables are anonymous data.
	 *
	 * Also support C jump tables which are in the same format as
	 * switch jump tables.  For objtool to recognize them, they
	 * need to be placed in the C_JUMP_TABLE_SECTION section.  They
	 * have symbols associated with them.
	 */
	if (find_symbol_containing(table_sec, table_offset) &&
	    strcmp(table_sec->name, C_JUMP_TABLE_SECTION))
		return NULL;

	/*
	 * Each table entry has a rela associated with it.  The rela
	 * should reference text in the same function as the original
	 * instruction.
	 */
	rodata_rela = find_rela_by_dest(file->elf, table_sec, table_offset);
	if (rodata_rela) {
		/*
		 * Use of RIP-relative switch jumps is quite rare, and
		 * indicates a rare GCC quirk/bug which can leave dead
		 * code behind.
		 */
		if (text_rela->type == R_X86_64_PC32)
			file->ignore_unreachables = true;

		return rodata_rela;
	}

	return NULL;
}
