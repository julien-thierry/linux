// SPDX-License-Identifier: GPL-2.0-or-later

#include <stdlib.h>
#include <string.h>

#include <asm/aarch64-insn.h>

#include "../../special.h"
#include "../../warn.h"
#include "arch_special.h"

/*
 * The arm64_switch_table_detection_plugin generate an array of elements
 * described by the following structure.
 * Each jump table found in the compilation unit is associated with one of
 * entries of the array.
 */
struct switch_table_info {
	u64 padding;
	u64 jump_ref;
	u64 nb_entries;
	u64 dest_relocations[];
} __attribute__((__packed__));

/*
 * Aarch64 jump tables are just arrays of offsets (of varying size/signess)
 * representing the potential destination from a base address loaded by an adr
 * instruction.
 *
 * Sadly, extracting the actual offset might require to consider multiple
 * instructions and decoding them to understand what they do. To make life
 * easier, the gcc plugin will generate a list of relocation entries for
 * each jump table target, conforming to the format expected by
 * add_jump_table().
 *
 * Aarch64 branches to jump tables are composed of multiple instructions:
 *
 *     ldr<?>  x_offset, [x_offsets_table, x_index, ...]
 *     adr     x_dest_base, <addr>
 *     add     x_dest, x_target_base, x_offset, ...
 *     br      x_dest
 *
 * The arm64_switch_table_detection_plugin will make the connection between
 * the instruction setting x_offsets_table (jump_ref) and the list of
 * relocations.
 */
struct rela *arch_find_switch_table(struct objtool_file *file,
				    struct instruction *insn)
{
	struct switch_table_info *sti;
	struct section *table_info_sec;
	void *sti_sec_start;
	struct rela *text_rela;

	table_info_sec = find_section_by_name(file->elf,
					      ".discard.switch_table_info");
	if (!table_info_sec)
		goto try_c_jmptbl;

	sti_sec_start = table_info_sec->data->d_buf;
	sti = sti_sec_start;

	while ((char *)sti - (char *)sti_sec_start <  table_info_sec->len) {
		struct rela *target_rela = find_rela_by_dest(file->elf,
							     table_info_sec,
							     (char *)&sti->jump_ref - (char *)sti_sec_start);

		if (!target_rela) {
			WARN("Malformed switch table entry");
			return NULL;
		}

		if (target_rela->sym->sec == insn->sec &&
		    target_rela->addend == insn->offset)
			return find_rela_by_dest(file->elf, table_info_sec,
						 (char *)&sti->dest_relocations[0] - (char *)sti_sec_start);

		/* Get next jump table entry */
		sti = (struct switch_table_info *) (&sti->dest_relocations[0] + sti->nb_entries);
	}

try_c_jmptbl:
	text_rela = find_rela_by_dest(file->elf, insn->sec, insn->offset);
	if (!text_rela || text_rela->sym->type != STT_SECTION ||
	    !text_rela->sym->sec->rodata)
		return NULL;

	/* Handle C jump tables */
	if (!strcmp(text_rela->sym->sec->name, C_JUMP_TABLE_SECTION))
		return find_rela_by_dest(file->elf, text_rela->sym->sec,
					 text_rela->addend);

	return NULL;
}
