/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2015 Josh Poimboeuf <jpoimboe@redhat.com>
 */

#ifndef _SPECIAL_H
#define _SPECIAL_H

#include <stdbool.h>
#include "check.h"
#include "elf.h"
#include "arch_special.h"

struct special_alt {
	struct list_head list;

	bool group;
	bool skip_orig;
	bool skip_alt;
	bool jump_or_nop;

	struct section *orig_sec;
	unsigned long orig_off;

	struct section *new_sec;
	unsigned long new_off;

	unsigned int orig_len, new_len; /* group only */
};

int special_get_alts(struct elf *elf, struct list_head *alts);

#ifndef arch_handle_alternative
static inline void arch_handle_alternative(unsigned short feature,
					   struct special_alt *alt)
{
}
#endif

bool arch_support_alt_relocation(struct special_alt *special_alt,
				 struct instruction *insn,
				 struct rela *rela);
int arch_add_jump_table_dests(struct objtool_file *file,
			      struct instruction *insn);
struct rela *arch_find_switch_table(struct objtool_file *file,
				    struct instruction *insn);
#endif /* _SPECIAL_H */
