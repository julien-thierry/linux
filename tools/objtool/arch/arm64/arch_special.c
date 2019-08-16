// SPDX-License-Identifier: GPL-2.0-or-later

#include "../../special.h"

int arch_add_jump_table_dests(struct objtool_file *file,
			      struct instruction *insn)
{
	return 0;
}

struct rela *arch_find_switch_table(struct objtool_file *file,
				    struct instruction *insn)
{
	return NULL;
}
