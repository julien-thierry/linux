/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Josh Poimboeuf <jpoimboe@redhat.com>
 */

#ifndef _ORC_H
#define _ORC_H

struct objtool_file;

#ifdef OBJTOOL_ORC

#include <asm/orc_types.h>

int arch_orc_init(struct objtool_file *file);
int arch_orc_create_sections(struct objtool_file *file);

int orc_dump(const char *objname);

#else

struct orc_entry {
};

static inline int arch_orc_init(struct objtool_file *file)
{
	return 0;
}

static inline int arch_orc_create_sections(struct objtool_file *file)
{
	return 0;
}

static inline int arch_orc_read_unwind_hints(struct objtool_file *file)
{
	return 0;
}

static inline int orc_dump(const char *objname)
{
	return 0;
}

#endif /* OBJTOOL_ORC */

#endif /* _ORC_H */
