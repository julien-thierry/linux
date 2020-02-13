/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2013 Huawei Ltd.
 * Author: Jiang Liu <liuj97@gmail.com>
 *
 * Copyright (C) 2014 Zi Shen Lim <zlim.lnx@gmail.com>
 */
#ifndef	__ASM_INSN_H
#define	__ASM_INSN_H
#include <linux/build_bug.h>
#include <linux/types.h>

#ifndef __ASSEMBLY__

int aarch64_insn_read(void *addr, u32 *insnp);
int aarch64_insn_write(void *addr, u32 insn);

int aarch64_insn_patch_text_nosync(void *addr, u32 insn);
int aarch64_insn_patch_text(void *addrs[], u32 insns[], int cnt);

bool aarch32_insn_is_wide(u32 insn);

#define A32_RN_OFFSET	16
#define A32_RT_OFFSET	12
#define A32_RT2_OFFSET	 0

u32 aarch32_insn_extract_reg_num(u32 insn, int offset);
u32 aarch32_insn_mcr_extract_opc2(u32 insn);
u32 aarch32_insn_mcr_extract_crm(u32 insn);

typedef bool (pstate_check_t)(unsigned long);
extern pstate_check_t * const aarch32_opcode_cond_checks[16];
#endif /* __ASSEMBLY__ */

#endif	/* __ASM_INSN_H */
