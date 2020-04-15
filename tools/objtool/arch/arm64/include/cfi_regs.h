/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _OBJTOOL_CFI_REGS_H
#define _OBJTOOL_CFI_REGS_H

#include <asm/aarch64-insn.h>

#define CFI_BP			AARCH64_INSN_REG_FP
#define CFI_RA			AARCH64_INSN_REG_LR
#define CFI_SP			AARCH64_INSN_REG_SP

#define CFI_NUM_REGS		32

#define CFA_SIZE	16
#define CFA_BP_OFFSET	-16
#define CFA_RA_OFFSET	-8

#endif /* _OBJTOOL_CFI_REGS_H */
