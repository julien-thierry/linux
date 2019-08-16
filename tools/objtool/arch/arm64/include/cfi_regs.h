/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _OBJTOOL_CFI_REGS_H
#define _OBJTOOL_CFI_REGS_H

#include <asm/aarch64-insn.h>

#define CFI_BP			AARCH64_INSN_REG_FP
#define CFI_LR			AARCH64_INSN_REG_LR
#define CFI_SP			AARCH64_INSN_REG_SP

#define CFI_NUM_REGS		32

#endif /* _OBJTOOL_CFI_REGS_H */
