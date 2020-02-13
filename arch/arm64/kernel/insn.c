// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2013 Huawei Ltd.
 * Author: Jiang Liu <liuj97@gmail.com>
 *
 * Copyright (C) 2014-2016 Zi Shen Lim <zlim.lnx@gmail.com>
 */
#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/stop_machine.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include <asm/cacheflush.h>
#include <asm/debug-monitors.h>
#include <asm/fixmap.h>
#include <asm/insn.h>
#include <asm/kprobes.h>
#include <asm/sections.h>
#include <asm/aarch64-insn.h>

static DEFINE_RAW_SPINLOCK(patch_lock);

static bool is_exit_text(unsigned long addr)
{
	/* discarded with init text/data */
	return system_state < SYSTEM_RUNNING &&
		addr >= (unsigned long)__exittext_begin &&
		addr < (unsigned long)__exittext_end;
}

static bool is_image_text(unsigned long addr)
{
	return core_kernel_text(addr) || is_exit_text(addr);
}

static void __kprobes *patch_map(void *addr, int fixmap)
{
	unsigned long uintaddr = (uintptr_t) addr;
	bool image = is_image_text(uintaddr);
	struct page *page;

	if (image)
		page = phys_to_page(__pa_symbol(addr));
	else if (IS_ENABLED(CONFIG_STRICT_MODULE_RWX))
		page = vmalloc_to_page(addr);
	else
		return addr;

	BUG_ON(!page);
	return (void *)set_fixmap_offset(fixmap, page_to_phys(page) +
			(uintaddr & ~PAGE_MASK));
}

static void __kprobes patch_unmap(int fixmap)
{
	clear_fixmap(fixmap);
}
/*
 * In ARMv8-A, A64 instructions have a fixed length of 32 bits and are always
 * little-endian.
 */
int __kprobes aarch64_insn_read(void *addr, u32 *insnp)
{
	int ret;
	__le32 val;

	ret = probe_kernel_read(&val, addr, AARCH64_INSN_SIZE);
	if (!ret)
		*insnp = le32_to_cpu(val);

	return ret;
}

static int __kprobes __aarch64_insn_write(void *addr, __le32 insn)
{
	void *waddr = addr;
	unsigned long flags = 0;
	int ret;

	raw_spin_lock_irqsave(&patch_lock, flags);
	waddr = patch_map(addr, FIX_TEXT_POKE0);

	ret = probe_kernel_write(waddr, &insn, AARCH64_INSN_SIZE);

	patch_unmap(FIX_TEXT_POKE0);
	raw_spin_unlock_irqrestore(&patch_lock, flags);

	return ret;
}

int __kprobes aarch64_insn_write(void *addr, u32 insn)
{
	return __aarch64_insn_write(addr, cpu_to_le32(insn));
}

int __kprobes aarch64_insn_patch_text_nosync(void *addr, u32 insn)
{
	u32 *tp = addr;
	int ret;

	/* A64 instructions must be word aligned */
	if ((uintptr_t)tp & 0x3)
		return -EINVAL;

	ret = aarch64_insn_write(tp, insn);
	if (ret == 0)
		__flush_icache_range((uintptr_t)tp,
				     (uintptr_t)tp + AARCH64_INSN_SIZE);

	return ret;
}

struct aarch64_insn_patch {
	void		**text_addrs;
	u32		*new_insns;
	int		insn_cnt;
	atomic_t	cpu_count;
};

static int __kprobes aarch64_insn_patch_text_cb(void *arg)
{
	int i, ret = 0;
	struct aarch64_insn_patch *pp = arg;

	/* The first CPU becomes master */
	if (atomic_inc_return(&pp->cpu_count) == 1) {
		for (i = 0; ret == 0 && i < pp->insn_cnt; i++)
			ret = aarch64_insn_patch_text_nosync(pp->text_addrs[i],
							     pp->new_insns[i]);
		/* Notify other processors with an additional increment. */
		atomic_inc(&pp->cpu_count);
	} else {
		while (atomic_read(&pp->cpu_count) <= num_online_cpus())
			cpu_relax();
		isb();
	}

	return ret;
}

int __kprobes aarch64_insn_patch_text(void *addrs[], u32 insns[], int cnt)
{
	struct aarch64_insn_patch patch = {
		.text_addrs = addrs,
		.new_insns = insns,
		.insn_cnt = cnt,
		.cpu_count = ATOMIC_INIT(0),
	};

	if (cnt <= 0)
		return -EINVAL;

	return stop_machine_cpuslocked(aarch64_insn_patch_text_cb, &patch,
				       cpu_online_mask);
}

bool aarch32_insn_is_wide(u32 insn)
{
	return insn >= 0xe800;
}

/*
 * Macros/defines for extracting register numbers from instruction.
 */
u32 aarch32_insn_extract_reg_num(u32 insn, int offset)
{
	return (insn & (0xf << offset)) >> offset;
}

#define OPC2_MASK	0x7
#define OPC2_OFFSET	5
u32 aarch32_insn_mcr_extract_opc2(u32 insn)
{
	return (insn & (OPC2_MASK << OPC2_OFFSET)) >> OPC2_OFFSET;
}

#define CRM_MASK	0xf
u32 aarch32_insn_mcr_extract_crm(u32 insn)
{
	return insn & CRM_MASK;
}

static bool __kprobes __check_eq(unsigned long pstate)
{
	return (pstate & PSR_Z_BIT) != 0;
}

static bool __kprobes __check_ne(unsigned long pstate)
{
	return (pstate & PSR_Z_BIT) == 0;
}

static bool __kprobes __check_cs(unsigned long pstate)
{
	return (pstate & PSR_C_BIT) != 0;
}

static bool __kprobes __check_cc(unsigned long pstate)
{
	return (pstate & PSR_C_BIT) == 0;
}

static bool __kprobes __check_mi(unsigned long pstate)
{
	return (pstate & PSR_N_BIT) != 0;
}

static bool __kprobes __check_pl(unsigned long pstate)
{
	return (pstate & PSR_N_BIT) == 0;
}

static bool __kprobes __check_vs(unsigned long pstate)
{
	return (pstate & PSR_V_BIT) != 0;
}

static bool __kprobes __check_vc(unsigned long pstate)
{
	return (pstate & PSR_V_BIT) == 0;
}

static bool __kprobes __check_hi(unsigned long pstate)
{
	pstate &= ~(pstate >> 1);	/* PSR_C_BIT &= ~PSR_Z_BIT */
	return (pstate & PSR_C_BIT) != 0;
}

static bool __kprobes __check_ls(unsigned long pstate)
{
	pstate &= ~(pstate >> 1);	/* PSR_C_BIT &= ~PSR_Z_BIT */
	return (pstate & PSR_C_BIT) == 0;
}

static bool __kprobes __check_ge(unsigned long pstate)
{
	pstate ^= (pstate << 3);	/* PSR_N_BIT ^= PSR_V_BIT */
	return (pstate & PSR_N_BIT) == 0;
}

static bool __kprobes __check_lt(unsigned long pstate)
{
	pstate ^= (pstate << 3);	/* PSR_N_BIT ^= PSR_V_BIT */
	return (pstate & PSR_N_BIT) != 0;
}

static bool __kprobes __check_gt(unsigned long pstate)
{
	/*PSR_N_BIT ^= PSR_V_BIT */
	unsigned long temp = pstate ^ (pstate << 3);

	temp |= (pstate << 1);	/*PSR_N_BIT |= PSR_Z_BIT */
	return (temp & PSR_N_BIT) == 0;
}

static bool __kprobes __check_le(unsigned long pstate)
{
	/*PSR_N_BIT ^= PSR_V_BIT */
	unsigned long temp = pstate ^ (pstate << 3);

	temp |= (pstate << 1);	/*PSR_N_BIT |= PSR_Z_BIT */
	return (temp & PSR_N_BIT) != 0;
}

static bool __kprobes __check_al(unsigned long pstate)
{
	return true;
}

/*
 * Note that the ARMv8 ARM calls condition code 0b1111 "nv", but states that
 * it behaves identically to 0b1110 ("al").
 */
pstate_check_t * const aarch32_opcode_cond_checks[16] = {
	__check_eq, __check_ne, __check_cs, __check_cc,
	__check_mi, __check_pl, __check_vs, __check_vc,
	__check_hi, __check_ls, __check_ge, __check_lt,
	__check_gt, __check_le, __check_al, __check_al
};
