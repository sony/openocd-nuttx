/***************************************************************************
 *   Copyright 2014,2015,2018 Sony Video & Sound Products Inc.             *
 *   Masatoshi Tateishi - Masatoshi.Tateishi@jp.sony.com                   *
 *   Masayuki Ishikawa - Masayuki.Ishikawa@jp.sony.com                     *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "imp.h"
#include "spi.h"
#include <jtag/jtag.h>
#include <helper/time_support.h>
#include <target/algorithm.h>
#include <target/armv7m.h>

#include "lc823450_spifi.h"

/* Timeout in ms */
#define SSP_CMD_TIMEOUT   (100)
#define SSP_PROBE_TIMEOUT (100)
#define SSP_MAX_TIMEOUT  (3000)

/* Size of the stack to alloc in the working area for the execution of
 * the ROM spifi_init() function */
#define SPIFI_INIT_STACK_SIZE  512

#define FLASH_SIZE	(4096 * 1024)
#define SECTOR_SIZE	4096

#define LC823450_SYSCONTROL_REGBASE 0x40080000
#define MCLKCNTBASIC (LC823450_SYSCONTROL_REGBASE + 0x0100)
#define         MCLKCNTBASIC_SFIF_CLKEN         (1 << 1)
#define MRSTCNTBASIC (LC823450_SYSCONTROL_REGBASE + 0x0114)
#define         MRSTCNTBASIC_SFIF_RSTB          (1 << 1)

#define PMDCNT0 (LC823450_SYSCONTROL_REGBASE + 0x0400)
#define PMDCNT1 (LC823450_SYSCONTROL_REGBASE + 0x0404)


struct lc823450_flash_bank {
	int probed;
	uint32_t ssp_base;
	uint32_t io_base;
	uint32_t ioconfig_base;
	uint32_t bank_num;
	uint32_t max_spi_clock_mhz;
	const struct flash_device *dev;
};

struct lc823450_target {
	char *name;
	uint32_t tap_idcode;
	uint32_t spifi_base;
	uint32_t ssp_base;
	uint32_t io_base;
	uint32_t ioconfig_base; /* base address for the port word pin registers */
};
static struct target *Target;

#define putreg32(v, a) target_write_u32(Target, a, v);
#define putreg16(v, a) target_write_u16(Target, a, v);
#define putreg8(v, a)  target_write_u8(Target, a, v);
#define MAX_TRANS_SIZE 256


uint32_t _getreg32(uint32_t a)
{
	uint32_t v;
	target_read_u32(Target, a, &v);
	return v;
}
#define getreg32(a) _getreg32(a)

uint16_t _getreg16(uint32_t a)
{
	uint16_t v;
	target_read_u16(Target, a, &v);
	return v;
}
#define getreg16(a) _getreg16(a)

uint8_t _getreg8(uint32_t a)
{
	uint8_t v;
	target_read_u8(Target, a, &v);
	return v;
}
#define getreg8(a) _getreg8(a)

#define up_udelay usleep


/* flash_bank lc823450 <base> <size> <chip_width> <bus_width> <target>
 */
FLASH_BANK_COMMAND_HANDLER(lc823450_flash_bank_command)
{
	struct lc823450_flash_bank *lc823450_info;

	if (CMD_ARGC < 6)
		return ERROR_COMMAND_SYNTAX_ERROR;

	lc823450_info = malloc(sizeof(struct lc823450_flash_bank));
	if (lc823450_info == NULL) {
		LOG_ERROR("not enough memory");
		return ERROR_FAIL;
	}

	bank->driver_priv = lc823450_info;
	lc823450_info->probed = 0;

	return ERROR_OK;
}

static int wait_txfifo_empty(void)
{
	int t;
	t = 1000;
	while((getreg32(SF_FIFO_NUM) & SF_FIFO_NUM_T_MASK) && t) {
		up_udelay(1);
		t--;
	}
	return t == 0 ? -ETIMEDOUT : 0;
}

static int wait_rxfifo_notempty(void)
{
	int t;
	t = 1000;
	while(!(getreg32(SF_FIFO_NUM) & SF_FIFO_NUM_R_MASK) && t) {
		up_udelay(1);
		t--;
	}
	return t == 0 ? -ETIMEDOUT : 0;
}

static int spiflash_cmd_only(int cmd)
{
	/* COMMAND(1byte) = 1 */
	putreg32(SF_SIZE_NOREAD | 1 << SF_SIZE_T_SHIFT, SF_SIZE);
	putreg32(0, SF_DUMMY);
	putreg8(cmd, SF_T_FIFO);

	/* Start Transfer */
	putreg32(SF_CTL_ACT, SF_CTL);
	return wait_txfifo_empty();
}

static int spiflash_write_busy(void)
{
	/* COMMAND(1byte) + status(1byte) */
	putreg32(1 << SF_SIZE_UL_SHIFT | 2 << SF_SIZE_T_SHIFT, SF_SIZE);
	putreg32(SF_DUMMY_DUMMY, SF_DUMMY);

	/* COMMAND */
	putreg8(SF_CMD_READ_STATUS1, SF_T_FIFO);

	/* Start Transfer */
	putreg32(SF_CTL_ACT, SF_CTL);

	wait_rxfifo_notempty();

	return getreg8(SF_R_FIFO) & SF_STATUS1_BUSY;
}

/* Send "write enable" command to SPI flash chip. */
static int spiflash_write_enable(void)
{
	return spiflash_cmd_only(SF_CMD_WRITE_EN);
}

#if 0
static int lc823450_bulk_erase(void)
{
	int ret;
	spiflash_write_enable();

	ret = spiflash_cmd_only(SF_CMD_CHIP_ERASE);
	if (ret)
		return ret;

	while(spiflash_write_busy())
		up_udelay(10);

	return 0;
}
#endif

static int lc823450_erase_core(int first, int cmd)
{
	uint32_t addr;
	int ret;

	while(spiflash_write_busy())
		up_udelay(10);

	spiflash_write_enable();

	addr = first * SECTOR_SIZE;

	/* COMMAND(1byte) + addr(3 byte) = 4 */
	putreg32(SF_SIZE_NOREAD | 4 << SF_SIZE_T_SHIFT, SF_SIZE);
	putreg32(0, SF_DUMMY);
	putreg8(cmd, SF_T_FIFO);

	/* address */
	putreg8((addr >> 16) & 0xff, SF_T_FIFO);
	putreg8((addr >> 8) & 0xff, SF_T_FIFO);
	putreg8((addr >> 0) & 0xff, SF_T_FIFO);

	/* Start Transfer */
	putreg32(SF_CTL_ACT, SF_CTL);

	ret = wait_txfifo_empty();
	if (ret)
		return ret;
	return 0;
}

static int lc823450_erase_internal(int first, int num)
{
	int i, last;

	last = first + num - 1;

	for (i = first; i <= last;) {
		if (i % 16 == 0 && (last - i + 1) >= 16) {
			lc823450_erase_core(i, SF_CMD_BLK_ERASE64);
			i += 16;
			LOG_DEBUG("erase 64\n");
		} else if (i % 8 == 0 && (last - i + 1) >= 8) {
			lc823450_erase_core(i, SF_CMD_BLK_ERASE32);
			i += 8;
			LOG_DEBUG("erase 32\n");
		} else {
			lc823450_erase_core(i, SF_CMD_SEC_ERASE);
			i++;
			LOG_DEBUG("erase 4\n");
		}
	}

	return 0;
}

static int lc823450_erase(struct flash_bank *bank, int first, int last)
{
	/* Do nothing */
	return 0;
}

#if 0
static ssize_t lc823450_read_core(off_t offset, size_t nbytes, uint8_t *buf)
{
	int i, ret;

	/* COMMAND(1byte) + address(3byte) + dummy(1byte) = 5 */
	putreg32(5 << SF_SIZE_UL_SHIFT | (5 + nbytes) << SF_SIZE_T_SHIFT,
	    SF_SIZE);

	putreg32(SF_DUMMY_DUMMY, SF_DUMMY);

	/* COMMAND */
	putreg8(SF_CMD_FAST_READ, SF_T_FIFO);


	/* address */
	putreg8((offset >> 16) & 0xff, SF_T_FIFO);
	putreg8((offset >> 8) & 0xff, SF_T_FIFO);
	putreg8((offset >> 0) & 0xff, SF_T_FIFO);

	/* Start Transfer */
	putreg32(SF_CTL_ACT, SF_CTL);

	for (i = 0; i < (int)nbytes; i++) {
		ret = wait_rxfifo_notempty();
		if (ret)
			return ret;

		buf[i] = getreg8(SF_R_FIFO);
	}
	return nbytes;
}

static ssize_t lc823450_read(off_t offset, size_t nbytes, uint8_t *buf)
{
	unsigned int i, tsize, remains;

	remains = nbytes;
	for (i = offset; i < offset + nbytes; i += MAX_TRANS_SIZE) {
		tsize = remains > MAX_TRANS_SIZE ? MAX_TRANS_SIZE : remains;
		lc823450_read_core(i, tsize, buf);
		buf += tsize;
		remains -= tsize;
	}

	return nbytes;
}
#endif



static int lc823450_protect(struct flash_bank *bank, int set,
	int first, int last)
{
	int sector;

	for (sector = first; sector <= last; sector++)
		bank->sectors[sector].is_protected = set;
	return ERROR_OK;
}

/*

00000000 <spiflash_write>:
   0:   b480            push    {r7}
   2:   b08f            sub     sp, #60 ; 0x3c
   4:   af00            add     r7, sp, #0
   6:   60f8            str     r0, [r7, #12]
   8:   60b9            str     r1, [r7, #8]
..........
 124:   4618            mov     r0, r3
 126:   373c            adds    r7, #60 ; 0x3c
 128:   46bd            mov     sp, r7
 12a:   f85d 7b04       ldr.w   r7, [sp], #4
- 12e:   4770            bx      lr
+ 12e:   be00            bkpt
 130:   40001000        andmi   r1, r0, r0
 134:   10000001        andne   r0, r0, r1
 138:   4000100c        andmi   r1, r0, ip
 13c:   40001030        andmi   r1, r0, r0, lsr r0
 140:   40001004        andmi   r1, r0, r4
 144:   4000101c        andmi   r1, r0, ip, lsl r0
 148:   01000002        tsteq   r0, r2
 14c:   40001034        andmi   r1, r0, r4, lsr r0

*/

const uint8_t write_firm[] = {
0x80, 0xb4, 0x8f, 0xb0, 0x00, 0xaf, 0xf8, 0x60, 0xb9, 0x60, 0x7a, 0x60,
0xbb, 0x68, 0x3b, 0x63, 0xfb, 0x68, 0x7b, 0x63, 0x7e, 0xe0, 0x3b, 0x6b, 0xb3, 0xf5, 0x80, 0x7f,
0xa8, 0xbf, 0x4f, 0xf4, 0x80, 0x73, 0xfb, 0x62, 0xfb, 0x6a, 0x7a, 0x6b, 0xba, 0x62, 0x7b, 0x62,
0x7b, 0x68, 0x3b, 0x62, 0x06, 0x23, 0xfb, 0x61, 0x3e, 0x4b, 0x3f, 0x4a, 0x1a, 0x60, 0x3f, 0x4b,
0x00, 0x22, 0x1a, 0x60, 0x3e, 0x4b, 0xfa, 0x69, 0xd2, 0xb2, 0x1a, 0x70, 0x3d, 0x4b, 0x01, 0x22,
0x1a, 0x60, 0x3d, 0x4b, 0x1b, 0x68, 0x03, 0xf0, 0x0f, 0x03, 0x00, 0x2b, 0xf9, 0xd1, 0x00, 0x23,
0xbb, 0x61, 0xbb, 0x69, 0x00, 0x2b, 0x4b, 0xd1, 0x32, 0x4b, 0x7a, 0x6a, 0x04, 0x32, 0x42, 0xf0,
0x80, 0x52, 0x1a, 0x60, 0x31, 0x4b, 0x00, 0x22, 0x1a, 0x60, 0x31, 0x4b, 0x02, 0x22, 0x1a, 0x70,
0x2f, 0x4b, 0xba, 0x6a, 0x12, 0x14, 0xd2, 0xb2, 0x1a, 0x70, 0x2d, 0x4b, 0xba, 0x6a, 0x12, 0x12,
0xd2, 0xb2, 0x1a, 0x70, 0x2a, 0x4b, 0xba, 0x6a, 0xd2, 0xb2, 0x1a, 0x70, 0x29, 0x4b, 0x01, 0x22,
0x1a, 0x60, 0x00, 0x23, 0x7b, 0x61, 0x0e, 0xe0, 0x25, 0x4a, 0x3b, 0x6a, 0x59, 0x1c, 0x39, 0x62,
0x1b, 0x78, 0x13, 0x70, 0x24, 0x4b, 0x1b, 0x68, 0x03, 0xf0, 0x0f, 0x03, 0x00, 0x2b, 0xf9, 0xd1,
0x7b, 0x69, 0x01, 0x33, 0x7b, 0x61, 0x7b, 0x69, 0x7a, 0x6a, 0x9a, 0x42, 0xec, 0xd8, 0x19, 0x4b,
0x1e, 0x4a, 0x1a, 0x60, 0x19, 0x4b, 0x01, 0x22, 0x1a, 0x60, 0x19, 0x4b, 0x05, 0x22, 0x1a, 0x70,
0x18, 0x4b, 0x01, 0x22, 0x1a, 0x60, 0x18, 0x4b, 0x1b, 0x68, 0x03, 0xf4, 0x70, 0x63, 0x00, 0x2b,
0xf9, 0xd0, 0x17, 0x4b, 0x1b, 0x78, 0xdb, 0xb2, 0x03, 0xf0, 0x01, 0x03, 0x00, 0x2b, 0xe6, 0xd1,
0xfb, 0x6a, 0x7a, 0x68, 0x13, 0x44, 0x7b, 0x60, 0x3a, 0x6b, 0xfb, 0x6a, 0xd3, 0x1a, 0x3b, 0x63,
0x7b, 0x6b, 0x03, 0xf5, 0x80, 0x73, 0x7b, 0x63, 0x7a, 0x6b, 0xf9, 0x68, 0xbb, 0x68, 0x0b, 0x44,
0x9a, 0x42, 0xff, 0xf4, 0x7a, 0xaf, 0xbb, 0x68, 0x18, 0x46, 0x3c, 0x37, 0xbd, 0x46, 0x5d, 0xf8,
0x04, 0x7b, /*0x70, 0x47,*/0x00, 0xbe,/* <- */ 0x00, 0x10, 0x00, 0x40, 0x01, 0x00, 0x00, 0x10, 0x0c, 0x10, 0x00, 0x40,
0x30, 0x10, 0x00, 0x40, 0x04, 0x10, 0x00, 0x40, 0x1c, 0x10, 0x00, 0x40, 0x02, 0x00, 0x00, 0x01,
0x34, 0x10, 0x00, 0x40
};

#define TARGET_FIRMBASE  0x02020000
#define TARGET_DATABASE  0x02100000
#define TARGET_STACKBASE 0x02030000

static int lc823450_write_core(const uint8_t *buffer, uint32_t offset,
	uint32_t count)
{
	struct armv7m_algorithm armv7m_info;
	struct reg_param reg_params[4];

	LOG_DEBUG("offset=0x%08" PRIx32 " count=0x%08" PRIx32,
		offset, count);

	target_write_buffer(Target, TARGET_DATABASE, count, buffer);

	armv7m_info.common_magic = ARMV7M_COMMON_MAGIC;
	armv7m_info.core_mode = ARM_MODE_THREAD;

	init_reg_param(&reg_params[0], "r0", 32, PARAM_OUT);
	init_reg_param(&reg_params[1], "r1", 32, PARAM_OUT);
	init_reg_param(&reg_params[2], "r2", 32, PARAM_OUT);
	init_reg_param(&reg_params[3], "sp", 32, PARAM_OUT);
	buf_set_u32(reg_params[0].value, 0, 32, offset);
	buf_set_u32(reg_params[1].value, 0, 32, count);
	buf_set_u32(reg_params[2].value, 0, 32, TARGET_DATABASE);
	buf_set_u32(reg_params[3].value, 0, 32, TARGET_STACKBASE);

	while(spiflash_write_busy())
		up_udelay(10);

	target_start_algorithm(Target,
		0, NULL,
		4, reg_params,
		TARGET_FIRMBASE, TARGET_FIRMBASE + 0x12e,
		&armv7m_info);

	target_wait_algorithm(Target,
		0, NULL,
		4, reg_params,
		TARGET_FIRMBASE + 0x12e, 10 * 1000,
		&armv7m_info);

	return 0;
}

#define HASH_BLOCK_SIZE (32 * 1024)
#define HASH_BLOCK_SEC (HASH_BLOCK_SIZE / SECTOR_SIZE)

static int lc823450_write(struct flash_bank *bank, const uint8_t *buffer,
	uint32_t offset, uint32_t count)
{
	int i;
	struct timeval tv, tv_start, tv_end;
	int remains;
	const uint8_t *bufp;
#define min(a, b) ((a) > (b) ? (b) : (a))

	gettimeofday(&tv_start, NULL);

	/* Pinmux */
	putreg32(0x540000c0, PMDCNT0);
	putreg32(0x00000017, PMDCNT1);

	/* Clock & Reset */
	putreg32(MCLKCNTBASIC_SFIF_CLKEN, MCLKCNTBASIC);
	putreg32(MRSTCNTBASIC_SFIF_RSTB, MRSTCNTBASIC);

	/* mode : little endian */
	putreg32(SF_MODE_T_MODE, SF_MODE);

	target_write_buffer(Target, TARGET_FIRMBASE, sizeof(write_firm),
	    write_firm);

	remains = count;
	bufp = buffer;
	for (i = 0; i < (int)(count + SECTOR_SIZE - 1) / SECTOR_SIZE; i += HASH_BLOCK_SEC) {
		int tsize;
		int start_sec;
		tsize = min(remains, HASH_BLOCK_SIZE);

		start_sec = offset / SECTOR_SIZE + i;

		lc823450_erase_internal(start_sec, HASH_BLOCK_SEC);

		lc823450_write_core(bufp, offset + i * SECTOR_SIZE,
		    tsize);

		LOG_OUTPUT("flash offset = %d, size = %d\n",
		    offset + i * SECTOR_SIZE, tsize);

		bufp += tsize;
		remains -= tsize;
	}
	gettimeofday(&tv_end, NULL);
	timersub(&tv_end, &tv_start, &tv);
	LOG_OUTPUT("write time = %d.%06d (s)\n",
		(int)tv.tv_sec, (int)tv.tv_usec);

#if 0 /* Verify */
	{
		uint8_t *tbuf;
		tbuf = malloc(count);
		lc823450_read(offset, count, tbuf);
		if (memcmp(tbuf, buffer, count)) {
			LOG_OUTPUT("VERIFY: NG\n");
			for (i = 0; i < (int)count; i++) {
				if (buffer[i] != tbuf[i])
					LOG_OUTPUT("%d: [0x%02x][0x%02x]\n", i,
					    buffer[i], tbuf[i]);
			}
		} else
			LOG_OUTPUT("VERIFY: OK\n");

		free(tbuf);
	}
#endif
	return 0;
}

static int lc823450_probe(struct flash_bank *bank)
{
	struct lc823450_flash_bank *lc823450_info = bank->driver_priv;
	struct flash_sector *sectors;

	Target = bank->target;

	/* If we've already probed, we should be fine to skip this time. */
	if (lc823450_info->probed)
		return ERROR_OK;
	lc823450_info->probed = 0;

	/* Set correct size value */
	bank->size = FLASH_SIZE;

	/* create and fill sectors array */
	bank->num_sectors = bank->size / SECTOR_SIZE;

	sectors = malloc(sizeof(struct flash_sector) * bank->num_sectors);

	for (int sector = 0; sector < bank->num_sectors; sector++) {
		sectors[sector].offset = sector * SECTOR_SIZE;
		sectors[sector].size = SECTOR_SIZE;
		sectors[sector].is_erased = 1;
		sectors[sector].is_protected = 0;
	}

	bank->sectors = sectors;

	lc823450_info->probed = 1;
	return ERROR_OK;
}

static int lc823450_auto_probe(struct flash_bank *bank)
{
	struct lc823450_flash_bank *lc823450_info = bank->driver_priv;
	if (lc823450_info->probed)
		return ERROR_OK;
	return lc823450_probe(bank);
}

static int lc823450_protect_check(struct flash_bank *bank)
{
	/* Nothing to do. Protection is only handled in SW. */
	return ERROR_OK;
}

static int get_lc823450_info(struct flash_bank *bank, char *buf, int buf_size)
{
	struct lc823450_flash_bank *lc823450_info = bank->driver_priv;

	if (!(lc823450_info->probed)) {
		snprintf(buf, buf_size,
			"\nSPIFI flash bank not probed yet\n");
		return ERROR_OK;
	}

	snprintf(buf, buf_size, "\nSPIFI flash information:\n"
		"  Device \'%s\' (ID 0x%08" PRIx32 ")\n",
		lc823450_info->dev->name, lc823450_info->dev->device_id);

	return ERROR_OK;
}

struct flash_driver lc823450_flash = {
	.name = "lc823450",
	.flash_bank_command = lc823450_flash_bank_command,
	.erase = lc823450_erase,
	.protect = lc823450_protect,
	.write = lc823450_write,
	.read = default_flash_read,
	.probe = lc823450_probe,
	.auto_probe = lc823450_auto_probe,
	.erase_check = default_flash_blank_check,
	.protect_check = lc823450_protect_check,
	.info = get_lc823450_info,
};
