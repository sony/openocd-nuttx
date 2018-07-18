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

#ifndef OPENOCD_FLASH_NOR_LC823450_SPIFI_H
#define OPENOCD_FLASH_NOR_LC823450_SPIFI_H

#define LC823450_SFLASH_REGBASE 0x40001000

#define SF_SIZE 	(LC823450_SFLASH_REGBASE + 0x00)
#define 	SF_SIZE_T_SHIFT		0
#define 	SF_SIZE_UL_SHIFT	24
#define 	SF_SIZE_NOREAD		(1 << 28)
#define SF_CTL		(LC823450_SFLASH_REGBASE + 0x04)
#define 	SF_CTL_ACT		(1 << 0)
#define SF_MODE		(LC823450_SFLASH_REGBASE + 0x08)
#define 	SF_MODE_MODE_SHIFT	0
#define 	SF_MODE_T_MODE		(1 << 8)
#define SF_DUMMY	(LC823450_SFLASH_REGBASE + 0x0c)
#define 	SF_DUMMY_DUMMY		(1 << 0)
#define SF_FIFO_CLR	(LC823450_SFLASH_REGBASE + 0x10)
#define SF_STATUS	(LC823450_SFLASH_REGBASE + 0x14)
#define SF_IRQEN	(LC823450_SFLASH_REGBASE + 0x18)
#define SF_FIFO_NUM	(LC823450_SFLASH_REGBASE + 0x1c)
#define 	SF_FIFO_NUM_T_SHIFT	0
#define 	SF_FIFO_NUM_T_MASK	(0xf << SF_FIFO_NUM_T_SHIFT)
#define 	SF_FIFO_NUM_R_SHIFT	8
#define 	SF_FIFO_NUM_R_MASK	(0xf << SF_FIFO_NUM_R_SHIFT)
#define SF_SRSTB	(LC823450_SFLASH_REGBASE + 0x20)
#define SF_PHASE_SET	(LC823450_SFLASH_REGBASE + 0x24)
#define SF_BUS		(LC823450_SFLASH_REGBASE + 0x28)
#define 	SF_BUS_BUSEN		(1 << 0)
#define 	SF_BUS_BUSMODE_SHIFT	8
#define SF_TIMING	(LC823450_SFLASH_REGBASE + 0x2c)
#define SF_T_FIFO	(LC823450_SFLASH_REGBASE + 0x30)
#define SF_R_FIFO	(LC823450_SFLASH_REGBASE + 0x34)

#define SF_CMD_PAGE_PROG	0x02
#define SF_CMD_READ_STATUS1	0x05
#define SF_CMD_WRITE_EN		0x06
#define SF_CMD_FAST_READ	0x0b
#define SF_CMD_SEC_ERASE	0x20
#define SF_CMD_BLK_ERASE32	0x52
#define SF_CMD_BLK_ERASE64	0xd8
#define SF_CMD_WRITE_STATUS2	0x31
#define SF_CMD_SR_WRITE_EN	0x50
#define SF_CMD_CHIP_ERASE	0x60
#define SF_CMD_FAST_READ_QUAD	0x6b

#define SF_STATUS1_BUSY	(1 << 0)
#define SF_STATUS2_QE	(1 << 1)

#endif /* OPENOCD_FLASH_NOR_LC823450_SPIFI_H */
