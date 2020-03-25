/*
 * Copyright (C) 2017-2020, Laird Connectivity
 *
 * This software file (the "File") is distributed by Laird, PLC.
 * under the terms of the GNU General Public License Version 2, June 1991
 * (the "License").  You may use, redistribute and/or modify this File in
 * accordance with the terms and conditions of the License, a copy of which
 * is available by writing to the Free Software Foundation, Inc.
 *
 * THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE
 * ARE EXPRESSLY DISCLAIMED.  The License provides additional details about
 * this warranty disclaimer.
 */

#ifndef _LRD_VENDOR_CMD_H_
#define _LRD_VENDOR_CMD_H_

#define LRD_OUI 0xC0EE40

enum lrd_vendor_commands {
	LRD_VENDOR_CMD_MFG_START = 1,
	LRD_VENDOR_CMD_MFG_WRITE,
	LRD_VENDOR_CMD_MFG_STOP,
	LRD_VENDOR_CMD_LRU_START,
	LRD_VENDOR_CMD_LRU_WRITE,
	LRD_VENDOR_CMD_LRU_STOP,
	LRD_VENDOR_CMD_LRD_WRITE,
	LRD_VENDOR_CMD_PROFILE_SET_PARMS = 20,
	LRD_VENDOR_CMD_MAX,
};

enum lrd_nlattrs {
	LRD_ATTR_UNUSED = 0,
	LRD_ATTR_CMD_RSP,
	LRD_ATTR_DATA,
	LRD_ATTR_PROFILE_PARMS_ROAM_TRIGGER = 20,	// S32
	LRD_ATTR_PROFILE_PARMS_ROAM_DELTA,		// U32
	LRD_ATTR_PROFILE_PARMS_ROAM_PERIOD,		// U32
	LRD_ATTR_PROFILE_PARMS_ACTIVE_DWELL_TIME,	// U32
	LRD_ATTR_PROFILE_PARMS_PASSIVE_DWELL_TIME,	// U32
	LRD_ATTR_PROFILE_PARMS_MAX_SCAN_INTERVAL,	// U32
	LRD_ATTR_PROFILE_PARMS_BMISS_TIMEOUT,		// U32
	LRD_ATTR_MAX
};

void lrd_set_vendor_commands(struct wiphy *wiphy);
void lrd_update_roam_params(struct ath6kl *ar, u8 if_idx);
void lrd_update_pm_params(struct ath6kl *ar, u8 if_idx);
#endif
