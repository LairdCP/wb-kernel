/*
 * Copyright (C) 2019-2020, Ezurio
 *
 * This software file (the "File") is distributed by Ezurio
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

#include <linux/netlink.h>
#include <net/genetlink.h>

#include "core.h"
#include "vendor_cmd.h"

#define SUMMIT_OUI 0xC0EE40

enum vendor_commands {
	VENDOR_CMD_MFG_START = 1,
	VENDOR_CMD_MFG_WRITE,
	VENDOR_CMD_MFG_STOP,
	VENDOR_CMD_LRU_START,
	VENDOR_CMD_LRU_WRITE,
	VENDOR_CMD_LRU_STOP,
	VENDOR_CMD_WRITE,
	VENDOR_CMD_PROFILE_SET_PARMS = 20,
	VENDOR_CMD_MAX,
};

enum nlattrs {
	ATTR_UNUSED = 0,
	ATTR_CMD_RSP,
	ATTR_DATA,
	ATTR_PROFILE_PARMS_ROAM_TRIGGER = 20,	// S32
	ATTR_PROFILE_PARMS_ROAM_DELTA,		// U32
	ATTR_PROFILE_PARMS_ROAM_PERIOD,		// U32
	ATTR_PROFILE_PARMS_ACTIVE_DWELL_TIME,	// U32
	ATTR_PROFILE_PARMS_PASSIVE_DWELL_TIME,	// U32
	ATTR_PROFILE_PARMS_MAX_SCAN_INTERVAL,	// U32
	ATTR_PROFILE_PARMS_BMISS_TIMEOUT,	// U32
	ATTR_MAX
};


static const
struct nla_policy vendor_attr_policy[ATTR_MAX] = {
	[ATTR_PROFILE_PARMS_ROAM_TRIGGER]	= { .type = NLA_S32 },
	[ATTR_PROFILE_PARMS_ROAM_DELTA]		= { .type = NLA_U32 },
	[ATTR_PROFILE_PARMS_ROAM_PERIOD]	= { .type = NLA_U32 },
	[ATTR_PROFILE_PARMS_PASSIVE_DWELL_TIME]	= { .type = NLA_U32 },
	[ATTR_PROFILE_PARMS_MAX_SCAN_INTERVAL]	= { .type = NLA_U32 },
	[ATTR_PROFILE_PARMS_BMISS_TIMEOUT]	= { .type = NLA_U32 },
};

#define PASSIVE_DWELL_TIME_DEFAULT		160
#define PASSIVE_DWELL_TIME_MIN			20
#define PASSIVE_DWELL_TIME_MAX			500

#define SCAN_CTRL_FLAGS				0x7F

#define FG_START_PERIOD				1
#define FG_END_PERIOD_DEFAULT			10
#define FG_END_PERIOD_MIN			2
#define FG_END_PERIOD_MAX			120

#define BMISS_TIME_DEFAULT			3000

// Firmware takes roam/scan period in milliseconds
// Vendor command definition is in seconds
#define SCAN_PERIOD_DEFAULT			5000
#define ROAM_PERIOD_MIN				2
#define ROAM_PERIOD_MAX				60

#define AR600X_NOISE_FLOOR_DBM			(-95)
#define ROAM_TRIGGER_DEFAULT			(-70)
#define ROAM_TRIGGER_MIN			(-90)
#define ROAM_TRIGGER_MAX			(-50)
#define LRSSI_THRESHOLD_DEFAULT			(ROAM_TRIGGER_DEFAULT - AR600X_NOISE_FLOOR_DBM)

#define ROAM_DELTA_DEFAULT			10
#define ROAM_DELTA_MIN				0
#define ROAM_DELTA_MAX				55

#define PM_PARMS_IDLE_PERIOD_DEFAULT		200
#define PM_PARMS_PSPOLL_NUMBER			1
#define PM_PARMS_NUM_TX_WAKEUP			1
#define PM_PARMS_TX_WAKEUP_POLICY		1

static int
vendor_cmd_profile_set_parms(struct wiphy *wiphy, struct wireless_dev *wdev,
			     const void *data, int data_len)
{
	struct ath6kl *ar = (struct ath6kl *)wiphy_priv(wiphy);
	struct nlattr *tb[ATTR_MAX+1];
	int rc = 0;

	if (!data)
		return -EINVAL;

	rc = nla_parse(tb, ATTR_MAX, data, data_len,
			vendor_attr_policy, NULL);
	if (rc)
		return rc;

	// Set parameters to default values and update as needed
	// Note that some are configurable via vendor command, others are not
	ar->summit_ext.scan_ctrl_flags = SCAN_CTRL_FLAGS;
	ar->summit_ext.bmiss_time = BMISS_TIME_DEFAULT;
	ar->summit_ext.fg_start_period = FG_START_PERIOD;

	// passive channel dwell time
	if (!ar->summit_ext.pas_chdwell_time)
		ar->summit_ext.pas_chdwell_time = PASSIVE_DWELL_TIME_DEFAULT;
	if (tb[ATTR_PROFILE_PARMS_PASSIVE_DWELL_TIME])
	{
		u16 tmp = (u16)nla_get_u32(tb[ATTR_PROFILE_PARMS_PASSIVE_DWELL_TIME]);
		if ((tmp >= PASSIVE_DWELL_TIME_MIN) && (tmp <= PASSIVE_DWELL_TIME_MAX))
			ar->summit_ext.pas_chdwell_time = tmp;
	}

	// maximum foreground scan period after backoff
	if (!ar->summit_ext.fg_end_period)
		ar->summit_ext.fg_end_period = FG_END_PERIOD_DEFAULT;
	if (tb[ATTR_PROFILE_PARMS_MAX_SCAN_INTERVAL])
	{
		u16 tmp = (u16)nla_get_u32(tb[ATTR_PROFILE_PARMS_MAX_SCAN_INTERVAL]);
		if ((tmp >= FG_END_PERIOD_MIN) && (tmp <= FG_END_PERIOD_MAX))
			ar->summit_ext.fg_end_period = tmp;
	}

	// roam period
	if (!ar->lrssi_scan_period)
		ar->lrssi_scan_period = SCAN_PERIOD_DEFAULT;
	if (tb[ATTR_PROFILE_PARMS_ROAM_PERIOD])
	{
		u16 tmp = (u16)nla_get_u32(tb[ATTR_PROFILE_PARMS_ROAM_PERIOD]);
		if ((tmp >= ROAM_PERIOD_MIN) && (tmp <= ROAM_PERIOD_MAX)) {
			// Input parameter is seconds, firmware takes milliseconds
			ar->lrssi_scan_period = tmp * 1000;
		}
	}

	// roam trigger
	if (tb[ATTR_PROFILE_PARMS_ROAM_TRIGGER])
	{
		s32 tmp = nla_get_s32(tb[ATTR_PROFILE_PARMS_ROAM_TRIGGER]);
		if ((tmp >= ROAM_TRIGGER_MIN) && (tmp <= ROAM_TRIGGER_MAX))
			ar->lrssi_roam_threshold = (u8)(tmp - AR600X_NOISE_FLOOR_DBM);
	}

	// roam delta
	if (!ar->summit_ext.roam_delta)
		ar->summit_ext.roam_delta = ROAM_DELTA_DEFAULT;
	if (tb[ATTR_PROFILE_PARMS_ROAM_DELTA])
	{
		u8 tmp = (u8)nla_get_u32(tb[ATTR_PROFILE_PARMS_ROAM_DELTA]);
		if ((tmp >= ROAM_DELTA_MIN) && (tmp <= ROAM_DELTA_MAX))
			ar->summit_ext.roam_delta = tmp;
	}

	ar->summit_ext.profile_initialized = true;

	return rc;
}

void summit_update_roam_params(struct ath6kl *ar, u8 if_idx)
{
	if (!ar->summit_ext.profile_initialized)
		return;

	ath6kl_wmi_set_roam_lrssi_cmd(ar->wmi, ar->lrssi_roam_threshold, ar->lrssi_scan_period);
	ath6kl_wmi_set_roam_delta_cmd(ar->wmi, ar->summit_ext.roam_delta);
	ath6kl_wmi_bmisstime_cmd(ar->wmi, if_idx, ar->summit_ext.bmiss_time, 0);
}

void summit_update_pm_params(struct ath6kl *ar, u8 if_idx)
{
	ath6kl_wmi_pmparams_cmd(ar->wmi, if_idx, PM_PARMS_IDLE_PERIOD_DEFAULT,
				PM_PARMS_PSPOLL_NUMBER, 0, PM_PARMS_TX_WAKEUP_POLICY,
				PM_PARMS_NUM_TX_WAKEUP, 0);
}

static const struct wiphy_vendor_command wiphy_vendor_commands[] = {
	{
		.info = {
			.vendor_id = SUMMIT_OUI,
			.subcmd    = VENDOR_CMD_PROFILE_SET_PARMS,
		},
		.flags = 0,
		.doit  = vendor_cmd_profile_set_parms,
		.policy = vendor_attr_policy,
	},
};

void summit_set_vendor_commands(struct wiphy *wiphy)
{
	wiphy->vendor_commands   = wiphy_vendor_commands;
	wiphy->n_vendor_commands = ARRAY_SIZE(wiphy_vendor_commands);
}
