/*
 * Copyright (C) 2019-2020, Laird Connectivity
 *
 * This software file (the "File") is distributed by Laird Connectivity
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


static const
struct nla_policy lrd_vendor_attr_policy[LRD_ATTR_MAX] = {
	[LRD_ATTR_PROFILE_PARMS_ROAM_TRIGGER]		= { .type = NLA_S32 },
	[LRD_ATTR_PROFILE_PARMS_ROAM_DELTA]		= { .type = NLA_U32 },
	[LRD_ATTR_PROFILE_PARMS_ROAM_PERIOD]		= { .type = NLA_U32 },
	[LRD_ATTR_PROFILE_PARMS_PASSIVE_DWELL_TIME]	= { .type = NLA_U32 },
	[LRD_ATTR_PROFILE_PARMS_MAX_SCAN_INTERVAL]	= { .type = NLA_U32 },
	[LRD_ATTR_PROFILE_PARMS_BMISS_TIMEOUT]		= { .type = NLA_U32 },
};

#define LRD_PASSIVE_DWELL_TIME_DEFAULT		160
#define LRD_PASSIVE_DWELL_TIME_MIN		20
#define LRD_PASSIVE_DWELL_TIME_MAX		500

#define LRD_SCAN_CTRL_FLAGS			0x7F

#define LRD_FG_START_PERIOD			1
#define LRD_FG_END_PERIOD_DEFAULT		10
#define LRD_FG_END_PERIOD_MIN			2
#define LRD_FG_END_PERIOD_MAX			120

#define LRD_BMISS_TIME_DEFAULT			3000

// Firmware takes roam/scan period in milliseconds
// Vendor command definition is in seconds
#define LRD_SCAN_PERIOD_DEFAULT			5000
#define LRD_ROAM_PERIOD_MIN			2
#define LRD_ROAM_PERIOD_MAX			60

#define AR600X_NOISE_FLOOR_DBM			(-95)
#define LRD_ROAM_TRIGGER_DEFAULT		(-70)
#define LRD_ROAM_TRIGGER_MIN			(-90)
#define LRD_ROAM_TRIGGER_MAX			(-50)
#define LRD_LRSSI_THRESHOLD_DEFAULT		((LRD_ROAM_TRIGGER_DEFAULT - AR600X_NOISE_FLOOR_DBM))

#define LRD_ROAM_DELTA_DEFAULT			10
#define LRD_ROAM_DELTA_MIN			0
#define LRD_ROAM_DELTA_MAX			55

#define LRD_PM_PARMS_IDLE_PERIOD_DEFAULT	200
#define LRD_PM_PARMS_PSPOLL_NUMBER		1
#define LRD_PM_PARMS_NUM_TX_WAKEUP		1
#define LRD_PM_PARMS_TX_WAKEUP_POLICY		1

static int
lrd_vendor_cmd_profile_set_parms(struct wiphy *wiphy, struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	struct ath6kl *ar = (struct ath6kl *)wiphy_priv(wiphy);
	struct nlattr *tb[LRD_ATTR_MAX+1];
	int rc = 0;

	if (!data)
		return -EINVAL;

	rc = nla_parse(tb, LRD_ATTR_MAX, data, data_len,
			lrd_vendor_attr_policy, NULL);
	if (rc)
		return rc;

	// Set parameters to laird default values and update as needed
	// Note that some are configurable via vendor command, others are not
	ar->laird.scan_ctrl_flags = LRD_SCAN_CTRL_FLAGS;
	ar->laird.bmiss_time = LRD_BMISS_TIME_DEFAULT;
	ar->laird.fg_start_period = LRD_FG_START_PERIOD;

	// passive channel dwell time
	if (!ar->laird.pas_chdwell_time)
		ar->laird.pas_chdwell_time = LRD_PASSIVE_DWELL_TIME_DEFAULT;
	if (tb[LRD_ATTR_PROFILE_PARMS_PASSIVE_DWELL_TIME])
	{
		u16 tmp = (u16)nla_get_u32(tb[LRD_ATTR_PROFILE_PARMS_PASSIVE_DWELL_TIME]);
		if ((tmp >= LRD_PASSIVE_DWELL_TIME_MIN) && (tmp <= LRD_PASSIVE_DWELL_TIME_MAX))
			ar->laird.pas_chdwell_time = tmp;
	}

	// maximum foreground scan period after backoff
	if (!ar->laird.fg_end_period)
		ar->laird.fg_end_period = LRD_FG_END_PERIOD_DEFAULT;
	if (tb[LRD_ATTR_PROFILE_PARMS_MAX_SCAN_INTERVAL])
	{
		u16 tmp = (u16)nla_get_u32(tb[LRD_ATTR_PROFILE_PARMS_MAX_SCAN_INTERVAL]);
		if ((tmp >= LRD_FG_END_PERIOD_MIN) && (tmp <= LRD_FG_END_PERIOD_MAX))
			ar->laird.fg_end_period = tmp;
	}

	// roam period
	if (!ar->lrssi_scan_period)
		ar->lrssi_scan_period = LRD_SCAN_PERIOD_DEFAULT;
	if (tb[LRD_ATTR_PROFILE_PARMS_ROAM_PERIOD])
	{
		u16 tmp = (u16)nla_get_u32(tb[LRD_ATTR_PROFILE_PARMS_ROAM_PERIOD]);
		if ((tmp >= LRD_ROAM_PERIOD_MIN) && (tmp <= LRD_ROAM_PERIOD_MAX)) {
			// Input parameter is seconds, firmware takes milliseconds
			ar->lrssi_scan_period = tmp * 1000;
		}
	}

	// roam trigger
	if (tb[LRD_ATTR_PROFILE_PARMS_ROAM_TRIGGER])
	{
		s32 tmp = nla_get_s32(tb[LRD_ATTR_PROFILE_PARMS_ROAM_TRIGGER]);
		if ((tmp >= LRD_ROAM_TRIGGER_MIN) && (tmp <= LRD_ROAM_TRIGGER_MAX))
			ar->lrssi_roam_threshold = (u8)(tmp - AR600X_NOISE_FLOOR_DBM);
	}

	// roam delta
	if (!ar->laird.roam_delta)
		ar->laird.roam_delta = LRD_ROAM_DELTA_DEFAULT;
	if (tb[LRD_ATTR_PROFILE_PARMS_ROAM_DELTA])
	{
		u8 tmp = (u8)nla_get_u32(tb[LRD_ATTR_PROFILE_PARMS_ROAM_DELTA]);
		if ((tmp >= LRD_ROAM_DELTA_MIN) && (tmp <= LRD_ROAM_DELTA_MAX))
			ar->laird.roam_delta = tmp;
	}

	ar->laird.profile_initialized = true;

	return rc;
}

void lrd_update_roam_params(struct ath6kl *ar, u8 if_idx)
{
	if (!ar->laird.profile_initialized)
		return;

	ath6kl_wmi_set_roam_lrssi_cmd(ar->wmi, ar->lrssi_roam_threshold, ar->lrssi_scan_period);
	ath6kl_wmi_set_roam_delta_cmd(ar->wmi, ar->laird.roam_delta);
	ath6kl_wmi_bmisstime_cmd(ar->wmi, if_idx, ar->laird.bmiss_time, 0);
}

void lrd_update_pm_params(struct ath6kl *ar, u8 if_idx)
{
	ath6kl_wmi_pmparams_cmd(ar->wmi, if_idx, LRD_PM_PARMS_IDLE_PERIOD_DEFAULT,
				LRD_PM_PARMS_PSPOLL_NUMBER, 0, LRD_PM_PARMS_TX_WAKEUP_POLICY,
				LRD_PM_PARMS_NUM_TX_WAKEUP, 0);
}

static const struct wiphy_vendor_command lrd_vendor_commands[] = {
	{
		.info = {
			.vendor_id = LRD_OUI,
			.subcmd    = LRD_VENDOR_CMD_PROFILE_SET_PARMS,
		},
		.flags = 0,
		.doit  = lrd_vendor_cmd_profile_set_parms,
		.policy = lrd_vendor_attr_policy,
	},
};

void lrd_set_vendor_commands(struct wiphy *wiphy)
{
	wiphy->vendor_commands   = lrd_vendor_commands;
	wiphy->n_vendor_commands = ARRAY_SIZE(lrd_vendor_commands);
}
