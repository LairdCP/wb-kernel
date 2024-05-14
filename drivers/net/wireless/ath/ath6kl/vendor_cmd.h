/*
 * Copyright (C) 2017-2024, Ezurio
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

#ifndef VENDOR_CMD_H
#define VENDOR_CMD_H

void summit_set_vendor_commands(struct wiphy *wiphy);
void summit_update_roam_params(struct ath6kl *ar, u8 if_idx);
void summit_update_pm_params(struct ath6kl *ar, u8 if_idx);

#endif
