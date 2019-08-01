/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _FIPS_H
#define _FIPS_H

#ifdef CONFIG_CRYPTO_FIPS
extern int fips_enabled;
extern int fips_wifi_enabled;
#else
#define fips_enabled 0
#define fips_wifi_enabled 0
#endif

#endif
