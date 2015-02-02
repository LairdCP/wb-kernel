/*
 * Copyright (c) 2013 Laird, Inc.
 * Licensed under GPLv2.
 */

#ifndef _MODDEBUG_H_
#define _MODDEBUG_H_

#ifdef LAIRD_DEBUG
extern void _printkhexs(const char *psz, const char *pfx,
			const void *buf, int len);
#else
#define _printkhexs(psz,pfx,buf,len)
#endif

#endif
