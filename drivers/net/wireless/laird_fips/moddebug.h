/*
 * Copyright (c) 2013 Laird, Inc.
 * Licensed under GPLv2.
 */

#ifndef _MODDEBUG_H_
#define _MODDEBUG_H_

#define DEBUG_TRACE0
#define DEBUG_TRACE1 \
	printk(KERN_ALERT "%s: line %d\n", __FUNCTION__, __LINE__);

/* debug output disabled */
#define _printkhexs(psz,pfx,buf,len)
#define DEBUG_TRACE DEBUG_TRACE0

#ifndef _printkhexs
extern void _printkhexs(const char *psz, const char *pfx,
			const void *buf, int len);
#endif

#ifndef DEBUG_TRACE
#define DEBUG_TRACE DEBUG_TRACE1
#endif

#endif
