/*
 * Copyright (C) 2005-2009 Novell, Inc.
 * 
 * All rights reserved.
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, contact Novell, Inc.
 * 
 * To contact Novell about this file by physical or electronic mail,
 * you may find current contact information at www.novell.com.
 */
#include <stdio.h>
#include <stdarg.h>

#include "helper.h"

/*
static int isFileExist (char *filename);

static int
isFileExist(char *string)
{
	struct stat buf;
	
	if(lstat(string,&buf)<0) {
		return -1;
	}
	else if(!S_ISREG(buf.st_mode) || (buf.st_size==0)) {
		return -1;
	}
	return 0;
}*/

int checkuname(char *str)
{
	int i, len;
	
	len = strlen(str);
	if(len == 0)
		return -1;
		
	for(i = 0; i < len; i++)
	{
		if(str[i] ==' ')
			return -1;
	}
	return 0;
}


void show_error_message (char * format, ...)
{
	va_list params;
	
	va_start (params, format);
	vfprintf (stderr, (const char *) format, params);
	va_end (params);
}
