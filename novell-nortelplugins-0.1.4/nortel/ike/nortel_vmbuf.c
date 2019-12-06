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
#include <sys/types.h>
#include <sys/param.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "nortel_vmbuf.h"
#include "racoon/vmbuf.h"

vchar_t * nortel_vmalloc(size) 
        size_t size;
{
    vchar_t *var;

    if ((var = (vchar_t *)malloc(sizeof(*var))) == NULL)
        return NULL;

    var->l = size;
    if (size == 0) {
        var->v = NULL;
    } else {
        var->v = (caddr_t)calloc(1, size);
        if (var->v == NULL) {
            free(var);
            return NULL;
        }
    }

    return var;
}

void nortel_vfree(var)
    vchar_t *var;
{
    if (var == NULL)
        return;

    if (var->v)
        (void)free(var->v);

    (void)free(var);

    return;
}

