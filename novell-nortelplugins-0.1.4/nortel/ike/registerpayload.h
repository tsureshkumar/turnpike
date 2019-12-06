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
#ifndef __REGISTERPAYLOAD_H__
#define __REGISTERPAYLOAD_H__

/* Framework headers */
#include "plugin_frame/common.h"
#include "plugin_frame/position.h"
    
#if 0
int constructHookPoint(struct hookpoint *hook, u_int8_t type, u_int8_t AttrOrPayloadType, u_int8_t AttrOrPayloadSubType, u_int32_t position, u_int8_t mandatoryOrOptional, u_int32_t keylen, void *KEY);

int constructHandlerInfo( struct handlerinfo *hi, u_int32_t DataTypeToBeSent, u_int32_t DataTypeToBeRecvd, CALLBACK callback);
#endif

int registerThis(struct hookpoint *hp, struct handlerinfo *hi);
int registerQMStartCallback();
int registerNotifyPayloadCallback();
int registerIsPayloadExistencyCheckCallback();
int registerIsPhase2CompleteCallback();
int registerIsRekeyReqCallback();
int registerVIDPayloadCallback();
int registerCheckVIDPayloadCallback();
int registerOpaqueIDCallback();
int registerGeneratePSKCallback();
int registerCfgSetAckCallback ();

#endif
