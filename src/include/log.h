/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *
 * Copyright (c) Members of the EGEE Collaboration. 2004-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Parts of this code may be based upon or even include verbatim pieces,
 * originally written by other people, in which case the original header
 * follows.
 *
 *********************************************************************/
#ifndef VOMS_LOG_H
#define VOMS_LOG_H

typedef enum { T_PRE = 0x00, T_STARTUP = 0x01, T_REQUEST = 0x02, T_RESULT = 0x04 } logtypes;
typedef enum { LEV_ERROR = 0, LEV_WARN, LEV_INFO, LEV_DEBUG, LEV_NONE} loglevels;

#include "config.h"
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

extern void       *LogInit();
extern void       *LogAddStreamer(void *, const char *,
                                  void * (*)(), 
                                  int (*)(void *, const char *), 
                                  void (*)(void *),
                                  void (*)(void *, const char *, const char*));
extern void        StartLogger(void *, int);
extern void        LogDestroy(void *);
extern loglevels   LogLevel(void *, loglevels);
extern logtypes    LogType(void *, int);
extern const char *LogDateFormat(void *, const char *);
extern const char *LogService(void *, const char *);
extern const char *LogFormat(void *, const char *);
extern int         LogMessage(void *, loglevels, logtypes, const char *, const char *, int, const char *);
extern int         LogMessageF(const char *, int, const char *, void *, loglevels, logtypes, const char *, ...);
extern int         LogBuffer(FILE *, void *, loglevels, logtypes, const char *);
extern logtypes    SetCurLogType(void *, logtypes);
extern void        LogActivate(void *, const char *);
extern void        LogDeactivate(void *, const char *);
extern void        LogOption(void *, const char *, const char *);
extern void        LogOptionInt(void *, const char *, int);
extern void        SetOwner(pid_t);
extern int         LogLevelMin(void *, loglevels);

#define LOG(h, lev, type, str) \
LogMessage((h), (lev), (type), (str), FUNC_NAME, __LINE__, __FILE__)

#define LOGM LogMessageF 

#define VARP FUNC_NAME, __LINE__, __FILE__

#endif /* VOMS_LOG_H */
