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
#ifndef VOMS_OPTIONS_H
#define VOMS_OPTIONS_H
#define __USE_GNU 1
#include <string>

extern "C" {
#if defined(HAVE_GETOPT_LONG) || defined(HAVE_GETOPT_LONG_ONLY)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <getopt.h>
#endif
#include <unistd.h>
#include "getopts.h"
}

#define OPT_NONE      0
#define OPT_BOOL      1
#define OPT_NUM       2
#define OPT_STRING    3
#define OPT_MULTI     4
#define OPT_CONFIG    5
#define OPT_HELP      6

extern bool getopts(int argc, char * const argv[], struct option *longopts);
extern void set_usage(std::string);
#endif /*___OPTIONS_H */
