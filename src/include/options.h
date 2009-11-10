/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *
 * Copyright (c) 2002-2009 INFN-CNAF on behalf of the EU DataGrid
 * and EGEE I, II and III
 * For license conditions see LICENSE file or
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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
