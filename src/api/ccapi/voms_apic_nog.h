/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *
 * Copyright (c) 2002, 2003 INFN-CNAF on behalf of the EU DataGrid.
 * For license conditions see LICENSE file or
 * http://www.edg.org/license.html
 *
 * Parts of this code may be based upon or even include verbatim pieces,
 * originally written by other people, in which case the original header
 * follows.
 *
 *********************************************************************/

#ifndef VOMS_APIC_NOG_H
#define VOMS_APIC_NOG_H

#ifndef VOMS_APIC_H
#ifdef __cplusplus
extern "C" {
#endif
#define NOGLOBUS
#include <voms_apic.h>
#undef NOGLOBUS
#ifdef __cplusplus
}
#endif
#else
#error The Globus and Globus-free versions are not compatible!
#endif
#endif
