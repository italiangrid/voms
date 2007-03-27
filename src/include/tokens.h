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
/***************************************************************************
 *  filename  : tokens.h
 *  authors   : Salvatore Monforte <salvatore.monforte@ct.infn.it>
 *  copyright : (C) 2001 by INFN
 ***************************************************************************/

// $Id:

/**
 * @file tokens.h
 * @brief The definition for token transmission and reception.
 * This file provides a couple of methods to send and receive tokens.
 * @author Salvatore Monforte salvatore.monforte@ct.infn.it
 * @author comments by Marco Pappalardo marco.pappalardo@ct.infn.it and Salvatore Monforte
 */

#ifndef VOMS_TOKENS_H
#define VOMS_TOKENS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <unistd.h>

int send_token(void *arg, void * token, size_t  token_length);
int get_token(void *arg, void ** token, size_t * token_length);

#ifdef __cplusplus
}
#endif
#endif /* _TOKENS_H */

/*
  Local Variables:
  mode: c++
  End:
*/

