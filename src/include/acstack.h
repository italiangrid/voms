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
#ifndef VOMS_ACSTACK_H
#define VOMS_ACSTACK_H

#include <openssl/asn1.h>
#include <openssl/stack.h>
#include <openssl/safestack.h>

#ifndef VOMS_MAYBECONST
#if defined(D2I_OF)
#define VOMS_MAYBECONST const
#else
#define VOMS_MAYBECONST
/* typedef void *d2i_of_void(void *, unsigned char **); */
#endif
#endif

#define IMPL_STACK(type) \
   DECLARE_STACK_OF(type) \
   STACK_OF(type) *sk_##type##_new (int (*cmp)(const type * const *, const type * const *)) \
       { return sk_new ( (int (*)(const char * const *, const char * const *))cmp);} \
   STACK_OF(type) *sk_##type##_new_null () { return sk_new_null(); } \
   void   sk_##type##_free (STACK_OF(type) *st) { sk_free(st); } \
   int    sk_##type##_num (const STACK_OF(type) *st) { return sk_num(st); } \
   type  *sk_##type##_value (const STACK_OF(type) *st, int i) { return (type *)sk_value(st, i); } \
   int    sk_##type##_push (STACK_OF(type) *st, type *val) { return sk_push(st, (char *)val); } \
   STACK_OF(type) *sk_##type##_dup (STACK_OF(type) *st) { return sk_dup(st); } \
   STACK_OF(type) *d2i_ASN1_SET_OF_##type (STACK_OF(type) **st, VOMS_MAYBECONST unsigned char **pp, long length, type *(*d2ifunc)(), void (*freefunc)(type *), int ex_tag, int ex_class) \
       { return d2i_ASN1_SET(st, pp, length, (char *(*)())d2ifunc, (void (*)(void *))freefunc, ex_tag, ex_class); } \
   int i2d_ASN1_SET_OF_##type (STACK_OF(type) *st, unsigned char **pp, int (*i2dfunc)(), int ex_tag, int ex_class, int is_set) \
       { return i2d_ASN1_SET(st, pp, i2dfunc, ex_tag, ex_class, is_set); } \
   void   sk_##type##_pop_free (STACK_OF(type) *st, void (*func)(type *)) { sk_pop_free(st, (void (*)(void *))func); }

#define DECL_STACK(type) \
   PREDECLARE_STACK_OF(type) \
   extern STACK_OF(type) *sk_##type##_new (int (*)(const type * const *, const type * const *)); \
   extern STACK_OF(type) *sk_##type##_new_null (); \
   extern void   sk_##type##_free (STACK_OF(type) *); \
   extern int    sk_##type##_num (const STACK_OF(type) *); \
   extern type  *sk_##type##_value (const STACK_OF(type) *, int); \
   extern type  *sk_##type##_set (STACK_OF(type) *, int, type *); \
   extern void   sk_##type##_zero (STACK_OF(type) *); \
   extern int    sk_##type##_push (STACK_OF(type) *, type *); \
   extern int    sk_##type##_unshift (STACK_OF(type) *, type *); \
   extern int    sk_##type##_find (STACK_OF(type) *, type *); \
   extern type  *sk_##type##_delete (STACK_OF(type) *, int); \
   extern type  *sk_##type##_delete_ptr (STACK_OF(type) *, type *); \
   extern int    sk_##type##_insert (STACK_OF(type) *, type *, int); \
   extern int (*sk_##type##_set_cmp_func (STACK_OF(type) *, int (*)(const type * const *, const type * const *)))(const type * const *, const type * const *); \
   extern STACK_OF(type) *sk_##type##_dup (STACK_OF(type) *); \
   extern void   sk_##type##_pop_free (STACK_OF(type) *, void (*)(type *)); \
   extern type  *sk_##type##_shift (STACK_OF(type) *); \
   extern type  *sk_##type##_pop (STACK_OF(type) *); \
   extern void   sk_##type##_sort (STACK_OF(type) *); \
   extern STACK_OF(type) *d2i_ASN1_SET_OF_##type (STACK_OF(type) **, VOMS_MAYBECONST unsigned char **, long, type *(*)(), void (*)(type *), int, int); \
   extern int i2d_ASN1_SET_OF_##type (STACK_OF(type) *, unsigned char **, int (*)(), int, int, int); \
   extern unsigned char *ASN1_seq_pack_##type (STACK_OF(type) *, int (*)(), unsigned char **, int *); \
   extern STACK_OF(type) *ASN1_seq_unpack_##type (unsigned char *, int, type *(*)(), void (*)(type *)) ;



#endif
