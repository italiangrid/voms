/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton interface for Bison's Yacc-like parsers in C

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     SUBJECTS = 258,
     COND_SUBJECTS = 259,
     COND_BANNED = 260,
     GLOBUS = 261,
     POS_RIGHTS = 262,
     NEG_RIGHTS = 263,
     CA_SIGN = 264,
     ACCESS_ID_CA = 265,
     ACCESS_ID_ANYBODY = 266,
     X509 = 267
   };
#endif
/* Tokens.  */
#define SUBJECTS 258
#define COND_SUBJECTS 259
#define COND_BANNED 260
#define GLOBUS 261
#define POS_RIGHTS 262
#define NEG_RIGHTS 263
#define CA_SIGN 264
#define ACCESS_ID_CA 265
#define ACCESS_ID_ANYBODY 266
#define X509 267




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 37 "signing_policy.y"
{
  char *string;
  struct condition *cond;
  struct policy *policy;
  void *array;
}
/* Line 1489 of yacc.c.  */
#line 80 "signing_policy.h"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



