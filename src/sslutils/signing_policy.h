/* A Bison parser, made by GNU Bison 3.7.4.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2020 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

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

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

#ifndef YY_SIGNING_SIGNING_POLICY_H_INCLUDED
# define YY_SIGNING_SIGNING_POLICY_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 1
#endif
#if YYDEBUG
extern int signingdebug;
#endif

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    YYEOF = 0,                     /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    SUBJECTS = 258,                /* SUBJECTS  */
    COND_SUBJECTS = 259,           /* COND_SUBJECTS  */
    COND_BANNED = 260,             /* COND_BANNED  */
    GLOBUS = 261,                  /* GLOBUS  */
    POS_RIGHTS = 262,              /* POS_RIGHTS  */
    NEG_RIGHTS = 263,              /* NEG_RIGHTS  */
    CA_SIGN = 264,                 /* CA_SIGN  */
    ACCESS_ID_CA = 265,            /* ACCESS_ID_CA  */
    ACCESS_ID_ANYBODY = 266,       /* ACCESS_ID_ANYBODY  */
    X509 = 267                     /* X509  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif
/* Token kinds.  */
#define YYEMPTY -2
#define YYEOF 0
#define YYerror 256
#define YYUNDEF 257
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

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 48 "signing_policy.y"

  char *string;
  struct condition *cond;
  struct policy *policy;
  void *array;

#line 98 "signing_policy.h"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif



int signingparse (struct policy ***policies, void *scanner);

#endif /* !YY_SIGNING_SIGNING_POLICY_H_INCLUDED  */
