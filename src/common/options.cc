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
#include "config.h"

#define __USE_GNU 1

extern "C" {
#include <stdlib.h>
#include <stdio.h>
#if defined(HAVE_GETOPT_LONG) || defined(HAVE_GETOPT_LONG_ONLY)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <getopt.h>
#endif
#include "getopts.h"
#include <unistd.h>
}

#include "options.h"

#include <iostream>
#include <fstream>
#include <vector>

extern "C" {
extern char *optarg;
extern int   optind, opterr, optopt;
}


/******************************/
static char *savea;
static int savei, savee, saveo;

bool getopts(int argc, char * const argv[], struct option *longopts);

void set_usage(std::string);

static void usage(char *);
static bool getopts_real(int argc, char * const argv[],
			 struct option *longopts, struct option *opts);

static std::string usage_string = "";

#if 0
static bool    onoff = false;
static int     value = 0;
static std::string  str = "default";
vector<char *> v;

int main(int argc, char *argv[])
{
  struct option opts[] = {
    {"bool",       1, (int *)&onoff, OPT_BOOL},
    {"int",        1, &value,        OPT_NUM},
    {"std::string",     1, (int *)&str,   OPT_STD::STRING},
    {"conf",       1, NULL,          OPT_CONFIG},
    {"multi",      1, (int *)&v,     OPT_MULTI},
    { 0, 0, 0, 0}
  };

  getopts(argc,argv,opts);
  cerr << "bool: " << onoff << "\nint: " << value << "\nstr: " << str << endl;

  for (int i = 0; i < v.size(); i++)
    cerr << "multi: " << v[i] << endl;
}
#endif

/*
 * Function:
 *   set_usage(std::string)
 *
 * Description:
 *   The following function sets the usage std::string used by the usage()
 *   function (See).
 *
 * Parameters:
 *   'std::string' - The usage std::string.
 *
 * Result:
 *   None.
 */
void 
set_usage(std::string str)
{
  usage_string = str;
  savei=optind;
  savee=opterr;
  saveo=optopt;
  savea=optarg;
}

/*
 * Function:
 *   usage(name)
 *
 * Description:
 *   This function prints the usage std::string previously memorized with the
 *   set_usage() function. (See)
 *
 * Parameters:
 *   'name' - The name of the program that calls this function.
 *
 * Result:
 *   None.
 */
static void 
usage(char *name)
{
  std::cerr << name << ": " << usage_string << std::endl;

}


/*
 * Function:
 *   getopts(argc, argv, longopts)
 *
 * Description:
 *   This function parses the command line using the getopt_long_only()
 *   function, and then does initialize some variables base on the
 *   parameters it finds. The scanning itself stops as soon as a
 *   non-option argument is encountered.
 *
 * Parameters:
 *   'argc'     - The program's argc.
 *   'argv'     - The program's argv.
 *   'longopts' - This is an array of option structures (see getopt_long(3)).
 *                However, the semantics of its fields have changed. First
 *                of all, the has_arg is now irrelevant, and the meaning of
 *                the flag field depends on the content of the val one. So,
 *                let's see the possible values of the val field:
 *
 *                OPT_NONE     : Nothing happens.
 *                OPT_HELP     : The usage std::string is printed and the function
 *                               failes.
 *                OPT_BOOL     : The flag field is expected to be a pointer to
 *                               an integer that will be set to 1 if the option
 *                               is specified and left alone otherwise.
 *                OPT_STD::STRING   : The flag field is expected to be a pointer to a
 *                               std::string that will be set to point at the
 *                               argument.
 *                OPT_NUM      : The flag field is expected to be a pointer to
 *                               an integer whose pointed value will be set with
 *                               the numeric value of the argument of the
 *                                option.
 *                OPT_CONFIG   : The flag field is irrelevant. The argument of
 *                               the option is the name of a file that will be
 *                               loaded into memory and that is expected to
 *                               contain more options that will be evaluated
 *                               immediately. The format of its contents is the
 *                               following:
 *                                               -[-]name[=value]
 *                               where the parts between [] are optional. There
 *                               must be at most one such option per line.
 *                OPT_MULTI    : A flag so specified may be present multiple
 *                               times in the command line, it is expected to
 *                               have a value, all the values are recorded. The
 *                               flag field is supposed to be a pointer to an
 *                               array of std::string. The first two elements must
 *                               be filled by the caller and are not actual
 *                               std::strings. The first pointer of the array is in
 *                               reality expected to be the number of elements
 *                               that the array can accomodate minus 2, and the
 *                               second element must be the number of elements
 *                               already present (again, minus the first two).
 *                               On output, the second element will contain the
 *                               number of std::strings entered in the array. The
 *                               pointers to the std::strings themselves will start
 *                               from the third element.
 *
 * Result:
 *   Failure:
 *     false.
 *   Success:
 *     true.
 */
bool
getopts(int argc, char * const argv[], struct option *longopts)
{
  int i = 0, num=0;
  struct option *opts;

  optind=savei;
  opterr=savee;
  optopt=saveo;
  optarg=savea;
  optind = 0;

  /*
   * Count the number of options passed.
   */
  while(!(longopts[num].name == 0 && longopts[num].has_arg == 0 && longopts[num].flag == 0 && longopts[num].val == 0))
    num++;

  /*
   * Allocates and fills a properly formatted struct option array.
   */

  try {
    opts = new struct option[num+1];
  } catch ( std::bad_alloc) {
    return false;
  }
  
  for (i = 0; i<num+1; i++) {
    opts[i].name = longopts[i].name;
    opts[i].flag = 0;
    opts[i].val  = longopts[i].val;
    switch (longopts[i].val) {
    case OPT_NONE: case OPT_BOOL: case OPT_HELP: case OPT_FUNCTION0:
      opts[i].has_arg = 0;
      break;
    case OPT_STRING: case OPT_NUM: case OPT_CONFIG:
    case OPT_FUNCTION1: case OPT_MULTI:
      opts[i].has_arg = 1;
      break;
    default:
      delete[] opts;
      return false;
      break;
    }
  }

  bool res = getopts_real(argc, argv, longopts, opts);
  delete[] opts;
  return res;
}

bool
getopts_real(int argc, char * const argv[], struct option *longopts, struct option *opts)
{
  int c;
  int index = 0;
  
  /*
   * Do the actual scanning of the argument list
   */

  do {

    c = getopt_long_only(argc, argv, "+", opts, &index);

    if (c == '?' || c == '+')
      break;

    if (c != -1 && c != '?')
    {
      if (longopts[index].flag == NULL && 
          !(longopts[index].val == OPT_NONE ||
            longopts[index].val == OPT_HELP ||
            longopts[index].val == OPT_CONFIG))
      {
        c = '?';
        break;
      }
      
      switch (longopts[index].val) 
      {
      
      case OPT_NONE:
        break;
      
      case OPT_BOOL:
        *((bool *)(longopts[index].flag)) = 1;
        break;
      
      case OPT_NUM:
        *((int *)(longopts[index].flag)) = atoi(optarg);
        break;
      
      case OPT_STRING:
        *((std::string *)(longopts[index].flag)) = optarg;
        break;
      
      case OPT_FUNCTION0:
      {
          bool (*zero)(void)  = (bool (*)(void))(longopts[index].flag);
          if (!zero())
            c = '?';
      }
      break;
      
      case OPT_FUNCTION1:
      {
        bool (*one)(char *)  = (bool (*)(char *))(longopts[index].flag);
          
        if (!one(optarg))
          c = '?';
      }
      break;
      
      case OPT_MULTI: 
      {
        std::vector<std::string> *v =((std::vector<std::string> *)(longopts[index].flag));
        if(optarg)
          v->push_back((std::string)(optarg));
        else c = '?';
      }
      break;
      
      case OPT_CONFIG: 
      {
        std::ifstream f(optarg);
        bool res = true;
        std::string line;
        char *optargsave;
        int optindsave, opterrsave, optoptsave;
	  
        while (f >> line) {
          if (line.c_str()[0] != '#') {
            std::vector<const char *> v;
            v.push_back(argv[0]);
            v.push_back(line.c_str());
            optargsave = optarg;
            optindsave = optind;
            opterrsave = opterr;
            optoptsave = optopt;
            optind = 0;
            res &= getopts_real(2, const_cast<char * const *>(&v[0]),
                                longopts, opts);
            optarg = optargsave;
            optind = optindsave;
            opterr = opterrsave;
            optopt = optoptsave;
          }
        }
        if (!res)
          c = '?';
      }
      break;
      
      case OPT_HELP:
        usage(argv[0]);
        exit(1);
        break;
      
      default:
        c = -2;
        break;
      }
    }
    
    if (c == ':')
    {
      c = '?';
    }
    
  } while (c != '?' && c != -1);

  if (c == '?')
  {
    exit(1);
  }
  else if (optind < argc && argv[optind][0] != '#' ) {
    std::cerr << "Found non option element " << argv[optind] << " in command line." << std::endl;
    return false;
  }

  return true;
}
