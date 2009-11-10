/**********************************************************************
 oldgaa_utils.c:

Description:
	This file is used internally by the oldgaa routines
**********************************************************************/


/**********************************************************************
                             Include header files
**********************************************************************/
#include "config.h"

#include <stdlib.h>     /* For malloc or free */
#include <math.h>       /* for pow()          */

#include <stdio.h>      /* File reading and writing */
#include <string.h> 
#include <errno.h>	/* For errno */

#include <assert.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "globus_oldgaa.h" 
#include "oldgaa_utils.h"

extern int oldgaa_rfc1779_name_parse(char *rfc1779_string,
                                     char **imported_name,
                                     char **errstring);

static
char *
oldgaa_to_regex(const char * const glob_regex);

static char *normalize(char * name);

/**********************************************************************
                       Define module specific variables
**********************************************************************/

int	       string_count = 0;
int	       string_max   = 0;
static char   *parse_error  = NULL;


/******************************************************************************

Function:   oldgaa_oldgaa_handle_error
Description:
	Given and error message and a pointer to a pointer to be
	allocated handle the allocation and setting of the pointer.

Parameters:
	errstring, pointer to a pointer to be set to the allocated
	error message. May be NULL.

	message, the error message.

Returns:
	Nothing

******************************************************************************/

void PRIVATE
oldgaa_handle_error(char       **errstring,
                    const char *const message)
{
  /* If this fails we're hosed so don't bother checking */
  if (errstring)
    {
      if (*errstring == NULL) *errstring = strdup(message);
      else
        {
          *errstring = (char *)realloc(*errstring, strlen(message)+1);
          if (*errstring != NULL) strcpy(*errstring, message);
        }
    }
   
} /* oldgaa_handle_error() */

/**********************************************************************

Function: oldgaa_strings_match() 

Description:
	Compare two strings.

Parameters:
	string1 and string2, pointers to two strings.

Returns:
	1 if strings match.
	0 if strings don't match.
       -1 on error, setting errno.

**********************************************************************/

int PRIVATE
oldgaa_strings_match(
                     const char * const			string1,
                     const char * const 			string2)
{
  /* Check arguments */
  if (!string1 || !string2)
    {
      errno = ERRNO_INVALID_ARGUMENT;
      return -1;
    }

  return (strcmp(string1, string2) == 0);
} /* strings_match() */


/*****************************************************************************
 * oldgaa_strcopy - copy a string allocating space if necessary
 *
 *     OLDGAA_STRCOPY takes a conventional string, S, as an argument, and a pointer to
 *     a second  string, R, which is to be replaced by S.  If R is long enough
 *     to hold S, S is copied.  Otherwise, new space is allocated, and R is
 *     freed.  S is then copied to the newly allocated space.  If S is
 *     NULL, then R is freed and NULL is returned.
 *
 *     In any event, OLDGAA_STRCOPY returns a pointer to the new copy of S,
 *     or a NULL pointer.
 *****************************************************************************/

char PRIVATE *
oldgaa_strcopy(const char *s, char *r)
{
  int	slen;
 
  if (!s && r) {
    free(r);
    return(NULL);
  }
  else if (!s) 
    return(NULL);

  free(r);

  slen = strlen(s) + 1;
   
  r = (char *) malloc(slen);
  if (!r) 
    out_of_memory();
   
  strcpy(r,s);
  return(r);

}

/**********************************************************************
  Compare elements
**********************************************************************/

int PRIVATE
oldgaa_compare_principals(oldgaa_principals_ptr element,
                          oldgaa_principals_ptr new)
{
  /* Do the principal's names match? */

  element->value = normalize(element->value);
  new->value     = normalize(new->value);

  if(oldgaa_strings_match(element->type,      new->type)     &&
     oldgaa_strings_match(element->authority, new->authority) &&
     oldgaa_strings_match(element->value,     new->value) )
    return TRUE;   
  else return FALSE;
}  


/****************************************************************************-*/


int PRIVATE
oldgaa_compare_rights(oldgaa_rights_ptr element, oldgaa_rights_ptr new)
{
  if (element == NULL || new == NULL)
    return FALSE;

  if(oldgaa_strings_match(element->type,      new->type)     &&
     oldgaa_strings_match(element->authority, new->authority) &&
     oldgaa_strings_match(element->value,     new->value) )
    return TRUE;
  else return FALSE;
}

/****************************************************************************-*/


int PRIVATE
oldgaa_compare_conditions(oldgaa_conditions_ptr element, 
                          oldgaa_conditions_ptr new)
{
  if(oldgaa_strings_match(element->type,      new->type)     &&
     oldgaa_strings_match(element->authority, new->authority) &&
     oldgaa_strings_match(element->value,     new->value) )
    return TRUE;
  else return FALSE;
}
    
/****************************************************************************-*/

int PRIVATE
oldgaa_compare_sec_attrbs(oldgaa_sec_attrb_ptr element, 
                          oldgaa_sec_attrb_ptr new)
{
  if(oldgaa_strings_match(element->type,      new->type)     &&
     oldgaa_strings_match(element->authority, new->authority) &&
     oldgaa_strings_match(element->value,     new->value) )
    return TRUE;
  else return FALSE;
}
  
/**********************************************************************
  Add new element to a list
**********************************************************************/

oldgaa_principals_ptr PRIVATE
oldgaa_add_principal(oldgaa_policy_ptr   *list, 
                     oldgaa_principals_ptr new)
{
  oldgaa_principals_ptr element;
  uint32 minor=0;

  element = *list;
  
  if (oldgaa_compare_principals(element, new)) {
    /* found this principal in the list */ 
    if (element != new)
      oldgaa_release_principals(&minor, &new);
    return element;
  }

  while(element->next ) 
    {
      element = element->next;
      if (oldgaa_compare_principals(element, new)) {
        /* found this principal in the list */    
        if (element != new)
          oldgaa_release_principals(&minor, &new);
        return element; 
      }
    }

  element->next = new; /* add new element to the end of the list */
  return new;
}    


/*****************************************************************************/

oldgaa_rights_ptr PRIVATE
oldgaa_add_rights(oldgaa_rights_ptr *list, 
                  oldgaa_rights_ptr  new)
{
  oldgaa_rights_ptr element;

  element = *list; 

  while(element->next!= NULL) element = element->next;   
  element->next = new;

  return new; 
}  

/*****************************************************************************/
oldgaa_cond_bindings_ptr PRIVATE
oldgaa_add_cond_binding(oldgaa_cond_bindings_ptr *list,
                        oldgaa_cond_bindings_ptr  new)
{
  oldgaa_cond_bindings_ptr element;

  element = *list;
 
  while(element->next!= NULL) element = element->next;
   
  element->next = new;

  return new; 
}  


/*****************************************************************************/


oldgaa_conditions_ptr PRIVATE
oldgaa_add_condition(oldgaa_conditions_ptr *list, 
                     oldgaa_conditions_ptr  new)
{
  oldgaa_conditions_ptr element;
 
  element = *list;

  /*
   *DEE This code does not make sence. It will add new
   *to the end of the list, but will leave it hanging
   *if its the same as one already on the list. 
   */

/*   if (oldgaa_compare_conditions(element, new))  */
/*     { */
/*       return element; /\* found this condition in the list *\/  */
/*     } */
/*   while(element->next)  */
/*     {        */
/*       element = element->next; */
/*       if (oldgaa_compare_conditions(element, new))  */
/*         { */
/*           return element; /\* found this condition in the list *\/ */
/*         } */
/*     } */
/*   element->next = new; /\* add new element to the end of the list *\/ */

  return new;
}    

/**********************************************************************
  Add new element to a list
**********************************************************************/

oldgaa_sec_attrb_ptr PRIVATE
oldgaa_add_attribute(oldgaa_sec_attrb_ptr *list, oldgaa_sec_attrb_ptr new)
{
  oldgaa_sec_attrb_ptr element;

  element = *list;

  if (oldgaa_compare_sec_attrbs(element, new)) return element; /* found
                                                                  this attribute in the list */ 

  while(element->next) 
    {
      element = element->next;
      if (oldgaa_compare_sec_attrbs(element, new)) return element; /* found
                                                                      this attribute in the list */    
    }

  element->next = new; /* add new element to the end of the list */
  return new;
}    


/**********************************************************************
  Bindings
**********************************************************************/

/* int */
/* oldgaa_duplicate_rights(oldgaa_rights_ptr rights, oldgaa+rights_ptr &new) */
/* { */
/* } */
void PRIVATE
oldgaa_collapse_policy(oldgaa_policy_ptr *policy)
{
  oldgaa_principals_ptr element = *policy;

  while(element) {
    oldgaa_rights_ptr thisright     = element->rights;
    oldgaa_rights_ptr  previousright = NULL;

    while (thisright) {
      if (oldgaa_compare_rights(thisright, previousright) == TRUE) {
        oldgaa_cond_bindings_ptr bindings     = thisright->cond_bindings;

        while (bindings) {
          oldgaa_conditions_ptr current = bindings->condition;

          while(current) {
            previousright->cond_bindings->condition->value = 
              realloc(previousright->cond_bindings->condition->value,
                      strlen(previousright->cond_bindings->condition->value) + 
                      2 + strlen(current->value));
            previousright->cond_bindings->condition->value = 
              strcat(previousright->cond_bindings->condition->value, " ");
            previousright->cond_bindings->condition->value = 
              strcat(previousright->cond_bindings->condition->value, current->value);
            current = current->next;
          }
          {
            uint32 minor = 0;
            oldgaa_release_conditions(&minor, &(bindings->condition));
            bindings->condition = NULL;
            bindings = bindings->next;
          }
        }
        thisright = thisright->next;
        
      }
      else {
        previousright=thisright;
        thisright = thisright->next;
      }
    }
    element = element->next;
  }

  element = *policy;
  while (element) {
    oldgaa_rights_ptr right = element->rights;
    oldgaa_rights_ptr prev  = NULL;
    while (right) {
      if (prev != NULL) {
        if (right->cond_bindings->condition == NULL) {
          uint32 minor = 0;
          prev->next = right->next;
          oldgaa_release_rights(&minor, &right);
          right = prev->next;
        }
        else {
          prev = right;
          right = right->next;
        }
      }
      else {
        prev = right;
        right = right->next;
      }
    }
    element = element->next;
  }
}



int PRIVATE
oldgaa_bind_rights_to_principals(oldgaa_principals_ptr start, 
                                 oldgaa_rights_ptr     rights)
{
  oldgaa_principals_ptr element = start;

  /*  while(element != NULL) {  */
/*     if (oldgaa_compare_rights(element->rights, rights) == TRUE) { */
/*       oldgaa_release_rights(*rights); */
/*       *rights = element->rights; */
/*       return OLDGAA_SUCCESS; */
/*     } */
    rights->next = element->rights;
      element->rights = rights;
      rights->reference_count++;

      /*      element         = element->next;*/
      /*    }*/
 
  return OLDGAA_SUCCESS;
}  


/* int */
/* oldgaa_compare_cond_bindings(oldgaa_cond_bindings_ptr element, */
/*                              oldgaa_cond_bindings_ptr new) */
/* { */
/*   if (oldgaa_strings_match(element->type,     new->type) && */
/*       oldgaa_strings_match(element->authority,new->authority)) */
/*     return TRUE; */
/*   return FALSE; */
/* } */

/*****************************************************************************/

static oldgaa_error_code
oldgaa_duplicate_conditions(oldgaa_conditions_ptr element , oldgaa_conditions_ptr *new)
{
  oldgaa_allocate_conditions(new);

  (*new)->type      = strdup(element->type);
  (*new)->authority = strdup(element->authority);
  (*new)->value     = strdup(element->value);
  (*new)->next = NULL;
  (*new)->reference_count = 0;
  (*new)->status = 0;

  return OLDGAA_SUCCESS;
}

void PRIVATE
oldgaa_bind_rights_to_conditions(oldgaa_rights_ptr        start,
                                 oldgaa_cond_bindings_ptr cond_bind)
{
  oldgaa_rights_ptr element = start;
  uint32 minor = 0;
  /*DEE - Looks like all the rights will point to this cond_bind*/
  /* With Globus we only have 1, so should not be a problem */
  /*  oldgaa_conditions_ptr c = cond_bind->condition;*/
  oldgaa_conditions_ptr current = NULL;
  while(element) {

    if (!element->cond_bindings) {
      oldgaa_cond_bindings_ptr new_cond_bind = NULL;
      if (oldgaa_allocate_cond_bindings(&new_cond_bind) == OLDGAA_SUCCESS) {
        element->cond_bindings = new_cond_bind;
        new_cond_bind->reference_count = 0;
      }
      else
        return;
    }
    /* walk on passed conditions */
    current = cond_bind->condition;
    while (current) {
      oldgaa_conditions_ptr new  = NULL;
      if (oldgaa_duplicate_conditions(current, &new) == OLDGAA_SUCCESS) {
        if (element->cond_bindings->condition != NULL) {
          new->next = element->cond_bindings->condition;
        }
        element->cond_bindings->condition = new;
        new->reference_count ++;
      }
      current = current->next;
    }
    element = element->next;
  }
  oldgaa_release_cond_bindings(&minor, &cond_bind);

}
/* /\*       if (oldgaa_compare_cond_bindings(element->cond_bindings, cond_bind)) { *\/ */
/*       if (element->cond_bindings) { */
/*         /\* find last element *\/ */
/*         oldgaa_conditions_ptr tmp = element->cond_bindings->condition; */
/*         while (tmp->next) */
/*           tmp = tmp->next; */

/*         tmp->next = c; */
/*         c->reference_count ++; */
/*         /\*        cond_bind->condition = NULL;*\/ */
/*         break; */
/*       } */
/* /\*       } *\/ */
/*       else { */
/*         cond_bind->next = element->cond_bindings; */
/*         element->cond_bindings = cond_bind; */
/*         cond_bind->reference_count++; */
/*         element                = element->next; */
/*       } */
/*     } */
/*   //  cond_bind->condition = NULL; */
/* }   */

/**********************************************************************
  Regex Handling Functions
**********************************************************************/

/**********************************************************************

Function: oldgaa_check_reg_expr() 

Description:
	Goes throug the list of reg expressions and looks for a match
        to the given rex expression.

Parameters:
	reg_expr pointer to a reg expression and reg_expr_list, pointers to
        a reg expression list

Returns:
	1 if regex match.
	0 if regex don't match.
	-1 on error, setting errno.

**********************************************************************/
int PRIVATE
oldgaa_check_reg_expr(char  *reg_expr, 
                      char **reg_expr_list)
{ 
  char **pregex;

  /* Check arguments */
  if (!reg_expr || !reg_expr_list)
    {
      errno = ERRNO_INVALID_ARGUMENT;
      return -1;
    }

  /* walk through the regexes and see if we match any */
  for (pregex = reg_expr_list;
       *pregex != NULL;
       pregex++)
    {
      if (oldgaa_regex_matches_string(reg_expr, *pregex) == 1)
        return 1; /* We have a match */		
    }

  return 0;
}



/**********************************************************************

Function: oldgaa_regex_matches_string()

Description:
	Determine if a regex matches a given string.

Parameters:
	string, the string to check

	regex, the regex to compare

Returns:
	1 if match.
	0 if don't match.
       -1 on error, setting errno.

**********************************************************************/

int PRIVATE
oldgaa_regex_matches_string(const char * const  string,
                            const char * const  regex)
{
  /* Our result (1 == match) */
  int					result = 0;

  char *                                star;
  
  /* Check arguments */
  if (!string || !regex)
    {
      errno = ERRNO_INVALID_ARGUMENT;
      return -1;
    }


  if(!strcmp(string,regex))
    {
      result = 1;
    }
  else
    {
      if((star = strrchr(regex,'*')) &&
         !strncmp(regex,string,(int) (star-regex)/sizeof(char)))
        {
          result = 1;
        }
    }

  return result;

} /* oldgaa_regex_matches_string() */



/**********************************************************************

Function: oldgaa_parse_regex() 

Description:
	Walks throug condition list and evaluates each condition.

Parameters:
        condition, pointer to oldgaa_conditions structure

Returns:
       list of regex

**********************************************************************/

char PRIVATE **
oldgaa_parse_regex(char * str)
                
{
  char **subject_regexes = NULL; 
  int    num_regexes     = 0;      /* Number of subject regexes we've parse */
  char   new_str[MAX_STRING_SIZE]; /* Pointer to the string*/
  int    i      = 0,               /* Pointer to our current location in str */
    j,                        /* Pointer to our current location in new_str */
    length = strlen(str);			
  int    end = FALSE;			

  /* Now read and parse all the subject regexes */
  subject_regexes = calloc(num_regexes + 1 /* for NULL */,
                           sizeof(char *));

  if (!subject_regexes) out_of_memory();
 		
  subject_regexes[0] = NULL;


  if (QUOTING != str[i]) strcpy(new_str, str);

  while(1)
    {
      char  *uncnv_regex;  /* Pointer to unconverted regex */   
      char  *cnv_regex;    /* Pointer to converted regex */   
      char **tmp_regexes;  /* Temporary holder for pointer to list of regexes */


      if(!end)
        {     
          while((str[i] == WHITESPACE)||
                (str[i] == TAB)       ||
                (str[i] == QUOTING)) i++;   

          j=0;
        
          /*   while((str[i] != WHITESPACE) &&
               (str[i] != TAB))*/

          while(1)
            {                
              if (str[i] == QUOTING)
                { 
                  if (i == length-1) end = TRUE;   
                  break;
                }

              if (i > length-1)
                { 
                  end = TRUE;   
                  break;
                }
    
              new_str[j]=str[i]; 
              i++; j++;
            }

          new_str[j]= NUL;
       
        } /* end of if(compound) */

      if (oldgaa_rfc1779_name_parse(new_str,
                                    &uncnv_regex,
                                    NULL) != 0)

        {
          oldgaa_handle_error(&parse_error,
                              "oldgaa_globus_parse_conditions: error parsing rfc1779 name");
          return NULL;
        }

      cnv_regex = oldgaa_to_regex(uncnv_regex);

      free(uncnv_regex);

      if (cnv_regex == NULL)
        {
          oldgaa_handle_error(&parse_error,
                              "oldgaa_globus_parse_conditions: error parsing regular expression"); 
          return NULL;
        }

      num_regexes++;
      tmp_regexes = realloc(subject_regexes,
                            (num_regexes + 1) * sizeof(char *));

      if (tmp_regexes == NULL)
        {
          oldgaa_handle_error(&parse_error, "oldgaa_globus_parse_conditions: out of memory");
          free(cnv_regex);
          return NULL;
        }

      subject_regexes = tmp_regexes;

      subject_regexes[num_regexes - 1] = cnv_regex;
      subject_regexes[num_regexes] = NULL;

      if (end)break;
   
    }

  if (num_regexes == 0)
 
    {
      /* No subject regexes were found */
  
      oldgaa_handle_error(&parse_error,
                          "oldgaa_globus_parse_conditions: no subject regexes found");
      return NULL;

    }

  return subject_regexes;

}


/**********************************************************************

Function:	oldgaa_to_regex()

Description:    
	Convert a shell-style regex to a regex suitable
	to feed into the posix regex commands.

	Specifically:

	'*' is converted to '.*'

	'?' is converted to '.'

	'.', '^', '\, and '$' are escaped by preceding them
	with a backslash
			
	'^' is prepended to the string and '$' is appended so that the
	resulting regex will force a complete match.

Parameters:
	glob_regex, a pointer to the glob-style regex string.

Returns:
	a pointer to allocated regex string
	NULL on error (errno is set).
		
**********************************************************************/

static
char *
oldgaa_to_regex(const char * const glob_regex)
{
  /* don't do the conversion */
  /* we're no longer doing regex matching -Sam */
  return strdup(glob_regex);
} /* oldgaa_to_regex() */


/**********************************************************************/

static char *substitute(char *string, char *from, char *to)
{
  char *pointer = strstr(string, from);
  char *newstring = NULL;

  if (!pointer)
    return string;

  newstring = (char*)malloc(strlen(string)+strlen(to)-strlen(from)+1);

  if (!newstring)
    return string;

  *pointer='\0';
  strcpy(newstring, string);
  strcat(newstring, to);
  strcat(newstring, pointer+strlen(from));
  free(string);
  return newstring;
}

static char *normalize(char * name)
{
  name = substitute(name, "/emailAddress=", "/Email=");
  name = substitute(name, "/E=", "/Email=");
  return substitute(name, "/USERID=", "/UID=");
}
