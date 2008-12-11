/**********************************************************************
 oldgaa_release.c:

Description:
	This file used internally by the oldgaa routines
**********************************************************************/
#include "config.h"

#include "globus_oldgaa.h"
#include "stdio.h" /* for fprintf() */

/**********************************************************************
Function:  oldgaa_release_buffer_contents

Description:
	Release the contents of a buffer

Parameters:

Returns:
**********************************************************************/

oldgaa_error_code  PRIVATE
oldgaa_release_buffer_contents (UNUSED(uint32         *minor_status),
                    oldgaa_buffer_ptr  buffer)
{
 	if (buffer == NULL || buffer == OLDGAA_NO_BUFFER) return OLDGAA_SUCCESS;
       
	if (buffer->value) free(buffer->value);
	buffer->length = 0;

	return OLDGAA_SUCCESS;

} /* oldgaa_release_buffer_contents */
/**********************************************************************
Function:  oldgaa_release_buffer

Description:
	Release the buffer

Parameters:

Returns:
**********************************************************************/

oldgaa_error_code  PRIVATE
oldgaa_release_buffer(UNUSED(uint32         *minor_status),
                    oldgaa_buffer_ptr *  buffer)
{
 	if (buffer == NULL || *buffer == NULL) return OLDGAA_SUCCESS;
       
    free(*buffer);
	*buffer = NULL;

	return OLDGAA_SUCCESS;

} /* oldgaa_release_buffer */

/**********************************************************************
Function:  oldgaa_release_options

Description:
	Release the contents of a buffer

Parameters:

Returns:
**********************************************************************/

oldgaa_error_code  PRIVATE
oldgaa_release_options(UNUSED(uint32          *minor_status),
                    oldgaa_options_ptr  buffer)
{
 	if (buffer == NULL || buffer == OLDGAA_NO_OPTIONS) return OLDGAA_SUCCESS;
       
	if (buffer->value) free(buffer->value);
	buffer->length = 0;

  free(buffer);

	return OLDGAA_SUCCESS;

} /* oldgaa_release_options */
     
/**********************************************************************
Function:  oldgaa_release_data

Description:
	Release the contents of a buffer

Parameters:

Returns:
**********************************************************************/

oldgaa_error_code  PRIVATE
oldgaa_release_data (UNUSED(uint32       *minor_status),
                  oldgaa_data_ptr  buffer)
{
 	if (buffer == NULL || buffer == OLDGAA_NO_DATA) return OLDGAA_SUCCESS;
       
	if (buffer->str)       free(buffer->str);
	if (buffer->error_str) free(buffer->error_str);

        free(buffer);

	return OLDGAA_SUCCESS;

} /* oldgaa_release_data */



/**********************************************************************

Function:   oldgaa_delete_sec_context()

Description:
	delete the security context

Parameters:

Returns:
**********************************************************************/

oldgaa_error_code  PRIVATE
oldgaa_release_sec_context(UNUSED(uint32             *minor_status),
                       oldgaa_sec_context_ptr *sec_context)
{

 oldgaa_sec_context_ptr  *context_handle = sec_context;
 uint32                inv_minor_status = 0, inv_major_status = 0;

	if (*context_handle == NULL || *context_handle == OLDGAA_NO_SEC_CONTEXT) 
	return OLDGAA_SUCCESS ;

	/* ignore errors to allow for incomplete context handles */

	if ((*context_handle)->identity_cred!= NULL) 
        inv_major_status = oldgaa_release_identity_cred(&inv_minor_status,
			      &((*context_handle)->identity_cred));
	

       if ((*context_handle)->authr_cred!= NULL)         
       inv_major_status = oldgaa_release_authr_cred(&inv_minor_status,
			      &((*context_handle)->authr_cred));
	

       if ((*context_handle)->group_membership!= NULL) 
       inv_major_status = oldgaa_release_identity_cred(&inv_minor_status,
			      &((*context_handle)->group_membership));
      

       if ((*context_handle)->group_non_membership!= NULL) 
       inv_major_status = oldgaa_release_identity_cred(&inv_minor_status,
			      &((*context_handle)->group_non_membership));
       

       if ((*context_handle)->attributes!= NULL) 
       inv_major_status = oldgaa_release_attributes(&inv_minor_status,
			      &((*context_handle)->attributes));
	

      if ((*context_handle)->unevl_cred!= NULL)
      inv_major_status = oldgaa_release_uneval_cred(&inv_minor_status,
			      &((*context_handle)->unevl_cred));
	

      if ((*context_handle)->connection_state!= NULL)  
      {
         inv_major_status = oldgaa_release_buffer_contents(&inv_minor_status,
			      (*context_handle)->connection_state);

         inv_major_status = oldgaa_release_buffer(&inv_minor_status,
			      &((*context_handle)->connection_state));
	  }

     free(*context_handle);
    *context_handle = OLDGAA_NO_SEC_CONTEXT;

  return OLDGAA_SUCCESS;

} /* oldgaa_delete_sec_context */

/**********************************************************************
Function:   oldgaa_release_identity_cred()

Description:
	delete the security context

Parameters:

Returns:
**********************************************************************/

oldgaa_error_code  PRIVATE
oldgaa_release_identity_cred (UNUSED(uint32                *minor_status),
                           oldgaa_identity_cred_ptr *identity_cred)

{
  oldgaa_identity_cred_ptr  *cred = identity_cred;
  uint32                  inv_minor_status = 0, inv_major_status = 0;

	if (*cred == NULL || *cred == OLDGAA_NO_IDENTITY_CRED) 
	return OLDGAA_SUCCESS;

	/* ignore errors to allow for incomplete context handles */

	if ((*cred)->principal!= NULL) 
	inv_major_status = oldgaa_release_principals(&inv_minor_status,
			                          &((*cred)->principal));
       
        if ((*cred)->conditions!= NULL) 
	inv_major_status = oldgaa_release_conditions(&inv_minor_status,
			                          &((*cred)->conditions));
	
        if ((*cred)->mech_spec_cred!= NULL) 
		{
        	inv_major_status = 
				oldgaa_release_buffer_contents(&inv_minor_status,
			                      (*cred)->mech_spec_cred);
			inv_major_status = oldgaa_release_buffer(&inv_minor_status,
						&((*cred)->mech_spec_cred));
		}
	
        if ((*cred)->next!= NULL) 
        inv_major_status = oldgaa_release_identity_cred(&inv_minor_status,
			                             &((*cred)->next));
    free(*cred);

   return OLDGAA_SUCCESS;

} 

/**********************************************************************
Function:   oldgaa_release_authr_cred()

Description:
	delete the security context

Parameters:

Returns:
**********************************************************************/

oldgaa_error_code  PRIVATE
oldgaa_release_authr_cred(UNUSED(uint32             *minor_status),
                       oldgaa_authr_cred_ptr *authr_cred)

{
  oldgaa_authr_cred_ptr   *cred = authr_cred;
  uint32               inv_minor_status = 0, inv_major_status = 0;

	if (*cred == NULL || *cred == OLDGAA_NO_AUTHORIZATION_CRED) 
	return OLDGAA_SUCCESS;

	/* ignore errors to allow for incomplete context handles */

	if ((*cred)->grantor != NULL)
	inv_major_status = oldgaa_release_principals(&inv_minor_status,
			      &((*cred)->grantor));
	

	if ((*cred)->grantee != NULL)
	inv_major_status = oldgaa_release_principals(&inv_minor_status,
			      &((*cred)->grantee));
	

    /*
     *DEE what about release of objects? 
     * Since There are is no oldgaa_allocate_authr_cred
     * that can be fixed when this routine is actually used. 
     */

        if ((*cred)->access_rights!= NULL) 
	inv_major_status = oldgaa_release_rights(&inv_minor_status,
			                      &((*cred)->access_rights));
	
       if ((*cred)->mech_spec_cred!= NULL) 
       {
           inv_major_status = 
                 oldgaa_release_buffer_contents(&inv_minor_status,
			                     (*cred)->mech_spec_cred);
           inv_major_status = oldgaa_release_buffer(&inv_minor_status,
                                &((*cred)->mech_spec_cred));
       }

       if ((*cred)->next!= NULL) 
       inv_major_status = oldgaa_release_authr_cred(&inv_minor_status,
			                         &((*cred)->next));
       
     free(*cred);

    return OLDGAA_SUCCESS;

} /* oldgaa_release_authr_cred */

/**********************************************************************
Function:   oldgaa_release_attributes()

Description:
	delete the security context

Parameters:

Returns:
**********************************************************************/

oldgaa_error_code  PRIVATE
oldgaa_release_attributes(UNUSED(uint32             *minor_status),
                       oldgaa_attributes_ptr *attributes)
{

oldgaa_attributes_ptr  *cred = attributes;
uint32               inv_minor_status = 0, inv_major_status = 0;

	if (*cred == NULL || *cred == OLDGAA_NO_ATTRIBUTES) 
	return OLDGAA_SUCCESS;

	/* ignore errors to allow for incomplete context handles */

  if ((*cred)->mech_type != NULL) free((*cred)->mech_type);
  if ((*cred)->type      != NULL) free((*cred)->type);
  if ((*cred)->value     != NULL) free((*cred)->value);

    
  if ((*cred)->conditions!= NULL) 
    inv_major_status = oldgaa_release_cond_bindings(&inv_minor_status,
                                                    &((*cred)->conditions));

  if ((*cred)->mech_spec_cred!= NULL) 
    {
      inv_major_status = 
        oldgaa_release_buffer_contents(&inv_minor_status,
                                       (*cred)->mech_spec_cred);
      inv_major_status =oldgaa_release_buffer(&inv_minor_status,
                                              &((*cred)->mech_spec_cred));
    }
  
  if ((*cred)->next!= NULL) 
    inv_major_status = oldgaa_release_attributes(&inv_minor_status,
                                                 &((*cred)->next));

  free(*cred);

  return OLDGAA_SUCCESS;

} /* oldgaa_rlease_attributes */

/**********************************************************************
Function:   oldgaa_rlease_uneval_cred()

Description:
	delete the security context

Parameters:

Returns:
**********************************************************************/

oldgaa_error_code  PRIVATE
oldgaa_release_uneval_cred(UNUSED(uint32              *minor_status),
                        oldgaa_uneval_cred_ptr *uneval_cred)

{
  oldgaa_uneval_cred_ptr  *cred = uneval_cred;
  uint32                inv_minor_status = 0, inv_major_status = 0;

	if (*cred == NULL || *cred == OLDGAA_NO_UNEVAL_CRED) 
	return OLDGAA_SUCCESS;

	/* ignore errors to allow for incomplete context handles */

       
        if ((*cred)->grantor != NULL) 
     	inv_major_status = oldgaa_release_principals(&inv_minor_status,
			      &((*cred)->grantor));
       

	if ((*cred)->grantee != NULL) 
	inv_major_status = oldgaa_release_principals(&inv_minor_status,
			      &((*cred)->grantee));


        if ((*cred)->mech_spec_cred!= NULL) 
        {
            inv_major_status = 
                oldgaa_release_buffer_contents(&inv_minor_status,
			                     (*cred)->mech_spec_cred);
            inv_major_status = oldgaa_release_buffer(&inv_minor_status,
                                &((*cred)->mech_spec_cred));
        }

       if ((*cred)->next!= NULL) 
       inv_major_status = oldgaa_release_uneval_cred(&inv_minor_status,
			                          &((*cred)->next));

	free(*cred);

    return OLDGAA_SUCCESS;

} /* oldgaa_rlease_unevaluated_cred */

/**********************************************************************
Function:   oldgaa_rlease_principals()

Description:
	delete the security context

Parameters:

Returns:
**********************************************************************/

oldgaa_error_code  PRIVATE
oldgaa_release_principals(UNUSED(uint32             *minor_status),
                       oldgaa_principals_ptr *principals)
{

  oldgaa_principals_ptr  *cred = principals;
  uint32               inv_minor_status = 0, inv_major_status = 0;

	if (*cred == NULL || *cred == OLDGAA_NO_PRINCIPALS) 
    return OLDGAA_SUCCESS;

	/* ignore errors to allow for incomplete context handles */


  if ((*cred)->rights != NULL) 
    inv_major_status = oldgaa_release_rights(&inv_minor_status,
                                             &((*cred)->rights));


  if ((*cred)->next != NULL) 
    inv_major_status = oldgaa_release_principals(&inv_minor_status,
                                                 &((*cred)->next));
       if ((*cred)->type      != NULL) free((*cred)->type);
       if ((*cred)->authority != NULL) free((*cred)->authority);
       if ((*cred)->value     != NULL) free((*cred)->value);
       
    free(*cred);

  return OLDGAA_SUCCESS;

} /* oldgaa_rlease_principals */

/**********************************************************************
Function:   oldgaa_rlease_rights()

Description:
	delete the security context

Parameters:

Returns:
**********************************************************************/

oldgaa_error_code  PRIVATE
oldgaa_release_rights(UNUSED(uint32         *minor_status),
                   oldgaa_rights_ptr *rights)
{

oldgaa_rights_ptr  *cred = rights;
uint32           inv_minor_status = 0, inv_major_status = 0;

	if (*cred == NULL || *cred == OLDGAA_NO_RIGHTS) 
	return OLDGAA_SUCCESS;

    (*cred)->reference_count--;
    if ((*cred)->reference_count > 0) {
        *rights = NULL;
        return OLDGAA_SUCCESS;
    }

	/* ignore errors to allow for incomplete context handles */

       
       if ((*cred)->cond_bindings != NULL)
       inv_major_status = oldgaa_release_cond_bindings(&inv_minor_status,
			      &((*cred)->cond_bindings));
    

       if ((*cred)->next != NULL)
       inv_major_status = oldgaa_release_rights(&inv_minor_status,
			      &((*cred)->next));
	
	if ((*cred)->type      != NULL) free((*cred)->type);
	if ((*cred)->authority != NULL) free((*cred)->authority);
	if ((*cred)->value     != NULL) free((*cred)->value);

       
    free(*cred);
    *rights = NULL;

  return OLDGAA_SUCCESS;

} /* oldgaa_rlease_rights */

/**********************************************************************
Function:   oldgaa_rlease_cond_bindings()

Description:
	delete the security context

Parameters:

Returns:
**********************************************************************/

oldgaa_error_code  PRIVATE
oldgaa_release_cond_bindings(UNUSED(uint32                 *minor_status),
                          oldgaa_cond_bindings_ptr  *cond_bind)
{
  oldgaa_cond_bindings_ptr  *cred = cond_bind;
  uint32                  inv_minor_status = 0, inv_major_status = 0;

	if (*cred == NULL || *cred == OLDGAA_NO_COND_BINDINGS) 
	return OLDGAA_SUCCESS;

	(*cred)->reference_count--;
	if ((*cred)->reference_count > 0) {
	    *cond_bind = NULL;
	    return OLDGAA_SUCCESS;
    }

	/* ignore errors to allow for incomplete context handles */

       if ((*cred)->condition != NULL)
       inv_major_status = oldgaa_release_conditions(&inv_minor_status,
			                         &((*cred)->condition));

       if ((*cred)->next != NULL) 
       inv_major_status = oldgaa_release_cond_bindings(&inv_minor_status,
			                            &((*cred)->next));
       
    free(*cred);
	*cond_bind = NULL;

  return OLDGAA_SUCCESS;

} 

/**********************************************************************
Function:   oldgaa_rlease_conditions()

Description:
	delete the security context

Parameters:

Returns:
**********************************************************************/

oldgaa_error_code  PRIVATE
oldgaa_release_conditions(UNUSED(uint32             *minor_status),
                          oldgaa_conditions_ptr *cond)
{
  oldgaa_conditions_ptr  *cred = cond;
  
  oldgaa_conditions_ptr start   = *cond;
  oldgaa_conditions_ptr anchor  = NULL;
  oldgaa_conditions_ptr current = NULL;

	if (*cred == NULL || *cred == OLDGAA_NO_CONDITIONS) 
    return OLDGAA_SUCCESS;

  while (start) {
    start->reference_count --;
    if (start->reference_count > 0) {
      if (anchor == NULL) {
        current = anchor = start;
      }
      current->next = start;
      current = start;
      start = start->next;
    }
    else {
      oldgaa_conditions_ptr tmp = start->next;

      free(start->type);
      free(start->authority);
      free(start->value);
      free(start);
      start = tmp;
    }
  }

  if (anchor) {
    current->next = NULL;
    *cond = anchor;
  }
  else
    *cond = NULL;

  return OLDGAA_SUCCESS;
}
/*   if ( */

/*   (*cred)->reference_count--; */
/*   if ((*cred)->reference_count > 0) { */
/*     *cond = NULL; */
/*     return OLDGAA_SUCCESS; */
/*   } */
/* 	/\* ignore errors to allow for incomplete context handles *\/ */

/*   if ((*cred)->next != NULL) { */
/*     inv_major_status = oldgaa_release_conditions(&inv_minor_status, */
/*                                                  &((*cred)->next)); */
/*   } */

/* 	if ((*cred)->type      != NULL) free((*cred)->type); */
/* 	if ((*cred)->authority != NULL) free((*cred)->authority); */
/* 	if ((*cred)->value     != NULL) free((*cred)->value); */

/*   free(*cred); */

/*   return OLDGAA_SUCCESS; */

/* }  */
/**********************************************************************
Function:   oldgaa_rlease_answer()

Description:
	delete the security context

Parameters:

Returns:
**********************************************************************/

oldgaa_error_code  PRIVATE
oldgaa_release_answer(UNUSED(uint32         *minor_status),
                   oldgaa_answer_ptr *answer)
{
  oldgaa_answer_ptr  *cred = answer;
  uint32           inv_minor_status = 0, inv_major_status = 0;

	if (*cred == NULL || *cred == OLDGAA_NO_ANSWER) 
	return OLDGAA_SUCCESS;

	/* ignore errors to allow for incomplete context handles */

       if ((*cred)->rights!= NULL) 
       inv_major_status = oldgaa_release_rights(&inv_minor_status,
			                     &((*cred)->rights));
       
    if ((*cred)->valid_time != NULL) free((*cred)->valid_time);
    free(*cred);

  return OLDGAA_SUCCESS;

} /* oldgaa_rlease_answer */


/**********************************************************************
Function:   oldgaa_rlease_principals()

Description:
	delete the security context

Parameters:

Returns:
**********************************************************************/

oldgaa_error_code  PRIVATE
oldgaa_release_sec_attrb(UNUSED(uint32             *minor_status),
                      oldgaa_sec_attrb_ptr   *attributes)
{

oldgaa_sec_attrb_ptr  *cred = attributes;
uint32              inv_minor_status = 0, inv_major_status = 0;

	if (*cred == NULL || *cred == OLDGAA_NO_SEC_ATTRB) 
	return OLDGAA_SUCCESS;

	/* ignore errors to allow for incomplete context handles */

       if ((*cred)->next != NULL) 
       inv_major_status = oldgaa_release_sec_attrb(&inv_minor_status,
			      &((*cred)->next));

	if ((*cred)->type      != NULL) free((*cred)->type);
	if ((*cred)->authority != NULL) free((*cred)->authority);
	if ((*cred)->value     != NULL) free((*cred)->value);

    free(*cred);

  return OLDGAA_SUCCESS;

} 

/**********************************************************************/
