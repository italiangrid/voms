/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <stdio.h>
#include <openssl/err.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <assert.h>

#include "proxypolicy.h"

/**
 * Sets the policy language of the PROXY_POLICY
 *
 * @param policy the PROXY_POLICY to set the policy language of
 * @param policy_language the policy language to set it to
 *
 * @return 1 on success, 0 on error
 */
int PROXY_POLICY_set_policy_language(
    PROXY_POLICY *                       policy,
    ASN1_OBJECT *                       policy_language)
{
    if(policy_language != NULL) 
    {
        ASN1_OBJECT_free(policy->policyLanguage);
        policy->policyLanguage = OBJ_dup(policy_language);
        return 1;
    }
    return 0;
}

/**
 * Sets the policy of the PROXY_POLICY
 *
 * @param proxypolicy the proxy policy to set the policy of
 * @param policy the policy to set it to
 * @param length the length of the policy
 *
 * @return 1 on success, 0 on error
 */
int PROXY_POLICY_set_policy(
    PROXY_POLICY *                       proxypolicy,
    unsigned char *                     policy,
    int                                 length)
{
  assert(length >= 0);
  
    if(policy != NULL)
    {
        unsigned char *                 copy = malloc(length);
        assert(copy != NULL && "malloc failed");
        memcpy(copy, policy, length);

        if(!proxypolicy->policy)
        {
            proxypolicy->policy = ASN1_OCTET_STRING_new();
        }
        
        ASN1_OCTET_STRING_set(proxypolicy->policy, copy, length);

    }
    else
    {
        if(proxypolicy->policy)
        {
            ASN1_OCTET_STRING_free(proxypolicy->policy);
        }
    }

    return 1;
}

IMPLEMENT_ASN1_DUP_FUNCTION(PROXY_POLICY);
