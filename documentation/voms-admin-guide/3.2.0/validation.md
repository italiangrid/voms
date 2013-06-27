---
layout: default
title: VOMS Admin membership validation
---

# VOMS Admin membership validation

In order to be compliant with the [JSPG policies on VO registration services][jspg-policies], VOMS Admin
implements two membership validation mechanisms:

- The Acceptable Usage Policy (AUP) signature verification mechanism
- the Membership expiration mechanism

## The AUP acceptance validation

The AUP acceptance mechanism enforces that every VO member has signed the VO
Acceptable Usage Policy. The signature is requested at VO registration time
and periodically, with the default period being every 12 months, in accordance
with the EGI policy.

When the AUP signature for a user expires in the VOMS database, VOMS sends an
email notification to the user requesting the signature of the AUP within a
grace period. 

The default AUP grace period is now <strong>15 days</strong> after the first notification
has been sent to the user that his/her signature has expired or a request
to sign again the AUP has been requested by the VO administrator. 

The length of the grace period can be changed using the
`voms.aup.sign_aup_task_lifetime` property.

When a user fails to sign the AUP in time, the user is supended, and VOMS
Admin sends a notification to the suspended user and to VO administrators to
inform about this fact.

<div class="alert alert-error">
	<h4>Important!</h4>
	No intervention is required from the VO administrator to restore the user membership.
	The user can restore his/her membership at <strong>anytime</strong> by signing the AUP following
	the link to the Sign AUP page included in the notification email.
</div>

### Requesting reacceptance for the VO AUP

A VO administrator can trigger the re-acceptance of the VO AUP at any time.
This operation can be done for:

- a single user, by clicking the *Request AUP reacceptance* button in the user detailed info page.
- all VO users, by clicking the *Trigger reacceptance* button for the currently active AUP version.

## Membership expiration validation

The membership expiration mechanism enforces that every VO member is actually
known and approved by the VO manager. When a user is registered in a VO an
expiration date is linked to his/her membership. The default lifetime for a
VOMS membership is 12 months (in accordance with the EGI policy), but can be
extended using the `voms.membership.default_lifetime` configuration property.

VOMS warns about expiring users in the next 30 days with an email sent to VO administrators.
The period covered by these warnings can be configured with the `voms.membership.expiration_warning_period`
property, to show, for instance, users about to expired in the next three months.

VOMS sends out these warning emails periodically, by default on a daily basis.
The periodicity of these warnings can be set with the `voms.membership.notification_resend_period`.

Once a membership expires for a given user, the user is suspended and a notification
is sent to the user and the relevant VO administrators.

<div class="alert alert-error">
	<h4>Important!</h4>
	The user <strong>cannot</strong> extend his membership in any way.
	The membership can only be extended by the intervention of a VO administrator.
</div>

### Disabling user suspension after membership expiration

The automatic suspension of users whose membership has expired can be disabled
using the `voms.preserve_expired_members` configuration property. VO
Administrators will still be notified of any expired or about to expire user
in order to take action.

### Turning off membership validation completely

The membership expiration checks can be completely disabled using the `voms.disable_membership_end_time`.












[jspg-policies]: https://documents.egi.eu/public/RetrieveFile?docid=79&version=6&filename=EGI-SPG-VOManagement-V1_0.pdf


