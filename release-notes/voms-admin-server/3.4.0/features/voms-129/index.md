---
layout: default
title: VOMS Admin server v. 3.4.0 - Configure multiple AUP resing reminders
---

[VOMS-129](https://issues.infn.it/jira/browse/VOMS-129) - VOMS admin provides configurable notification interval for Sign AUP messages

# Configure multiple AUP resing reminders

This enhancement was aimed at the notification sent out by VOMS Admin when a VO user has to sign the AUP again. 

Before this in fact, there was only one email sent to the user. Admins could specify in the configuration how much time the user has in order to sign the AUP after the email was sent, but multiple reminders weren't allowed. If only one email is sent to the user, there is an increased risk that the user gets suspended because the email gets lost (spam filter, mail server problems), or he can't act on it (holidays). Even though the user can reinstate his membership any time by signing the AUP, an unexpected suspension notice can still cause users to worry or even panic.

With [VOMS Admin 3.4.0 release][vomsadmin340], admins can send out multiple reminders.

The `voms.aup.sign_aup_task_lifetime` option has become a comma separated list containing the days at which emails are sent to the user before they get suspended, for example:

    voms.aup.sign_aup_task_lifetime = 30,14,7,1

This example would send 4 emails, the first 30 days before suspension, then one 14 days, one 7 days before, and the last one the day before suspension. 

Configuring it in this way doesn't break compatibility with existing configurations, e.g.

    voms.aup.sign_aup_task_lifetime = 15

will still be a valid configuration, it will just send out one email 15 days before.

[vomsadmin340]: {{site.baseurl}}/release-notes/voms-admin-server/3.4.0/