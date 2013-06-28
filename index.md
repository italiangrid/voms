---
layout: default
title: VOMS home
---

<div class="marketing">
	<h1>VOMS</h1>
	<p class="lead">VOMS (Virtual Organization Membership Service) enables Virtual Organization access control in distributes services. It is the tool used by <a href="http://wlcg.web.cern.ch/">WLCG</a> to authorize the use of the storage and computing resources that were used in discovering the <a href="http://press.web.cern.ch/press-releases/2012/07/cern-experiments-observe-particle-consistent-long-sought-higgs-boson">Higgs boson</a>.</p> 
	<p>VOMS is an attribute authority that issues signed tokens (Attribute Certificate or SAML assertions) stating a user membership to an organisation. Attributes are used by services to allow or deny us of resources that are.</p>
</div>

<hr class="soften">

{% for post in site.posts limit:2 %}
<div class="row-fluid marketing">
	<div class="span2">
		<p class="text-left">{{ post.date | date_to_long_string }}</p>
	</div>
	<div class="span10">
		<p><span class="news-title">{{ post.title }}</span> {{ post.summary }}</p>
  </div>
</div>
{% endfor %}

<hr class="soften">

<div class="row-fluid marketing">
	<div class="span6">
		<h2 class="">Organization management</h2>
		<p class="">VOMS provides a web application for managing organizations. It support a rich registration process with AUP acceptance enforcement and membership expiration. Users can be assigned to groups and can be given roles and generics attributes.</p>
		<p class="">Or VO administrators can use a command line client for management.</p>
		
	</div>
	<div class="span6">
		<img src="http://docs.openstack.org/trunk/openstack-compute/admin/content/figures/1/figures/horizon-screenshot.jpg" class="img-rounded">
	</div>
</div>

<hr class="soften">

<div class="row-fluid marketing">
	<div class="span6">
		<h2 class="">Client tools</h2>
		<p class="">A user can use the VOMS clients to request a signed token (an Attribute Certificate compliant to <a href="http://www.ietf.org/rfc/rfc3281.txt">RFC 3281</a>) from a VOMS server that state that she belongs to the VO and embed it in to an <a href="http://www.ietf.org/rfc/rfc3820.txt">X509 Proxy Certificate</a>. When authenticating to third party services using the proxy, the user brings along this information that services may use to drive authorization decisions.
		</p>
	</div>
	<div class="span6">
		<img src="assets/img/clients.png" class="img-polaroid">
	</div>
</div>

<hr class="soften">

<div class="row-fluid marketing">
	<div class="span6">
		<h2>Enable attribute based authorization</h2>
		<p>Services can uses VOMS attributes to allow access to resources. When authenticating users using proxy certificates, they can extract VOMS attributes from the proxy using the VOMS API and use them in the authorization process.</p>
		<p>The VOMS API come in Java and C/C++ bindings. It allows services to extract VO membership information from the proxy certificate authentication and use it to take authorization decisions.</p>
	</div>
	<div class="span6">
		<img src="assets/img/snippet.png" class="img-rounded">
	</div>
</div>

<hr class="soften">

</div>

