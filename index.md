---
layout: home
title: VOMS home
---
<!--
<div class="row-fluid marketing">
	<h2>News</h2>
</div>
{% for post in site.posts limit:2 %}
<div class="row-fluid marketing news-row">
	    <div class="span2 news-date">
		    <p class="text-left">{{ post.date | date_to_long_string }}</p>
	    </div>
	    <div class="span10">
            <h3>{{post.title}}</h3>
            <p>{{post.summary}} <a href="{{post.url}}">more</a></p>
			
        </div>
</div>
{% endfor %}
-->
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
		<h2>APIs for attribute based authorization</h2>
		<p>Services can uses VOMS attributes to allow access to resources. When authenticating users using proxy certificates, they can extract VOMS attributes from the proxy using the VOMS API and use them in the authorization process.</p>
		<p>The VOMS API come in Java and C/C++ bindings. It allows services to extract VO membership information from the proxy certificate authentication and use it to take authorization decisions.</p>
	</div>
	<div class="span6">
		<img src="assets/img/snippet.png" class="img-rounded">
	</div>
</div>

<hr class="soften">

</div>

