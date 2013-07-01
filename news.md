---
layout: default
title: News
---

# News
{% for post in site.posts limit:10 %}
<div class="row-fluid marketing news-row">
	    <div class="span2">
		    <p class="text-left">{{ post.date | date_to_long_string }}</p>
	    </div>
	    <div class="span10">
            <h3>{{post.title}}</h3>
            <p>{{post.summary}}</p>
			<a href="{{ site.baseurl }}{{post.url}}">Read more</a>
        </div>
</div>
{% endfor %}