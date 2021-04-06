#!/bin/bash
jekyll serve

#docker run --rm --label=jekyll -v $(pwd):/srv/jekyll -it \
#    -p 4000:4000 \
#    -e POLLING=true \
#    jekyll/jekyll jekyll serve
