#!/bin/bash

docker run --rm --label=jekyll -v $(pwd):/srv/jekyll -it \
    -p $(docker-machine ip default):4000:4000 \
    -e POLLING=true \
    jekyll/jekyll:pages \
    jekyll serve --incremental --watch

# Old command
# jekyll server --baseurl '' --watch
