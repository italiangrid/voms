#!/bin/bash
# jekyll serve

docker run --rm --label=jekyll --volume="$(pwd):/srv/jekyll" -it \
    -e FORCE_POLLING=true \
    -p 4000:4000 \
    jekyll/jekyll jekyll serve --watch
