---
title: XSS
type: slide
slideOptions:
  showNotes: true
  transition: none
  transitionSpeed: fast
  dependencies:
    - src: https://a.disquscdn.com/1587400073/build/js/abadd50d331d.js
      async: false
    - src: https://vimeo.com/api/oembed.json?url=https://vimeo.com/419314015&callback=window.Reveal.navigateRight
      async: true
    - src: __HTML_PAYLOAD__/pandoc?exportType=rst&delay=1
      async: true
    - src: __HTML_PAYLOAD__/pandoc?exportType=asciidoc&delay=1
      async: true
    - src: __HTML_PAYLOAD__/pandoc?exportType=pdf&delay=1
      async: true
    - src: __HTML_PAYLOAD__/pandoc?exportType=latex&delay=1
      async: true
    - src: https://vimeo.com/api/oembed.json?url=https://vimeo.com/419314015&callback=window.RevealMarkdown.processSlides
      async: true
    - src: __HTML_PAYLOAD__/pandoc?exportType=rst&delay=2
      async: true
    - src: __HTML_PAYLOAD__/pandoc?exportType=asciidoc&delay=2
      async: true
    - src: __HTML_PAYLOAD__/pandoc?exportType=pdf&delay=2
      async: true
    - src: __HTML_PAYLOAD__/pandoc?exportType=latex&delay=2
      async: true
    - src: https://a.disquscdn.com/1587400073/js/src/templates.js
      async: true
---

# How this works:

reveal.js loads arbitrary JS via the `dependencies` config option, and because hackmd uses scripts from all over the place your CSP is a little bit broader than usual.

---

On a second slide, we have an element with a `data-markdown` attribute in the speaker notes. `reveal.js` (both the patched version and the original) allow us to include a remote resource, and do not properly escape closing `</script>` tags. Unfortunately, the speaker notes are not always outside of the original slide yet when the first JSONP response comes in, and processing the slides again would break our DOM injection, so we force a slide navigation to push the speaker notes out of the original slide `<section>` first.

Note:
  <div data-markdown="__HTML_PAYLOAD__/download"></div>

---

The loaded markdown has a jQuery template that is automatically rendered by the libraries pulled from Disqus above. This allows us to `fetch` and `eval` arbitrary JS code (I use an additional network request there, but we could probably just as easily inline that into a `<pre>` tag somewhere).
