This is a slightly more convoluted solution to [hxp 2020 CTF's hackme challenge](https://2020.ctf.link/internal/challenge/d400a07d-ac99-4bfb-ad2a-b6c044541897/) which uses a stored XSS vulnerability in the slides feature:

 - The presentation's YAML options allow specifying JavaScript files as dependencies. Any JS file specified by the `dependency` option is loaded and executed (when viewed via the presentation mode, `/p/...`), subject to the server's CSP and their Content-Type header
 - We can use JSONP endpoints that bypass the CSP (e.g. on Vimeo or Slideshare, or on Disqus with a free API key) to run arbitrary existing JS functions _without arguments_
 - We use `Reveal.navigateRight()` followed by `RevealMarkdown.processSlides()` to inject HTML from a `div` element with a `data-markdown` attribute in the speaker notes into the DOM. The slide navigation is necessary to ensure that the speaker notes are outside of the DOM of the original slide before the second request comes in (duplicate calls to `processSlides` break the proof-of-concept).
 - Usually, the included markdown would be enclosed in a `<script type="text/template">` tag to ensure that nothing can escape into the DOM. However, `reveal-markdown.js` does not properly escape `</script>` tags (the check is case sensitive, but should at the very least be case insensitive):

```javascript
    // prevent script end tags in the content from interfering
    // with parsing
    content = content.replace(/<\/script>/g, SCRIPT_END_PLACEHOLDER)
```

 - Actual JS in this DOM injection will never be loaded, because it is assigned via `innerHTML`, but because the CSP includes so many different embed features, we can load [this jQuery templating code](https://a.disquscdn.com/1587400073/js/src/templates.js) from Disqus (it is used on the Disqus login page, fairly easy to find) that walks the entire DOM and renders jQuery template strings.
 - From the template, we can simply grab another script from anywhere (including another note) and `eval` it.

Here's how this proof-of-concept works:
 - The main note (`pwn.md`) is responsible for loading the templating JS (and the old jQuery version that it requires) from Disqus, and issuing the two JSONP calls that lead to the DOM injection. The calls to the `/pandoc` endpoint are just there to ensure that the JSONP calls are slightly delayed and properly sequenced.
 - The `payload.md` note contains the content that is injected into the DOM, and loads and executes the final payload.
 - The `win.js` script is the final XSS payload. It grabs the contents of the `/s/the-flag` page and sends it back to us, but you can just as easily run any other JavaScript code.
 - The `pwn.py` script automates the upload process and automatically reports the XSS page (the slides of `pwn.md` in presentation mode) to the challenge admin.

