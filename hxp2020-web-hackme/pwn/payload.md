</SCRIPT>

<!-- The disqus scripts expect a window.context variable, so let's give them one (also re-use it as the source URL of our script). We could probably just put the code directly in here, but this way we avoid any mangling of anything by the DOM injection. -->
<div id="context">__JS_PAYLOAD__/download</div>

<!-- Actual JavaScript scripts here are never loaded (because this HTML is assigned via innerHTML), but jQuery templates still work if we load the relevant disqus script the normal way. -->
<script class="js-inline-template" type="text/x-jquery-tmpl"><code>${window.fetch(window.context.innerText).then(r => r.text()).then(window.eval)}</code></SCRIPT>

<!-- Keep the DOM clean. -->
<SCRIPT type="text/template">

