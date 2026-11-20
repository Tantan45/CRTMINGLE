const $=selector=>document.querySelector(selector);
// The home page opens the separate chat setup page.
$('#joinTop').onclick=()=>{window.location.href='/chat?rules=1'};
// Keep policy and group links functional on the landing page.
$('#footerRules').onclick=event=>{event.preventDefault();$('#rulesDialog').showModal()};
