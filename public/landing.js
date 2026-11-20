const $=selector=>document.querySelector(selector);
// The home page opens the separate chat setup page.
$('#joinTop').onclick=()=>{window.location.href='/chat?rules=1'};
// Show the number of live chat connections reported by this server instance.
async function refreshOnlineCount(){try{const response=await fetch('/api/public/config');const data=await response.json();$('#headerOnlineCount').textContent=data.onlineUsers;}catch{}}
refreshOnlineCount();setInterval(refreshOnlineCount,10000);
// Keep policy and group links functional on the landing page.
$('#footerRules').onclick=event=>{event.preventDefault();$('#rulesDialog').showModal()};
