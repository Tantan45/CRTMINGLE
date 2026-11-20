const $=selector=>document.querySelector(selector);
// The home page opens the separate chat setup page.
$('#joinTop').onclick=()=>{window.location.href='/chat?rules=1'};
// Load public footer details and the live online count.
async function refreshPublicInfo(){try{const response=await fetch('/api/public/config');const data=await response.json();$('#headerOnlineCount').textContent=data.onlineUsers;$('#counselor').textContent='School counselor: '+data.counselor;$('#crisis').textContent=data.crisis;}catch{}}
refreshPublicInfo();setInterval(refreshPublicInfo,10000);
// Keep policy and group links functional on the landing page.
$('#footerRules').onclick=event=>{event.preventDefault();$('#rulesDialog').showModal()};
