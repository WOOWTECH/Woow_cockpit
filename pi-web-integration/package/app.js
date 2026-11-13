(() => {
 const host=window.location.hostname;
 const allowed=['__GATEWAY_HOST__','__VPN_HOST__'].filter(Boolean);
 const publicOrigin='__PUBLIC_ORIGIN__';
 const publicEntry=publicOrigin.startsWith('https://')&&window.location.origin===publicOrigin;
 const frame=document.getElementById('pi');
 if(!publicEntry&&!allowed.includes(host)){frame.hidden=true;document.getElementById('unavailable').hidden=false;return;}
 if(!publicEntry&&window.location.protocol!=='http:'){
  frame.hidden=true;
  const warning=document.getElementById('secure-required');warning.hidden=false;
  document.getElementById('secure-link').href=`http://${host}:${window.location.port||9090}/`;
  return;
 }
 const gatewayOrigin=publicEntry?publicOrigin:`http://${host}:__GATEWAY_PORT__`;
 const systemTheme=window.matchMedia('(prefers-color-scheme: dark)');
 function syncTheme(){
  let preference='auto';try{preference=localStorage.getItem('shell:style')||'auto'}catch{}
  const theme=preference==='dark'||(preference==='auto'&&systemTheme.matches)?'dark':'light';
  document.documentElement.classList.toggle('pf-v6-theme-dark',theme==='dark');
  document.documentElement.style.colorScheme=theme;
  frame.contentWindow?.postMessage({type:'woow-cockpit-theme',theme},gatewayOrigin);
 }
 frame.addEventListener('load',syncTheme);
 window.addEventListener('storage',event=>{if(event.key==='shell:style'||event.key===null)syncTheme()});
 window.addEventListener('cockpit-style',syncTheme);
 systemTheme.addEventListener('change',syncTheme);
 window.addEventListener('message',event=>{if(event.origin===gatewayOrigin&&event.source===frame.contentWindow&&event.data?.type==='woow-cockpit-theme-ready')syncTheme()});
 syncTheme();
 frame.src=`${gatewayOrigin}/${publicEntry?'pi-web/':''}`;
})();
