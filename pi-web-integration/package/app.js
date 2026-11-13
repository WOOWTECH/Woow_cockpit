(() => {
 const host=window.location.hostname;
 const allowed=['__GATEWAY_HOST__','__VPN_HOST__'].filter(Boolean);
 const frame=document.getElementById('pi'),direct=document.getElementById('direct');
 if(!allowed.includes(host)){frame.hidden=true;direct.hidden=true;document.getElementById('notice').hidden=true;document.getElementById('unavailable').hidden=false;return;}
 if(window.location.protocol!=='https:'){
  frame.hidden=true;direct.hidden=true;document.getElementById('notice').hidden=true;
  const warning=document.getElementById('secure-required');warning.hidden=false;
  document.getElementById('secure-link').href=`https://${host}:${window.location.port||9090}/`;
  return;
 }
 const url=`https://${host}:__GATEWAY_PORT__/`;direct.href=url;frame.src=url;
})();
