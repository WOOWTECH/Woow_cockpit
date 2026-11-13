(() => {
 const host=window.location.hostname;
 const allowed=['__GATEWAY_HOST__','__VPN_HOST__'].filter(Boolean);
 const frame=document.getElementById('pi');
 if(!allowed.includes(host)){frame.hidden=true;document.getElementById('unavailable').hidden=false;return;}
 if(window.location.protocol!=='http:'){
  frame.hidden=true;
  const warning=document.getElementById('secure-required');warning.hidden=false;
  document.getElementById('secure-link').href=`http://${host}:${window.location.port||9090}/`;
  return;
 }
 frame.src=`http://${host}:__GATEWAY_PORT__/`;
})();
