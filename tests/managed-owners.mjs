import assert from 'node:assert/strict';
import {test} from 'node:test';
import {installManagedOwners} from '../native/podman/managed-owners.js';

function setup(spawn, owner) {
  const privilege = new EventTarget();
  const cockpit = {spawn, user: async () => ({id: 1001}), location: {path: [], options: owner ? {owner} : {}}};
  class App {
    constructor() { this.state = {users: [{uid:0,name:'system',con:null},{uid:null,name:'admin',con:null}]}; this.calls=[]; this.resets=0; }
    setState(update, done) {Object.assign(this.state,typeof update==='function'?update(this.state):update);done?.();}
    componentDidMount() {this.onNavigate();}
    componentWillUnmount() {}
    onNavigate() {
      const owner=cockpit.location.options.owner;
      const user=this.state.users.find(u=>String(u.uid)===owner);
      if(owner && !user) this.resets++;
      else if(user) this.init(user.uid,user.name);
    }
    async init(uid,name) {this.calls.push([uid,name]);this.setState({users:this.state.users.map(u=>u.uid===uid?{...u,con:{uid}}:u)});}
    cleanupAfterService(con) {this.state.users=this.state.users.filter(u=>u.uid!==con.uid);}
  }
  installManagedOwners(App,cockpit,privilege);
  const app=new App();app.componentDidMount();return {app,cockpit,privilege};
}
const payload=JSON.stringify({scopes:[{uid:0,owner:'root'},{uid:1000,owner:'operator'}]});
const tick=()=>new Promise(resolve=>setTimeout(resolve,0));
test('All initializes configured owner without a dropdown change',async()=>{
  const {app}=setup(async()=>payload);await tick();
  assert.equal(app.state.ownerFilter,'all');assert.deepEqual(app.calls,[[1000,'operator']]);
  app.onNavigate();await tick();assert.equal(app.calls.length,1);
});
test('cold UID link is preserved until owner discovery completes',async()=>{
  let release;const {app}=setup(()=>new Promise(r=>release=r),'1000');
  assert.equal(app.resets,0);release(payload);await tick();
  assert.equal(app.resets,0);assert.equal(app.calls[0][0],1000);
});
test('elevation rechecks configured owners after an unprivileged first load',async()=>{
  let allowed=false;
  const {app,privilege}=setup(async()=>{if(!allowed)throw {problem:'access-denied'};return payload});
  await tick();assert.equal(app.calls.length,0);
  allowed=true;privilege.dispatchEvent(new Event('changed'));await tick();
  assert.equal(app.calls.length,1);assert.equal(app.state.users.filter(u=>u.uid===1000).length,1);
});
test('late closed connection cannot delete a replacement for the same UID',async()=>{
  const {app}=setup(async()=>payload);await tick();
  const current=app.state.users.find(u=>u.uid===1000).con;
  app.cleanupAfterService({uid:1000});assert.equal(app.state.users.find(u=>u.uid===1000).con,current);
  app.cleanupAfterService(current);assert.equal(app.state.users.some(u=>u.uid===1000),false);
});
