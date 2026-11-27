import test from "node:test";
import assert from "node:assert/strict";
import { fetchOne } from "../action/observe.mjs";
const ident={id:"fixture",headers:{"user-agent":"crawlcheck-test"}};
test("observer refuses a direct private target without fetching",async()=>{
  const calls=[];
  const result=await fetchOne("http://169.254.169.254/latest/meta-data",ident,1000,async u=>{calls.push(u);return new Response("secret");});
  assert.equal(calls.length,0);
  assert.match(result.row.error,/blocked: non-public address/);
});
test("observer checks every redirect hop and blocks an internal target",async()=>{
  const calls=[];
  const result=await fetchOne("https://example.test/start",ident,1000,async (u,opt)=>{
    calls.push([String(u),opt.redirect]);
    return new Response(null,{status:302,headers:{location:"http://127.0.0.1/admin"}});
  });
  assert.deepEqual(calls,[["https://example.test/start","manual"]]);
  assert.equal(result.row.status,null);
  assert.match(result.row.error,/blocked: non-public address/);
});
test("safe relative redirect retains a final URL and body digest",async()=>{
  const calls=[];
  const result=await fetchOne("https://example.test/start",ident,1000,async (u,opt)=>{
    calls.push(String(u));
    assert.ok(opt.signal);
    return String(u).endsWith("/start")
      ?new Response(null,{status:302,headers:{location:"/done"}})
      :new Response("ok",{status:200});
  });
  assert.equal(result.row.status,200);
  assert.equal(result.row.url_final,"https://example.test/done");
  assert.equal(result.row.bytes,2);
  assert.match(result.row.sha256,/^[a-f0-9]{64}$/);
  assert.deepEqual(calls,["https://example.test/start","https://example.test/done"]);
});
test("redirect cycles stop after the limit",async()=>{
  let calls=0;
  const result=await fetchOne("https://example.test/start",ident,1000,async()=>{
    calls++;
    return new Response(null,{status:302,headers:{location:"/start"}});
  });
  assert.equal(calls,6);
  assert.match(result.row.error,/more than 5 redirects/);
});
