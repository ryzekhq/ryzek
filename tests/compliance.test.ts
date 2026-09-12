import { compileAll } from "../src/rule-spec";
import { complianceSpecs, owaspCoverage, RULE_TO_OWASP, OWASP_MCP } from "../src/compliance-rules";
import { newRules } from "../src/ryzek-rules-index";
import { ToolManifest } from "../src/types";

const rules = compileAll(complianceSpecs);
const sk=(n:string,d:string,e:any={}):ToolManifest=>({name:n,description:d,
  sourceFile:e.src??"server.json",parameters:e.parameters,permissions:e.permissions,
  raw:{body:e.body??"",...e.raw}});
interface C{label:string;tool:ToolManifest;want:string[]}

const DIRTY:C[]=[
 {label:"wildcard oauth scope",want:["oauth-misconfiguration"],
  tool:sk("srv","A server",{body:'oauth: { client_id:"x", scopes: ["*"] }'})},
 {label:"implicit flow",want:["oauth-misconfiguration"],
  tool:sk("srv","A server",{body:'authorization_endpoint="/a"; response_type="token"'})},
 {label:"wildcard redirect",want:["oauth-misconfiguration"],
  tool:sk("srv","A server",{body:'client_id="a"; redirect_uris: ["https://*.example.net/cb"]'})},
 {label:"pkce disabled",want:["oauth-misconfiguration"],
  tool:sk("srv","A server",{body:'oauth config: code_challenge = false'})},
 {label:"cors star",want:["permissive-cors"],
  tool:sk("srv","A server",{body:'res.setHeader("Access-Control-Allow-Origin","*")'})},
 {label:"cors origin true",want:["permissive-cors"],
  tool:sk("srv","A server",{body:'app.use(cors({ origin: true, credentials: true }))'})},
 {label:"no-verify install",want:["missing-provenance"],
  tool:sk("srv","A server",{body:'pip install --trusted-host files.pythonhosted.org pkg'})},
 {label:"curl binary no checksum",want:["missing-provenance"],
  tool:sk("srv","A server",{body:'curl -sL https://x.io/agent.tar.gz | tar xz'})},
 {label:"tls verify off",want:["missing-provenance"],
  tool:sk("srv","A server",{body:'NODE_TLS_REJECT_UNAUTHORIZED=0 npm i'})},
];

const CLEAN:C[]=[
 {label:"scoped oauth with pkce",want:[],
  tool:sk("srv","A server",{body:'oauth: { client_id:"x", scopes:["read:files"], code_challenge_method:"S256", redirect_uris:["https://app.example.net/cb"] }'})},
 {label:"cors explicit origin",want:[],
  tool:sk("srv","A server",{body:'res.setHeader("Access-Control-Allow-Origin","https://app.example.net")'})},
 {label:"curl with checksum",want:[],
  tool:sk("srv","A server",{body:'curl -sL https://x.io/agent.tar.gz -o a.tgz && sha256sum -c a.tgz.sha256'})},
 {label:"plain skill",want:[],tool:sk("fmt","Formats tables",{body:'return rows.join("|")'})},
 {label:"cosign verified",want:[],
  tool:sk("srv","A server",{body:'curl -sL https://x.io/bin -o b && cosign verify-blob b'})},
];

let pass=0,fail=0;
const run=(t:ToolManifest)=>rules.flatMap(r=>r.check(t));
console.log("DIRTY\n"+"-".repeat(66));
for(const c of DIRTY){const g=run(c.tool).map(f=>f.ruleId);
 const ok=c.want.every(w=>g.includes(w));
 console.log(`${ok?"PASS":"FAIL"}  ${c.label.padEnd(26)} ${g.join(", ")||"(none)"}`);ok?pass++:fail++;}
console.log("\nCLEAN\n"+"-".repeat(66));
for(const c of CLEAN){const g=run(c.tool).map(f=>f.ruleId);
 const ok=g.length===0;
 console.log(`${ok?"PASS":"FAIL"}  ${c.label.padEnd(26)} ${g.join(", ")||"(silent)"}`);ok?pass++:fail++;}

console.log("\n"+"=".repeat(66));
console.log(`${pass} passed, ${fail} failed, ${pass+fail} total`);

// mapping integrity
const all=[...newRules.map(r=>r.id),...complianceSpecs.map(s=>s.id),
 "excessive-permissions","prompt-injection","exfiltration-pattern","hardcoded-secrets",
 "dynamic-execution","description-mismatch","unicode-obfuscation","loose-parameter-schema",
 "untrusted-external-install","concealed-instruction","opaque-payload",
 "homoglyph-tool-name","duplicate-tool-name","toolset-mutation","shadow-mcp-discovery"];
const uniq=[...new Set(all)];
const unmapped=uniq.filter(id=>!RULE_TO_OWASP[id]);
const orphan=Object.keys(RULE_TO_OWASP).filter(id=>!uniq.includes(id));
console.log(`\nOWASP MAPPING`);
console.log(`  rules total      ${uniq.length}`);
console.log(`  mapped           ${Object.keys(RULE_TO_OWASP).length}`);
console.log(`  unmapped         ${unmapped.length?unmapped.join(", "):"none"}`);
console.log(`  orphan mappings  ${orphan.length?orphan.join(", "):"none"}`);

console.log(`\nCOVERAGE — OWASP MCP Top 10`);
for(const c of owaspCoverage()){
  const bar = c.count ? "#".repeat(Math.min(c.count,12)) : "-";
  console.log(`  ${c.id}  ${String(c.count).padStart(2)}  ${bar.padEnd(12)} ${c.category}`);
}
const covered=owaspCoverage().filter(c=>c.count>0).length;
console.log(`\n  ${covered} of 10 categories covered`);
