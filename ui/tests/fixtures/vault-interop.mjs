// Public synthetic secrets only. Used by Go's wrapper interoperability test.
import {webcrypto} from 'node:crypto';
import {createRequire} from 'node:module';
import {readFileSync} from 'node:fs';
import {VaultSession} from '../../static/security/vault-core.mjs';
globalThis.crypto ??= webcrypto;
const {argon2id}=createRequire(import.meta.url)('../../static/vendor/hash-wasm-4.12.0/argon2.umd.min.js');
let kdfOutput;
const derive=async ({password,salt})=>{
  const output=await argon2id({password,salt,memorySize:65536,iterations:3,parallelism:4,hashLength:32,outputType:'binary'});
  kdfOutput=Buffer.from(output).toString('base64url');return output;
};
const v=new VaultSession(derive);
const rootContext=w=>Object.fromEntries(['owner_id','root_id','root_version','wrapper_id','method'].map(k=>[k,w[k]]));
const passphrase='  SYNTHETIC 密碼 e\u0301 🔐  ';
if(process.argv[2]==='open') {
  const fixture=JSON.parse(readFileSync(0,'utf8'));
  const request={context:fixture.context,revision:'1',destination_profile_sha256:fixture.credential.envelope.destination_profile_sha256,wrapped_key:JSON.stringify(fixture.credential.wrapped_key),envelope:JSON.stringify(fixture.credential.envelope)};
  await v.unlockPassphrase({context:rootContext(fixture.root.passphrase),wrapper:JSON.stringify(fixture.root.passphrase),passphrase});
  const pass=await v.releaseCredential(request);v.lock();
  await v.unlockRecovery({context:rootContext(fixture.root.recovery),wrapper:JSON.stringify(fixture.root.recovery),recovery_key:fixture.root.recovery_key});
  const recovery=await v.releaseCredential(request);v.lock();
  process.stdout.write(JSON.stringify({pass:Buffer.from(pass).toString('base64url'),recovery:Buffer.from(recovery).toString('base64url')}));pass.fill(0);recovery.fill(0);
} else {
  const root=await v.setup({owner_id:'account:alice-密碼-🔐',passphrase});
  const context={owner_id:root.owner_id,root_id:root.root_id,root_version:root.root_version,connector_id:crypto.randomUUID(),credential_id:crypto.randomUUID(),epoch:'1'};
  const destination={schema:'mcpwarden.destination.v1',endpoint:'https://example.com/mcp',header_names:['authorization'],network:'public'};
  // The Go test supplies the digest computed by its trusted destination parser.
  const credential=await v.createCredential({context,revision:'1',destination_profile_sha256:process.argv[2],bundle:JSON.stringify({kind:'header_bundle',headers:[{name:'authorization',value:'Bearer SYNTHETIC_INTEROP'}]})});
  v.lock();process.stdout.write(JSON.stringify({root,context,credential,destination,kdf_output:kdfOutput}));
}
