import {readdir,readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
async function walk(path){const entries=await readdir(path,{withFileTypes:true});return (await Promise.all(entries.map(e=>e.isDirectory()?walk(`${path}/${e.name}`):`${path}/${e.name}`))).flat();}
const files=(await walk('dist')).filter(p=>!p.endsWith('/sw.js')).sort();
const version=createHash('sha256');for(const f of files)version.update(await readFile(f));
const assets=files.map(f=>'/'+f.slice(5));
const cache='aegis-app-'+version.digest('hex').slice(0,12);
await writeFile('dist/sw.js',`const CACHE=${JSON.stringify(cache)},ASSETS=${JSON.stringify([...assets,'/'])};
self.addEventListener('install',e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS)).then(()=>self.skipWaiting()));});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k.startsWith('aegis-app-')&&k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim()));});
self.addEventListener('fetch',e=>{const u=new URL(e.request.url);if(e.request.method!=='GET'||u.origin!==self.location.origin)return;e.respondWith(caches.open(CACHE).then(async c=>{if(e.request.mode==='navigate')return (await c.match('/index.html'))||fetch(e.request);return (await c.match(e.request,{ignoreVary:true}))||fetch(e.request);}));});
`);
console.log('Offline app cache generated:',cache);
