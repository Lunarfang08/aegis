import type {Request,Report} from './types';
let worker: Worker | null = null;
let sequence = 0;
const pending = new Map<number,{resolve:(v:any)=>void;reject:(e:Error)=>void}>();
function call(action:string,value:unknown,format?:string):Promise<any> {
  if(!worker) {
    worker = new Worker(new URL('./engine.worker.ts',import.meta.url),{type:'module'});
    worker.onmessage = ({data}) => { const p = pending.get(data.id); if(p) {pending.delete(data.id);data.error?p.reject(new Error(data.error)):p.resolve(data.result);} };
    worker.onerror = () => { pending.forEach(p=>p.reject(new Error('The verification engine could not load. Rebuild WASM and reload the app.'))); pending.clear(); worker?.terminate(); worker=null; };
  }
  return new Promise((resolve,reject)=>{const id=++sequence;pending.set(id,{resolve,reject});worker!.postMessage({id,action,value,format});});
}
export const analyze = (value:Request):Promise<Report> => call('analyze',value);
export const render = (value:Report,format:string):Promise<string> => call('render',value,format);
