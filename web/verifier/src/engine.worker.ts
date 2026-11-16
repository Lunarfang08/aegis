/// <reference lib="webworker" />
import init, {analyze,render} from './wasm/aegis_wasm';
import wasmUrl from './wasm/aegis_wasm_bg.wasm?url';
const ready = init({module_or_path:wasmUrl});
self.onmessage = async ({data}) => {
  try {
    await ready;
    const result = data.action === 'analyze' ? JSON.parse(analyze(JSON.stringify(data.value))) : render(JSON.stringify(data.value),data.format);
    self.postMessage({id:data.id,result});
  } catch(error) { self.postMessage({id:data.id,error:String(error)}); }
};
