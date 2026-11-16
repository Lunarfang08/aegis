import {test,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {readFileSync,readdirSync} from 'node:fs';
import {resolve} from 'node:path';
import {execFileSync} from 'node:child_process';
const root=resolve('../..');
const fixture=(name:string)=>resolve(root,'fixtures',name);
async function demo(page:any,name='Clean evidence'){await page.getByRole('button',{name:new RegExp(`^${name}`)}).click();await expect(page.getByText('SAMPLE DATA')).toBeVisible();await expect(page.getByRole('main')).toHaveAttribute('aria-busy','false');}
async function nav(page:any,name:string){await page.getByRole('navigation').getByRole('button',{name:new RegExp(`^${name}`)}).click();}
async function exportedJson(page:any){await nav(page,'Report');await page.getByRole('radio',{name:/JSON report/}).check();const download=page.waitForEvent('download');await page.getByRole('button',{name:'Download report'}).click();const file=await download;return JSON.parse(readFileSync((await file.path())!,'utf8'));}
test('clean demo matches native engine and all report exports work',async({page})=>{
  const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));await page.goto('/');await demo(page);
  const browser=await exportedJson(page);
  const native=JSON.parse(execFileSync(resolve(root,'target/debug/aegis'),['verify',fixture('clean'),'--trust-store',fixture('demo-trust-store.json'),'--system','Atlas AI Assistant','--json'],{encoding:'utf8'}));
  expect(browser).toEqual(native);expect(browser.summary.valid).toBe(10);
  for(const format of ['HTML report','Markdown report']){await page.getByRole('radio',{name:new RegExp(format)}).check();const download=page.waitForEvent('download');await page.getByRole('button',{name:'Download report'}).click();expect((await download).suggestedFilename()).toMatch(/\.(html|md)$/);}
  expect(errors).toEqual([]);
});
test('evidence search, filters, details and control links',async({page})=>{
  await page.goto('/');await demo(page);await nav(page,'Evidence');await page.getByRole('textbox',{name:'Search evidence'}).fill('embedding');await expect(page.locator('tbody tr')).toHaveCount(1);
  await page.getByRole('button',{name:'Inspect Text embedding model',exact:true}).click();await expect(page.getByRole('dialog')).toBeVisible();await expect(page.getByText(/Exact source bytes match/)).toBeVisible();await page.getByRole('tab',{name:'Original source'}).click();await expect(page.locator('.source-code')).toContainText('CycloneDX');await page.keyboard.press('Escape');
  await page.getByRole('textbox',{name:'Search evidence'}).fill('');await page.getByLabel('Evidence type filter').selectOption('Attestation');await expect(page.locator('tbody tr')).toHaveCount(2);
  await nav(page,'Controls');await page.getByRole('button',{name:/MAP 1.1/}).click();await expect(page.getByText('Reviewed context assessment (unsupported)')).toBeVisible();await expect(page.locator('.requirements')).toContainText('Missing');
});
test('tampered and partial evidence never appear fully verified',async({page})=>{await page.goto('/');await demo(page,'Tampered evidence');await expect(page.getByText('Some evidence needs a closer look')).toBeVisible();let r=await exportedJson(page);expect(r.summary.invalid).toBeGreaterThan(5);expect(r.summary.broken).toBeGreaterThan(0);await nav(page,'Overview');await demo(page,'Partial evidence');r=await exportedJson(page);expect(r.summary.valid).toBe(0);expect(r.summary.unverifiable).toBeGreaterThan(0);});
test('real file import, trust-store import, framework change and reset',async({page})=>{await page.goto('/');await page.locator('input[aria-label="Choose evidence files"]').setInputFiles(readdirSync(fixture('clean')).map(f=>fixture(`clean/${f}`)));await expect(page.getByText('Some evidence needs a closer look')).toBeVisible();await page.getByRole('button',{name:/Trust store/}).click();await page.locator('input[aria-label="Choose trust store"]').setInputFiles(fixture('demo-trust-store.json'));await expect(page.getByText('Integrity checked. Evidence ready to review.')).toBeVisible();await page.getByRole('combobox',{name:'Framework',exact:true}).selectOption('eu-ai-act');await nav(page,'Controls');await expect(page.getByRole('button',{name:/ART. 12/})).toBeVisible();await nav(page,'Overview');await page.getByRole('button',{name:'Clear',exact:true}).click();await expect(page.getByText('Bring your evidence. Get clarity.')).toBeVisible();});
test('unsupported file is visible in input accounting',async({page})=>{await page.goto('/');await page.locator('input[aria-label="Choose evidence files"]').setInputFiles({name:'unsupported.json',mimeType:'application/json',buffer:Buffer.from('{"hello":"world"}')});await nav(page,'Evidence');await expect(page.getByText('unsupported.json', {exact:true})).toBeVisible();await page.getByText('unsupported.json', {exact:true}).click();await expect(page.getByText(/Unsupported format; expected/)).toBeVisible();});
test('offline reload and verification produce no network calls',async({page,context})=>{await page.goto('/');await page.evaluate(async()=>{await navigator.serviceWorker.ready;if(!navigator.serviceWorker.controller)await new Promise<void>(resolve=>navigator.serviceWorker.addEventListener('controllerchange',()=>resolve(),{once:true}));});await context.setOffline(true);await page.reload();await expect(page.getByRole('heading',{name:'Evidence overview'})).toBeVisible();const requests:string[]=[];page.on('request',r=>{if(!r.url().startsWith('http://127.0.0.1:4173/'))requests.push(r.url());});await demo(page);await expect(page.getByText('Integrity checked. Evidence ready to review.')).toBeVisible();expect(requests).toEqual([]);});
test('desktop and mobile are accessible and do not overflow',async({page})=>{
  await page.goto('/');for(const size of [{width:1440,height:1080},{width:390,height:844}]){await page.setViewportSize(size);const results=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa']).analyze();expect(results.violations.map(v=>({id:v.id,nodes:v.nodes.map(n=>({target:n.target,summary:n.failureSummary}))}))).toEqual([]);expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);}
  await page.getByRole('button',{name:'Open navigation'}).click();await page.getByRole('navigation').getByRole('button',{name:/Evidence/}).click();await expect(page.getByRole('heading',{name:'Your evidence',exact:true})).toBeVisible();
});
test('populated views, control expansion and evidence dialog pass accessibility checks',async({page})=>{
  await page.goto('/');await demo(page);
  async function accessible(){const result=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa']).analyze();expect(result.violations.map(v=>({id:v.id,nodes:v.nodes.map(n=>({target:n.target,summary:n.failureSummary}))}))).toEqual([]);}
  await accessible();await nav(page,'Evidence');await accessible();await page.getByRole('button',{name:'Inspect Text embedding model',exact:true}).click();await accessible();await page.getByRole('tab',{name:'Integrity checks'}).focus();await page.keyboard.press('ArrowRight');await expect(page.getByRole('tab',{name:'Normalized evidence'})).toBeFocused();await page.keyboard.press('Escape');await nav(page,'Controls');await page.getByRole('button',{name:/MAP 1.1/}).click();await accessible();await nav(page,'Report');await accessible();
});
test('malicious input shows actionable error and never replaces the previous run',async({page})=>{
  await page.goto('/');await demo(page);await page.getByRole('button',{name:'Import evidence',exact:true}).click();await page.locator('input[aria-label="Choose evidence files"]').setInputFiles({name:'broken.zip',mimeType:'application/zip',buffer:Buffer.from('not an archive')});await expect(page.getByRole('alert')).toContainText('Invalid ZIP');await expect(page.getByRole('dialog')).toHaveCount(0);await expect(page.getByText('Atlas AI Assistant',{exact:true})).toBeVisible();
});
