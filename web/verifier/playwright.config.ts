import {defineConfig} from '@playwright/test';
export default defineConfig({testDir:'./tests',timeout:30000,fullyParallel:false,use:{baseURL:'http://127.0.0.1:4173',headless:true,viewport:{width:1440,height:1080},launchOptions:{executablePath:process.env.AEGIS_CHROMIUM_PATH}},webServer:{command:'npm run preview',url:'http://127.0.0.1:4173',reuseExistingServer:!process.env.CI},reporter:'list'});
