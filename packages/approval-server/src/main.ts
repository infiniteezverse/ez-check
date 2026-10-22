import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { Store } from './store.js';

const config = loadConfig();
const store = new Store(config.dataDir);

createApp(config, store).listen(config.port, config.host, () => {
  console.log(`EZ CHECK approval server on ${config.origin}`);
  if (!store.hasCredentials()) console.log(`No passkey yet: register one at ${config.origin}/register`);
  if (config.generatedToken) {
    console.log(`Generated agent token for this run (set EZCHECK_AGENT_TOKEN to keep one):\n  ${config.agentToken}`);
  }
});
