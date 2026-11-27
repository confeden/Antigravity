/* AI Unlocker paid IDE proxy */
import { app as aiuApp, session as aiuSession } from 'electron';
import { existsSync as aiuExists, readFileSync as aiuRead, watchFile as aiuWatch, unwatchFile as aiuUnwatch } from 'node:fs';
import { join as aiuJoin } from 'node:path';

{
    const local = process.env.LOCALAPPDATA;
    const directory = local && aiuJoin(local, 'AGUnlocker');
    const marker = directory && aiuJoin(directory, 'paid-ide-enabled');
    if (marker && aiuExists(marker)) {
        let port = 53130;
        const portFile = aiuJoin(directory, 'paid_proxy_port');
        try {
            const saved = Number(aiuRead(portFile, 'utf8').trim());
            if (Number.isInteger(saved) && saved >= 1 && saved <= 65535) port = saved;
        } catch (error) {
            if (error.code !== 'ENOENT') console.error('AI Unlocker: could not read the proxy port', error);
        }
        const proxy = 'http://127.0.0.1:' + port;
        const environment = {
            HTTP_PROXY: proxy, HTTPS_PROXY: proxy, ALL_PROXY: proxy, AG_LS_PROXY: proxy,
            NO_PROXY: 'localhost,127.0.0.1,::1', NODE_USE_ENV_PROXY: '1',
        };
        const previous = Object.entries(environment).map(([key, value]) => {
            const before = process.env[key];
            process.env[key] = value;
            return [key, before, value];
        });
        const switches = ['proxy-server', 'proxy-bypass-list', 'no-proxy-server', 'proxy-pac-url', 'proxy-auto-detect', 'disable-quic'];
        const original = new Map(switches.filter(key => aiuApp.commandLine.hasSwitch(key))
            .map(key => [key, aiuApp.commandLine.getSwitchValue(key)]));
        for (const key of switches) aiuApp.commandLine.removeSwitch(key);
        aiuApp.commandLine.appendSwitch('proxy-server', proxy);
        aiuApp.commandLine.appendSwitch('disable-quic');
        const paid = { mode: 'fixed_servers', proxyRules: proxy, proxyBypassRules: '<local>' };
        const restoreProxy = new Map();
        const protect = (owner, closeConnections) => {
            if (!aiuExists(marker) || restoreProxy.has(owner) || typeof owner.setProxy !== 'function') return;
            const setProxy = owner.setProxy;
            let previousConfiguration;
            const setPaidProxy = configuration => {
                previousConfiguration = configuration;
                return setProxy.call(owner, paid);
            };
            owner.setProxy = setPaidProxy;
            restoreProxy.set(owner, async fallback => {
                if (owner.setProxy === setPaidProxy) owner.setProxy = setProxy;
                const previous = previousConfiguration?.proxyRules === proxy ? undefined : previousConfiguration;
                await setProxy.call(owner, previous || fallback);
                if (closeConnections) await owner.closeAllConnections();
            });
        };
        const created = entry => protect(entry, true);
        protect(aiuApp, false);
        aiuApp.on('session-created', created);
        aiuApp.whenReady().then(() => created(aiuSession.defaultSession))
            .catch(error => console.error('AI Unlocker: could not configure the default session', error));

        const restore = () => {
            if (aiuExists(marker)) return;
            aiuUnwatch(marker, restore);
            aiuApp.removeListener('session-created', created);
            for (const [key, before, value] of previous) {
                if (process.env[key] !== value) continue;
                if (before === undefined) delete process.env[key];
                else process.env[key] = before;
            }
            for (const key of switches) {
                aiuApp.commandLine.removeSwitch(key);
                if (original.has(key)) aiuApp.commandLine.appendSwitch(key, original.get(key));
            }
            const config = original.has('no-proxy-server') ? { mode: 'direct' }
                : original.has('proxy-pac-url') ? { mode: 'pac_script', pacScript: original.get('proxy-pac-url') }
                : original.has('proxy-server') ? {
                    mode: 'fixed_servers', proxyRules: original.get('proxy-server'),
                    proxyBypassRules: original.get('proxy-bypass-list') || '',
                } : { mode: original.has('proxy-auto-detect') ? 'auto_detect' : 'system' };
            aiuApp.whenReady().then(async () => {
                await Promise.all([...restoreProxy.values()].map(reset => reset(config)));
            }).catch(error => console.error('AI Unlocker: could not restore IDE proxy settings', error));
        };
        aiuWatch(marker, { persistent: false, interval: 500 }, restore);
    }
}
/* End AI Unlocker paid IDE proxy */
