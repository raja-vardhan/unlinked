import { useEffect } from 'react';
import { Wallet } from './Wallet';
import { Site } from './Site';
import { Console } from './Console';

export type Config = {
  role: 'wallet' | 'site-a' | 'site-b' | 'console';
  origin: string;
  urls: Record<string, string>;
  site?: { title: string; minAge: number; requireUtah: boolean };
};

const ROLE_LABEL: Record<Config['role'], string> = {
  wallet: 'Your wallet',
  'site-a': 'Sample website',
  'site-b': 'Sample website',
  console: 'Attacker console',
};

export function App({ config }: { config: Config }) {
  const isPopup = new URLSearchParams(window.location.search).has('present');

  useEffect(() => {
    document.documentElement.dataset.role = config.role;
    document.title = config.site?.title ?? ROLE_LABEL[config.role];
  }, [config]);

  const links = [
    ['wallet', 'Wallet'],
    ['site-a', 'Pinecrest Apps'],
    ['site-b', 'Red Rock Cellar'],
    ['console', 'Attacker console'],
  ] as const;

  return (
    <>
      <header className="topbar">
        <div className="topbar-inner">
          <div className="brand">
            <strong>{config.site?.title ?? ROLE_LABEL[config.role]}</strong>
            <span className="origin">{config.origin}</span>
          </div>
          {!isPopup && (
            <nav aria-label="Demo roles">
              {links.map(([role, label]) => (
                <a key={role} href={config.urls[role]} aria-current={role === config.role ? 'page' : undefined}>
                  {label}
                </a>
              ))}
            </nav>
          )}
        </div>
      </header>
      <main className={isPopup ? 'page narrow' : 'page'}>
        {config.role === 'wallet' && <Wallet config={config} isPopup={isPopup} />}
        {(config.role === 'site-a' || config.role === 'site-b') && <Site config={config} />}
        {config.role === 'console' && <Console config={config} />}
      </main>
      <footer className="footnote">
        Unlinked is a hackathon model of Utah Code 63A-20. Identity checks are simulated and it is not affiliated with
        the State of Utah. Site names are fictional.
      </footer>
    </>
  );
}

export function short(value: string, keep = 10): string {
  return value.length > keep * 2 + 1 ? `${value.slice(0, keep)}…${value.slice(-keep)}` : value;
}
