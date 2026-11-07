import { useCallback, useEffect, useState } from 'react';
import { short, type Config } from './App';

type Account = { id: string; visits: number };

type Outcome =
  | { kind: 'accepted'; mode: string; received: Record<string, string>; account: Account | null }
  | { kind: 'rejected'; reason: string; mode: string; received: Record<string, string> }
  | { kind: 'declined' }
  | { kind: 'refused'; reason: string }
  | { kind: 'error'; reason: string };

const LABELS: Record<string, string> = {
  pseudonym: 'Anonymous account ID (0 = none)',
  wantPseudonym: 'Account requested (1 = yes)',
  issuerAx: 'Issuer key (x), same for everyone',
  issuerAy: 'Issuer key (y), same for everyone',
  cutoffDate: 'Question: born on or before',
  today: 'Date of the check',
  requireUtah: 'Residency asked (1 = yes)',
  revRoot: 'Revocation list root, same for everyone',
  scope: 'This site’s ID',
  nonce: 'This request’s single-use nonce',
};

const ORDER = ['cutoffDate', 'requireUtah', 'pseudonym', 'wantPseudonym', 'today', 'scope', 'nonce', 'revRoot', 'issuerAx', 'issuerAy'];

// A cutoff no real age policy would use, as the first step of a binary search.
const PROBE_CUTOFF = 19750101;

export function Site({ config }: { config: Config }) {
  const site = config.site!;
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [busy, setBusy] = useState(false);
  const [counts, setCounts] = useState({ zk: 0, standard: 0 });

  const refreshCounts = useCallback(async () => {
    const res = await fetch('/api/log');
    const { entries } = (await res.json()) as { entries: { mode: string; result: string }[] };
    const accepted = entries.filter((e) => e.result === 'accepted');
    setCounts({
      zk: accepted.filter((e) => e.mode === 'zk').length,
      standard: accepted.filter((e) => e.mode === 'standard').length,
    });
  }, []);

  useEffect(() => {
    refreshCounts().catch(() => undefined);
  }, [refreshCounts]);

  async function ask(mode: 'zk' | 'standard', options: { probe?: boolean; account?: boolean } = {}) {
    const { probe = false, account = false } = options;
    setBusy(true);
    setOutcome(null);
    const walletUrl = config.urls.wallet;
    const finish = (next: Outcome) => {
      setOutcome(next);
      setBusy(false);
    };

    // The window must open during the click, or browsers block it.
    const popup = window.open(`${walletUrl}/?present=1`, 'unlinked-wallet', 'width=500,height=800');
    if (!popup) {
      finish({ kind: 'error', reason: 'Your browser blocked the wallet window. Allow pop-ups for this site.' });
      return;
    }

    // Listen before the wallet can announce itself, and let the request catch up.
    const requestReady: Promise<{ nonce: string; cutoffDate: number }> = fetch(
      account ? '/api/request?account=1' : '/api/request',
    ).then((res) => res.json());

    let answered = false;
    const stop = () => {
      window.removeEventListener('message', onMessage);
      window.clearInterval(watcher);
    };

    async function onMessage(event: MessageEvent) {
      if (event.origin !== walletUrl) return;
      const message = event.data;
      if (message?.type === 'wallet-ready') {
        try {
          const request = await requestReady;
          const outgoing = probe ? { ...request, cutoffDate: PROBE_CUTOFF } : request;
          popup!.postMessage({ type: 'proof-request', mode, request: outgoing }, walletUrl);
        } catch (err) {
          answered = true;
          stop();
          popup!.close();
          finish({ kind: 'error', reason: String(err) });
        }
        return;
      }
      if (!['declined', 'refused', 'presentation'].includes(message?.type)) return;
      answered = true;
      stop();
      if (message.type === 'declined') return finish({ kind: 'declined' });
      if (message.type === 'refused') return finish({ kind: 'refused', reason: message.reason });
      try {
        const request = await requestReady;
        const res = await fetch('/api/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode, nonce: request.nonce, presentation: message.presentation }),
        });
        const body = await res.json();
        finish(
          body.ok
            ? { kind: 'accepted', mode, received: body.received, account: body.account ?? null }
            : { kind: 'rejected', mode, reason: body.reason, received: body.received ?? {} },
        );
        await refreshCounts();
      } catch (err) {
        finish({ kind: 'error', reason: String(err) });
      }
    }

    // Covers the holder closing the wallet window without answering.
    const watcher = window.setInterval(() => {
      if (popup.closed && !answered) {
        stop();
        setBusy(false);
      }
    }, 500);
    window.addEventListener('message', onMessage);
  }

  const requirement = `${site.minAge} or older${site.requireUtah ? ', Utah residents only' : ''}`;

  return (
    <>
      <section className="card hero">
        <p className="eyebrow">Age-restricted</p>
        <h1>{site.title}</h1>
        <p className="lede">Before you continue, this site needs to know you are {requirement}.</p>
        <div className="row">
          <button className="primary" onClick={() => ask('zk')} disabled={busy}>Verify with a ZK proof</button>
          <button onClick={() => ask('zk', { account: true })} disabled={busy}>Open an anonymous account</button>
          <button onClick={() => ask('standard')} disabled={busy}>Compare: standard credential</button>
          <button className="ghost" onClick={() => ask('zk', { probe: true })} disabled={busy}>Attack: probe for a birth date</button>
        </div>
        {busy && <p className="progress" role="status">Waiting for your wallet…</p>}
      </section>

      {outcome && <Result outcome={outcome} />}

      <section className="card">
        <h2>This site's log</h2>
        <p>
          {counts.zk} ZK {counts.zk === 1 ? 'proof' : 'proofs'} and {counts.standard} standard{' '}
          {counts.standard === 1 ? 'credential' : 'credentials'} accepted. The attacker console pools this log with the
          other site's.
        </p>
      </section>
    </>
  );
}

function AccountPanel({ account }: { account: Account }) {
  const [banned, setBanned] = useState(false);

  async function ban() {
    const res = await fetch('/api/account/ban', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: account.id }),
    });
    if (res.ok) setBanned(true);
  }

  return (
    <div className="account">
      <h3>Anonymous account</h3>
      <p>
        <code>{short(account.id)}</code>, visit {account.visits}. This site can recognize this holder and moderate them,
        but can't learn who they are or match them at another site.
      </p>
      {banned ? (
        <p className="bad" role="status">Banned. Opening this account again will be rejected, with no identity involved.</p>
      ) : (
        <button onClick={ban}>Ban this account</button>
      )}
    </div>
  );
}

function Result({ outcome }: { outcome: Outcome }) {
  if (outcome.kind === 'declined') {
    return (
      <section className="card" role="status">
        <h2>Declined</h2>
        <p>The wallet said no. This site isn't told why, so it can't tell an underage visitor from a cautious one.</p>
      </section>
    );
  }
  if (outcome.kind === 'refused') {
    return (
      <section className="card result-good" role="status">
        <h2>The wallet refused to answer</h2>
        <p>{outcome.reason}</p>
      </section>
    );
  }
  if (outcome.kind === 'error') {
    return (
      <section className="card result-bad" role="alert">
        <h2>Something went wrong</h2>
        <p>{outcome.reason}</p>
      </section>
    );
  }
  if (outcome.kind === 'rejected') {
    return (
      <section className="card result-bad" role="alert">
        <h2>Rejected</h2>
        <p>{outcome.reason}</p>
      </section>
    );
  }

  const isZk = outcome.mode === 'zk';
  const entries = Object.entries(outcome.received);
  const publicRows = ORDER.filter((key) => outcome.received[key] !== undefined);
  const proofPoints = entries.filter(([key]) => key.startsWith('proof.')).length;

  return (
    <section className={`card ${isZk ? 'result-good' : 'result-bad'}`} role="status">
      <h2>{isZk ? 'Verified. The site learned only “yes”.' : 'Verified, but the site now holds a tracking value.'}</h2>
      {isZk && <p>This site checked the proof itself, without contacting the state.</p>}
      {outcome.account && <AccountPanel account={outcome.account} />}
      {!isZk && (
        <p>
          The signature below is the same at every site this holder visits, and the state knows whose it is. Run the
          attacker console to see the result.
        </p>
      )}
      <h3>Everything this site received</h3>
      <div className="table-wrap">
        <table>
          <tbody>
            {isZk ? (
              <>
                {publicRows.map((key) => (
                  <tr key={key}>
                    <th scope="row">{LABELS[key] ?? key}</th>
                    <td><code>{short(outcome.received[key])}</code></td>
                  </tr>
                ))}
                <tr>
                  <th scope="row">Opaque proof</th>
                  <td>{proofPoints} coordinates of random-looking curve points, different every time</td>
                </tr>
              </>
            ) : (
              entries.sort().map(([key, value]) => (
                <tr key={key} className={key.startsWith('signature') ? 'flag' : undefined}>
                  <th scope="row">{key}</th>
                  <td><code>{short(value)}</code></td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
