import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import type { Config } from './App';
import {
  buildInput,
  checkIssuer,
  checkQuestion,
  holderCommit,
  randomField,
  standardPresentation,
  type Credential,
  type IssuerKey,
  type ProofRequest,
  type Snapshot,
} from './lib/core';

const STORAGE_KEY = 'unlinked.credential';

function loadCredential(): Credential | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as Credential) : null;
  } catch {
    return null;
  }
}

function saveCredential(cred: Credential | null) {
  try {
    if (cred) localStorage.setItem(STORAGE_KEY, JSON.stringify(cred));
    else localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Storage can be blocked; the credential then lasts only for this page.
  }
}

function formatDate(d: number): string {
  const s = String(d);
  return `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}`;
}

function prove(input: Record<string, string | string[]>) {
  return new Promise<{ proof: unknown; publicSignals: string[]; ms: number }>((resolve, reject) => {
    const worker = new Worker('/zk/prover.worker.js');
    worker.onmessage = (event) => {
      worker.terminate();
      if (event.data.ok) resolve(event.data);
      else reject(new Error(event.data.error));
    };
    worker.onerror = (event) => {
      worker.terminate();
      reject(new Error(event.message || 'The prover failed to start'));
    };
    worker.postMessage({ input });
  });
}

export function Wallet({ config, isPopup }: { config: Config; isPopup: boolean }) {
  const [cred, setCred] = useState<Credential | null>(loadCredential);

  const update = useCallback((next: Credential | null) => {
    saveCredential(next);
    setCred(next);
  }, []);

  if (isPopup) return <Consent config={config} cred={cred} />;
  return cred ? (
    <Holding config={config} cred={cred} onErase={() => update(null)} />
  ) : (
    <Issue config={config} onIssued={update} />
  );
}

function Issue({ config, onIssued }: { config: Config; onIssued: (c: Credential) => void }) {
  const [name, setName] = useState('Alex Morgan');
  const [dob, setDob] = useState('1994-03-12');
  const [isUtah, setIsUtah] = useState(true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const holderSecret = randomField().toString();
      const res = await fetch(`${config.urls.state}/issue`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name,
          dob: Number(dob.replaceAll('-', '')),
          isUtah,
          holderCommit: holderCommit(holderSecret),
        }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? 'Issuance failed');
      onIssued({ ...body, name, holderSecret });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card">
      <h1>Get a credential</h1>
      <p className="lede">
        This stands in for identity proofing. The state sees these details once, signs a credential, then erases
        everything except your name beside an encrypted token it can't open.
      </p>
      <form onSubmit={submit} className="form">
        <label>
          Legal name
          <input value={name} onChange={(e) => setName(e.target.value)} required />
        </label>
        <label>
          Birth date
          <input type="date" value={dob} onChange={(e) => setDob(e.target.value)} required />
        </label>
        <label className="check">
          <input type="checkbox" checked={isUtah} onChange={(e) => setIsUtah(e.target.checked)} />
          Utah resident
        </label>
        <button className="primary" disabled={busy}>
          {busy ? 'Requesting…' : 'Request credential'}
        </button>
        {error && <p className="bad" role="alert">{error}</p>}
      </form>
    </section>
  );
}

function Holding({ config, cred, onErase }: { config: Config; cred: Credential; onErase: () => void }) {
  const [status, setStatus] = useState('');
  const [isError, setIsError] = useState(false);

  async function revoke(ground: 'compromise' | 'holder-request') {
    try {
      const res = await fetch(`${config.urls.state}/revoke/code`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: cred.revToken, ground }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error);
      setIsError(false);
      setStatus(`Revoked. The state published revocation list #${body.epoch} without learning who you are from it.`);
    } catch (err) {
      setIsError(true);
      setStatus(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <>
      <section className="card">
        <h1>Your credential</h1>
        <p className="lede">The state saw these details once and doesn't keep them, apart from your name beside an encrypted token. Sites get proofs about them, never the details.</p>
        <dl className="facts">
          <dt>Name</dt>
          <dd>{cred.name}</dd>
          <dt>Birth date</dt>
          <dd>{formatDate(cred.dob)}</dd>
          <dt>Utah resident</dt>
          <dd>{cred.isUtah ? 'Yes' : 'No'}</dd>
          <dt>Expires</dt>
          <dd>{formatDate(cred.expiry)}</dd>
        </dl>
      </section>

      <section className="card">
        <h2>Use it</h2>
        <p>Open a site and ask it to verify you. Each one gets an answer it can't match against the other.</p>
        <div className="row">
          <a className="button" href={config.urls['site-a']}>Pinecrest Apps (18+)</a>
          <a className="button" href={config.urls['site-b']}>Red Rock Cellar (21+, Utah)</a>
        </div>
      </section>

      <section className="card">
        <h2>Revocation code</h2>
        <p>
          Keep a printed copy. It revokes this credential even if you lose your phone, so revoking doesn't depend on the
          state knowing which credential is yours.
        </p>
        <code className="code-block">{cred.revToken}</code>
        <div className="row">
          <button onClick={() => window.print()}>Print</button>
          <button onClick={() => revoke('compromise')}>Report compromised</button>
          <button onClick={() => revoke('holder-request')}>Revoke at my request</button>
          <button className="ghost" onClick={onErase}>Erase from this device</button>
        </div>
        {status && <p className={isError ? 'bad' : 'good'} role="status">{status}</p>}
      </section>
    </>
  );
}

type Incoming = { request: ProofRequest; mode: 'zk' | 'standard'; origin: string; source: Window };

function Consent({ config, cred }: { config: Config; cred: Credential | null }) {
  const [incoming, setIncoming] = useState<Incoming | null>(null);
  const [refusal, setRefusal] = useState('');
  const [problem, setProblem] = useState('');
  const [progress, setProgress] = useState('');
  const [finished, setFinished] = useState('');
  const announced = useRef(false);

  useEffect(() => {
    function onMessage(event: MessageEvent) {
      if (event.data?.type !== 'proof-request' || !event.source) return;
      const source = event.source as Window;
      // event.origin comes from the browser, so a site can't claim to be another site.
      const next: Incoming = { request: event.data.request, mode: event.data.mode, origin: event.origin, source };
      const refused = checkQuestion(next.request);
      setIncoming(next);
      if (refused) {
        setRefusal(refused);
        source.postMessage({ type: 'refused', reason: refused }, event.origin);
      }
    }
    window.addEventListener('message', onMessage);
    if (!announced.current && window.opener) {
      announced.current = true;
      window.opener.postMessage({ type: 'wallet-ready' }, '*');
    }
    return () => window.removeEventListener('message', onMessage);
  }, []);

  function reply(message: unknown) {
    incoming?.source.postMessage(message, incoming.origin);
  }

  function decline() {
    reply({ type: 'declined' });
    window.close();
  }

  async function share() {
    if (!incoming || !cred) return;
    setProblem('');
    try {
      if (incoming.mode === 'standard') {
        reply({ type: 'presentation', presentation: standardPresentation(cred, incoming.request) });
        window.close();
        return;
      }
      setProgress('Downloading the public issuer key and revocation list…');
      const [issuerRes, listRes] = await Promise.all([
        fetch(`${config.urls.mirror}/issuer.json`, { cache: 'no-store' }),
        fetch(`${config.urls.mirror}/revocation.json`, { cache: 'no-store' }),
      ]);
      const issuerProblem = checkIssuer(cred, (await issuerRes.json()) as IssuerKey);
      if (issuerProblem) {
        setProgress('');
        setProblem(issuerProblem);
        return;
      }
      const snapshot = (await listRes.json()) as Snapshot;

      setProgress('Checking this device’s copy of the list…');
      const built = await buildInput(cred, incoming.request, incoming.origin, snapshot);
      if (built.problem || !built.input) {
        setProgress('');
        setProblem(built.problem ?? 'Could not prepare a proof.');
        return;
      }

      setProgress('Generating the proof on this device…');
      const { proof, publicSignals, ms } = await prove(built.input);
      // The proving time stays here: it would hint at the device if sent to the site.
      reply({ type: 'presentation', presentation: { proof, publicSignals } });
      setProgress('');
      setFinished(`Proof generated on this device in ${(ms / 1000).toFixed(1)} seconds and sent.`);
      window.setTimeout(() => window.close(), 1500);
    } catch (err) {
      setProgress('');
      setProblem(err instanceof Error ? err.message : String(err));
    }
  }

  if (!incoming) {
    return (
      <section className="card">
        <h1>Waiting for the site</h1>
        <p>Open this window using a site's verify button.</p>
      </section>
    );
  }

  const { request, origin, mode } = incoming;

  if (refusal) {
    return (
      <section className="card">
        <h1 className="bad">Request refused</h1>
        <p><strong>{origin}</strong> asked a question this wallet won't answer.</p>
        <p>{refusal}</p>
        <button className="primary" onClick={() => window.close()}>Close</button>
      </section>
    );
  }

  if (!cred) {
    return (
      <section className="card">
        <h1>No credential yet</h1>
        <p>Get a credential in the wallet first.</p>
        <button onClick={decline}>Tell the site “declined”</button>
      </section>
    );
  }

  const question = `Are you ${request.minAge} or older${request.requireUtah ? ' and a Utah resident' : ''}?`;

  if (finished) {
    return (
      <section className="card result-good" role="status">
        <h1>Sent</h1>
        <p>{finished}</p>
      </section>
    );
  }

  return (
    <section className="card">
      <p className="eyebrow">{origin} asks</p>
      <h1>{question}</h1>

      {mode === 'zk' ? (
        <>
          <h2>What it will receive</h2>
          <ul className="ticks">
            <li>A proof that the answer is yes</li>
            <li>Values every other holder shares today, plus this site's ID and this request's nonce</li>
            {request.wantPseudonym && (
              <li>
                <strong>An anonymous account ID for this site only.</strong> It lets this site recognize you when you
                return. Every other site gets a different one.
              </li>
            )}
          </ul>
          <h2>What it will not receive</h2>
          <ul className="crosses">
            <li>Your name, birth date or address</li>
            <li>The state's signature, or anything that matches other sites</li>
          </ul>
        </>
      ) : (
        <div className="warning">
          <h2>Comparison mode: standard credential</h2>
          <p>
            Claims stay hidden, but this sends the state's signature unchanged. It's identical at every site, so it works
            like a tracking cookie.
          </p>
        </div>
      )}

      {progress && <p className="progress" role="status">{progress}</p>}
      {problem && (
        <div className="warning" role="alert">
          <p>{problem}</p>
          <p>The site will only be told “declined”, not why.</p>
        </div>
      )}
      <div className="row">
        {!problem && (
          <button className="primary" onClick={share} disabled={Boolean(progress)}>
            {mode === 'zk' ? 'Send proof' : 'Send credential'}
          </button>
        )}
        <button onClick={decline} disabled={Boolean(progress)}>Decline</button>
      </div>
    </section>
  );
}
