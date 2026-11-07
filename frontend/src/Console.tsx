import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { short, type Config } from './App';

type FieldRow = { field: string; distinctA: number; distinctB: number; shared: number; verdict: string };
type AttackResult = {
  mode: string;
  entriesA: number;
  entriesB: number;
  titleA: string;
  titleB: string;
  linkedA: number;
  links: { siteA: number; siteB: number; field: string; value: string }[];
  identified: { site: string; index: number; person: string; field: string }[];
  fields: FieldRow[];
};
type StateSummary = {
  issued: number;
  epoch: number;
  escrow: { person: string; ciphertext: string; issuedAt: string }[];
  shadow: { person: string }[];
  revocations: { ground: string; at: string; epoch: number }[];
  requests: { method: string; path: string }[];
  keepShadow: boolean;
};
type ReplayResult = { attempts: { name: string; ok: boolean; reason: string }[] };

async function getJson<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);
  const body = await res.json();
  if (!res.ok) throw new Error(body.error ?? res.statusText);
  return body as T;
}

export function Console({ config }: { config: Config }) {
  const [malicious, setMalicious] = useState(false);
  const [standard, setStandard] = useState<AttackResult | null>(null);
  const [zk, setZk] = useState<AttackResult | null>(null);
  const [state, setState] = useState<StateSummary | null>(null);
  const [stateDown, setStateDown] = useState(false);
  const [replay, setReplay] = useState<ReplayResult | null>(null);
  const [error, setError] = useState('');

  const runAttack = useCallback(async (useShadow: boolean) => {
    const flag = useShadow ? '1' : '0';
    try {
      const [s, z] = await Promise.all([
        getJson<AttackResult>(`/api/attack?mode=standard&malicious=${flag}`),
        getJson<AttackResult>(`/api/attack?mode=zk&malicious=${flag}`),
      ]);
      setStandard(s);
      setZk(z);
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  const refreshState = useCallback(async () => {
    try {
      setState(await getJson<StateSummary>('/api/state'));
      setStateDown(false);
    } catch {
      setStateDown(true);
    }
  }, []);

  useEffect(() => {
    void runAttack(malicious);
  }, [malicious, runAttack]);

  useEffect(() => {
    void refreshState();
    const timer = window.setInterval(refreshState, 3000);
    return () => window.clearInterval(timer);
  }, [refreshState]);

  async function runReplay() {
    try {
      setReplay(await getJson<ReplayResult>('/api/replay', { method: 'POST' }));
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <>
      <section className="panel">
        <div className="panel-head">
          <div>
            <h1>Can the logs be linked?</h1>
            <p className="lede">
              Every value both sites logged, joined exactly. Run it again after you verify on the sites: your own entries
              are in these logs, among the synthetic holders.
            </p>
          </div>
          <div className="row">
            <label className="check toggle">
              <input
                type="checkbox"
                checked={malicious}
                disabled={state !== null && !state.keepShadow}
                onChange={(e) => setMalicious(e.target.checked)}
              />
              State cheats: add everything it secretly kept
            </label>
            <button className="primary" onClick={() => runAttack(malicious)}>Run attack</button>
          </div>
        </div>
        {error && <p className="bad" role="alert">{error}</p>}
        <div className="versus">
          {standard && <AttackCard title="Standard credential" result={standard} malicious={malicious} />}
          {zk && <AttackCard title="ZK proof" result={zk} malicious={malicious} />}
        </div>
      </section>

      <section className="panel">
        <h2>Replay and relay</h2>
        <p>Takes the latest accepted proof from Pinecrest Apps and tries to reuse it.</p>
        <button onClick={runReplay}>Run replay attack</button>
        {replay && (
          <ul className="results">
            {replay.attempts.map((attempt) => (
              <li key={attempt.name}>
                <strong>{attempt.name}:</strong>{' '}
                <span className={attempt.ok ? 'bad' : 'good'}>{attempt.ok ? 'ACCEPTED' : `rejected, ${attempt.reason}`}</span>
              </li>
            ))}
          </ul>
        )}
      </section>

      {stateDown ? (
        <section className="panel" role="status">
          <h2>What the state holds and sees</h2>
          <p className="good"><strong>The state is offline.</strong> Sites can still verify proofs, because they never needed it.</p>
        </section>
      ) : (
        state && <StatePanel state={state} zk={zk} standard={standard} />
      )}
      <FraudPanel config={config} onDone={refreshState} />
      <JudgeChecks />
      <UtahMap />
    </>
  );
}

function AttackCard({ title, result, malicious }: { title: string; result: AttackResult; malicious: boolean }) {
  const [open, setOpen] = useState(false);
  const leaked = result.linkedA > 0 || result.identified.length > 0;
  const named = new Set(result.identified.map((i) => i.person));
  const joinFields = result.fields.filter((f) => f.verdict.startsWith('LINKS')).map((f) => f.field);

  return (
    <article className={`attack ${leaked ? 'leaked' : 'held'}`}>
      <h3>{title}</h3>
      <dl className="scores">
        <div>
          <dt>Linked across sites</dt>
          <dd>{result.linkedA}<small> of {result.entriesA}</small></dd>
        </div>
        <div>
          <dt>People named{malicious ? '' : ' (state not cheating)'}</dt>
          <dd>{malicious ? named.size : '–'}</dd>
        </div>
      </dl>
      {joinFields.length > 0 && (
        <p>
          Joined on: <code>{joinFields.join(', ')}</code>
        </p>
      )}
      {result.identified.length > 0 && (
        <p>
          For example, <strong>{result.identified[0].person}</strong> was identified on {result.identified[0].site} from
          <code> {result.identified[0].field}</code>.
        </p>
      )}
      {!leaked && <p>No logged value joins the two sites{malicious ? ' or matches anything the state kept' : ''}.</p>}
      <button className="ghost" onClick={() => setOpen(!open)} aria-expanded={open}>
        {open ? 'Hide' : 'Show'} every logged field
      </button>
      {open && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">Field</th>
                <th scope="col">Distinct A</th>
                <th scope="col">Distinct B</th>
                <th scope="col">In both</th>
                <th scope="col">Verdict</th>
              </tr>
            </thead>
            <tbody>
              {result.fields.map((row) => (
                <tr key={row.field} className={row.verdict.startsWith('LINKS') ? 'flag' : undefined}>
                  <th scope="row"><code>{row.field}</code></th>
                  <td>{row.distinctA}</td>
                  <td>{row.distinctB}</td>
                  <td>{row.shared}</td>
                  <td>{row.verdict}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </article>
  );
}

function StatePanel({
  state,
  zk,
  standard,
}: {
  state: StateSummary;
  zk: AttackResult | null;
  standard: AttackResult | null;
}) {
  const byPath = new Map<string, number>();
  for (const r of state.requests) byPath.set(r.path, (byPath.get(r.path) ?? 0) + 1);
  const verifications = (zk?.entriesA ?? 0) + (zk?.entriesB ?? 0) + (standard?.entriesA ?? 0) + (standard?.entriesB ?? 0);
  // Issuing and revoking are the only things that should ever reach the state.
  const verifyTraffic = state.requests.filter((r) => r.path !== '/issue' && !r.path.startsWith('/revoke')).length;

  return (
    <section className="panel">
      <h2>What the state holds and sees</h2>
      <dl className="scores">
        <div>
          <dt>Verifications at sites</dt>
          <dd>{verifications}</dd>
        </div>
        <div>
          <dt>Requests those caused at the state</dt>
          <dd className={verifyTraffic === 0 ? 'good' : 'bad'}>{verifyTraffic}</dd>
        </div>
        <div>
          <dt>Credentials issued</dt>
          <dd>{state.issued}</dd>
        </div>
        <div>
          <dt>Revocation list</dt>
          <dd>#{state.epoch}</dd>
        </div>
      </dl>
      <h3>Every request the state has received, by path</h3>
      <ul className="results">
        {[...byPath.entries()].map(([path, count]) => (
          <li key={path}><code>{path}</code>: {count}</li>
        ))}
      </ul>
      {state.revocations.length > 0 && (
        <>
          <h3>Revocations (ground recorded, person not recorded)</h3>
          <ul className="results">
            {state.revocations.map((r) => (
              <li key={`${r.epoch}-${r.at}`}>List #{r.epoch}: {r.ground}</li>
            ))}
          </ul>
        </>
      )}
      <h3>Escrow: all an honest state retains</h3>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Person</th>
              <th scope="col">Revocation token, encrypted to the trustee</th>
            </tr>
          </thead>
          <tbody>
            {state.escrow.slice(-5).reverse().map((rec) => (
              <tr key={rec.ciphertext}>
                <th scope="row">{rec.person}</th>
                <td><code>{short(rec.ciphertext, 18)}</code></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="note">Showing the latest 5 of {state.escrow.length}.</p>
      {state.keepShadow ? (
        <p className="note">
          To give the cheating-state attack real data, this demo state also keeps {state.shadow.length} shadow records of
          hashes and signatures, with no birth dates. A real issuer wouldn't. Run <code>HONEST_STATE=1 make demo</code> to
          turn them off.
        </p>
      ) : (
        <p className="note">Running with <code>HONEST_STATE=1</code>: the state keeps no shadow records.</p>
      )}
    </section>
  );
}

function FraudPanel({ config, onDone }: { config: Config; onDone: () => void }) {
  const [person, setPerson] = useState('Alex Morgan');
  const [order, setOrder] = useState('');
  const [message, setMessage] = useState('');
  const [isError, setIsError] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    try {
      const body = await getJson<{ epoch: number; revoked: number }>(`${config.urls.state}/revoke/fraud`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ person, courtOrder: order, ground: 'fraud' }),
      });
      setIsError(false);
      setMessage(`The trustee decrypted the token and the state published list #${body.epoch}.`);
      onDone();
    } catch (err) {
      setIsError(true);
      setMessage(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <section className="panel">
      <h2>Fraud revocation</h2>
      <p>
        The state can't read its own escrow, so it needs the independent trustee. Leave the court order blank to see the
        trustee refuse.
      </p>
      <form onSubmit={submit} className="form inline">
        <label>
          Person
          <input value={person} onChange={(e) => setPerson(e.target.value)} required />
        </label>
        <label>
          Court order reference
          <input value={order} onChange={(e) => setOrder(e.target.value)} placeholder="e.g. 2026-CV-0142" />
        </label>
        <button>Request revocation</button>
      </form>
      {message && <p className={isError ? 'bad' : 'good'} role="status">{message}</p>}
    </section>
  );
}

const JUDGE_CHECKS: { suspicion: string; test: string; expect: string }[] = [
  {
    suspicion: 'The servers keep what I typed and look it up later.',
    test: 'Issue a credential with a made-up name and birth date, verify, then run make search TEXT="…" for each. Also read the POST body in DevTools.',
    expect: 'Zero matches at the sites, mirror and disk. Your name appears only in the state’s escrow. Your birth date appears nowhere.',
  },
  {
    suspicion: 'Verification only works because your servers remember me.',
    test: 'Run make kill-state and make fresh-site, reload Pinecrest Apps, then verify.',
    expect: 'Accepted, with the state stopped, by a new process with empty memory.',
  },
  {
    suspicion: 'The verifier just says yes.',
    test: 'Run make check-proof. It uses snarkjs, not this project’s Go code, with no network. You can also copy judge-kit/ to your own laptop.',
    expect: 'OK! for the real proof, Invalid proof when one number changes.',
  },
  {
    suspicion: 'The math isn’t really enforcing anything.',
    test: 'In the wallet, use Try to cheat. Claim a false birth date, or issue a credential to a minor and claim the real one.',
    expect: 'The prover fails with a circuit error, and no proof exists.',
  },
  {
    suspicion: 'You ran the setup, so you could forge proofs.',
    test: 'Run make stop, then make contribute, and type your own randomness.',
    expect: 'Setup still verifies and lists your contribution. Forging now needs your secret too.',
  },
  {
    suspicion: 'This laptop isn’t running the code you showed me.',
    test: 'Clone the public repo and run it on your own laptop, so my machine isn’t involved.',
    expect: 'The same results, using keys you generated.',
  },
];

function JudgeChecks() {
  return (
    <section className="panel">
      <h2>Don't trust this laptop</h2>
      <p className="lede">
        Suppose it's a rigged demo that stores what you type. Each test below would expose that, and most use tools from
        outside this project.
      </p>
      <div className="table-wrap">
        <table className="map">
          <thead>
            <tr>
              <th scope="col">If you suspect</th>
              <th scope="col">Run this</th>
              <th scope="col">You should see</th>
            </tr>
          </thead>
          <tbody>
            {JUDGE_CHECKS.map((row) => (
              <tr key={row.suspicion}>
                <td>{row.suspicion}</td>
                <td>{row.test}</td>
                <td>{row.expect}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="note">
        These can't show that a real state deletes what it saw at issuance, or that an untrusted wallet app is honest. The
        first is limited by design: even if it keeps everything, proofs give it nothing to match. The second is why the
        wallet is open source and why Utah's law requires wallet choice.
      </p>
    </section>
  );
}

type Status = 'Shown live' | 'Partly' | 'Not modeled';

const UTAH_MAP: { cite: string; requirement: string; demo: string; status: Status }[] = [
  {
    cite: '301(1)(e)(ii)',
    requirement: 'Show a minimum age without disclosing age or birth date',
    demo: 'The proof answers only yes or no. See “Everything this site received” on either site.',
    status: 'Shown live',
  },
  {
    cite: '301(1)(a)',
    requirement: 'Cross-context correlation protections',
    demo: 'The linking attack above finds no join at the log level. IP addresses and timing still need network-level protection.',
    status: 'Partly',
  },
  {
    cite: '301(3)',
    requirement: 'No mechanism for the department to monitor or track presentations',
    demo: 'Sites have no address for the state, the request count above stays at 0, and the offline verifier runs with no network.',
    status: 'Shown live',
  },
  {
    cite: '301(5)',
    requirement: 'Revoke only for compromise, error or fraud, or holder request',
    demo: 'The API accepts only those grounds and records which one was used. Proofs show non-membership in a public list.',
    status: 'Shown live',
  },
  {
    cite: '301(4)',
    requirement: 'Limits on using, keeping and disclosing applicant data, with disclosure on a warrant or court order',
    demo: 'An honest state keeps only an encrypted token per person. The trustee stand-in only checks that a court order reference exists.',
    status: 'Partly',
  },
  {
    cite: '303(1)(d)',
    requirement: 'Endorsement reflects a point in time, with no continuous monitoring or tracking',
    demo: 'A credential carries its own expiry and the state is not contacted again.',
    status: 'Shown live',
  },
  {
    cite: '301(1)(e)(i)',
    requirement: 'Selectively disclose identity attributes',
    demo: 'Residency is a separate yes or no. Name, image and address are not modeled as disclosures.',
    status: 'Partly',
  },
  {
    cite: '301(1)(d)',
    requirement: 'Support online and offline presentation',
    demo: 'Verification runs with no network, but there is no QR or NFC channel for handing over a proof in person.',
    status: 'Partly',
  },
  {
    cite: '301(1)(a)',
    requirement: 'Compromise detection and recovery',
    demo: 'A printed code revokes a lost credential. Detecting compromise and reissuing are not built.',
    status: 'Partly',
  },
  {
    cite: '301(2)(e)',
    requirement: 'Open standards free of licensing fees and patent restrictions',
    demo: 'Built on published open-source schemes, not reviewed for patents. Utah has not selected standards, and this is not the ISO mdoc format.',
    status: 'Partly',
  },
  {
    cite: '301(1)(f)',
    requirement: 'Holder chooses a conforming wallet',
    demo: 'There is one wallet here, though nothing in the protocol ties a credential to it.',
    status: 'Not modeled',
  },
  {
    cite: '301(2)(c)',
    requirement: 'Issuance and revocation infrastructure in a state-controlled, in-state data center',
    demo: 'Everything runs on this one machine.',
    status: 'Not modeled',
  },
  {
    cite: '301(2)(g)(iii)',
    requirement: 'Digital guardians for minors and incapacitated individuals',
    demo: 'Not built.',
    status: 'Not modeled',
  },
];

const STATUS_CLASS: Record<Status, string> = {
  'Shown live': 'pill pill-good',
  Partly: 'pill pill-part',
  'Not modeled': 'pill pill-none',
};

function UtahMap() {
  return (
    <section className="panel">
      <h2>How this maps to Utah's framework</h2>
      <p className="lede">
        Against Utah Code 63A-20. This models the privacy requirements and does not claim conformance: the state's final
        standards aren't published, and its implementation guide is a draft.
      </p>
      <div className="table-wrap">
        <table className="map">
          <thead>
            <tr>
              <th scope="col">Section</th>
              <th scope="col">Requirement</th>
              <th scope="col">This demo</th>
              <th scope="col">Status</th>
            </tr>
          </thead>
          <tbody>
            {UTAH_MAP.map((row) => (
              <tr key={row.cite + row.requirement}>
                <th scope="row"><code>{row.cite}</code></th>
                <td>{row.requirement}</td>
                <td>{row.demo}</td>
                <td><span className={STATUS_CLASS[row.status]}>{row.status}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
