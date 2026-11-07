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
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
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
              <input type="checkbox" checked={malicious} onChange={(e) => setMalicious(e.target.checked)} />
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

      {state && <StatePanel state={state} zk={zk} standard={standard} />}
      <FraudPanel config={config} onDone={refreshState} />
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
