import { createRoot } from 'react-dom/client';
import { App, type Config } from './App';
import './styles.css';

const root = createRoot(document.getElementById('root')!);

fetch('/config.json')
  .then((res) => res.json() as Promise<Config>)
  .then((config) => root.render(<App config={config} />))
  .catch((err) => root.render(<p style={{ padding: 16 }}>Could not load this role's configuration: {String(err)}</p>));
