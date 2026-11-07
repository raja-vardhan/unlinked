// Generates proofs off the main thread. The witness and the private credential
// data exist only inside this worker, on the holder's device.
importScripts('/zk/snarkjs.min.js');

self.onmessage = async (event) => {
  const started = performance.now();
  try {
    const { proof, publicSignals } = await self.snarkjs.groth16.fullProve(
      event.data.input,
      '/zk/presentation.wasm',
      '/zk/presentation_final.zkey',
    );
    self.postMessage({ ok: true, proof, publicSignals, ms: Math.round(performance.now() - started) });
  } catch (err) {
    self.postMessage({ ok: false, error: String(err && err.message ? err.message : err) });
  }
};
