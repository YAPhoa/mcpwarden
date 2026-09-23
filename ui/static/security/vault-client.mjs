// The owner UI will explicitly call these methods after its interactive flow.
// This module performs no HTTP requests, persistence, or automatic key release.
export class VaultClient {
  #worker = null; #pending = null; #next = 0;
  lock() {
    this.#worker?.terminate(); this.#worker = null;
    if (this.#pending) { clearTimeout(this.#pending.timer); this.#pending.reject(new Error('Vault locked')); this.#pending = null; }
  }
  #call(operation, input) {
    if (this.#pending) return Promise.reject(new Error('Vault operation already pending'));
    if (!this.#worker) {
      this.#worker = new Worker(new URL('./vault-worker.mjs', import.meta.url), {type:'module'});
      this.#worker.onerror = event => { event.preventDefault(); this.lock(); };
      this.#worker.onmessageerror = () => this.lock();
      this.#worker.onmessage = ({data}) => {
        const p = this.#pending;
        if (!p || data?.id !== p.id) return;
        clearTimeout(p.timer); this.#pending = null;
        if (data.error) p.reject(new Error('Vault operation failed')); else p.resolve(data.result);
      };
    }
    return new Promise((resolve, reject) => {
      const id = ++this.#next, timer = setTimeout(() => this.lock(), 65000);
      this.#pending = {id,resolve,reject,timer};
      try { this.#worker.postMessage({id,operation,input}); } catch { this.lock(); }
    });
  }
  setup(input) { return this.#call('setup', input); }
  unlockPassphrase(input) { return this.#call('unlockPassphrase', input); }
  unlockRecovery(input) { return this.#call('unlockRecovery', input); }
  createCredential(input) { return this.#call('createCredential', input); }
  releaseCredential(input) { return this.#call('releaseCredential', input); }
  changePassphrase(input) { return this.#call('changePassphrase', input); }
}
