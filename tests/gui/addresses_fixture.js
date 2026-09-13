// Synthetic UI responses only. Cryptographic derivation is tested in Rust.
let finishDerivation;
window.__TAURI__ = {
  event: { listen: async () => () => {} },
  core: { invoke: async (command, args) => {
    if (command === 'tos_status') return { accepted: true };
    if (command === 'default_data_dir') return '/tmp/argos-addresses-fixture';
    if (command === 'list_incomplete_sessions') return [];
    if (command === 'donation_config') return { enabled: false };
    if (command !== 'show_addresses') return null;
    if (document.getElementById('fixture-delay').checked) await new Promise(resolve => { finishDerivation = resolve; });
    if (args.input.seed.split(' ').length !== 24) throw new Error('Expected a valid seed phrase');
    return Array.from({length: args.input.count}, (_, offset) => {
      const index = args.input.start_index + offset;
      return {index, transparent_receive_address: `t1fixture-receive-${index}`, transparent_receive_path: `m / 44' / 133' / 0' / 0 / ${index}`,
        transparent_change_address: `t1fixture-change-${index}`, transparent_change_path: `m / 44' / 133' / 0' / 1 / ${index}`,
        sapling_address: `zsfixture-${index}`, sapling_path: `m_Sapling / 32' / 133' / ${index}'`,
        unified_address: `u1fixture-${index}`, orchard_path: `m_Orchard / 32' / 133' / ${index}'`};
    });
  }}
};
document.addEventListener('DOMContentLoaded', () => {
  const label = document.createElement('label');
  label.textContent = 'Delay synthetic response';
  const check = document.createElement('input'); check.type = 'checkbox'; check.id = 'fixture-delay'; label.append(check);
  const button = document.createElement('button'); button.textContent = 'Finish synthetic response'; button.onclick = () => { finishDerivation?.(); finishDerivation = null; };
  document.getElementById('addresses-dialog').append(label, button);
});
