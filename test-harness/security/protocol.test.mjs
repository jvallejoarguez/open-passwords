// Offline lifecycle regressions for the unmodified src/protocol.js. A fake native port runs the real
// SRP + AES-GCM exchange with dummy PINs and credentials. No browser, vault, helper or network.
import assert from 'node:assert/strict';
import test from 'node:test';
import { FakeHelper, installClock, tick, until, within, gateSubtle, pair } from './fake-native.mjs';
import { ApplePasswords } from '../../src/protocol.js';

function setup(t) {
  const clock = installClock(t);
  const helper = new FakeHelper();
  const client = new ApplePasswords();
  return { clock, helper, client };
}
const site = (host) => `https://${host}/login`;
const names = (logins) => logins.map((l) => l.username);

test('a delayed Messages code cannot become another site\'s code list', async (t) => {
  const { clock, helper, client } = setup(t);
  await pair(client, helper);
  helper.answer = (cmd, plain) => ({ STATUS: 0, Entries: [{ source: 'messages',
    domain: new URL(plain.frameURLs[0]).hostname,
    code: plain.frameURLs[0].includes('first.example') ? '111111' : '222222' }] });
  helper.hold.add(16);
  const first = client.getOneTimeCodes(1, 0, [site('first.example')]);
  await until(() => helper.held.length === 1, 'code query to reach the helper');
  clock.advance(8000);
  await within(assert.rejects(first, /timeout/));
  await within(assert.rejects(client.getOneTimeCodes(2, 0, [site('second.example')]), /earlier request/));
  assert.equal(helper.sent(16).length, 1);
  helper.hold.clear();
  helper.held[0].release();
  await tick();
  const result = await within(client.getOneTimeCodes(2, 0, [site('second.example')]));
  assert.deepEqual(result.entries.map(({ domain, code }) => ({ domain, code })),
    [{ domain: 'second.example', code: '222222' }]);
});

test('a deferred save withdrawn while queued is not sent after the earlier lookup completes', async (t) => {
  const { helper, client } = setup(t);
  await pair(client, helper);
  helper.hold.add(4);
  const lookup = client.getLoginNamesForURL(1, site('site.example'));
  await until(() => helper.held.length === 1, 'lookup to block the queue');
  let valid = true;
  const save = client.saveLogin(1, site('site.example'), 'dummy', 'DUMMY-EXPIRED', { shouldSend: () => valid });
  valid = false;
  helper.hold.clear();
  helper.held[0].release();
  await within(lookup);
  assert.equal(await within(save), false);
  assert.equal(helper.sent(6).length, 0);
});

test('a timed-out reply is dropped, never handed to the next request for another site', async (t) => {
  const { clock, helper, client } = setup(t);
  await pair(client, helper);
  helper.hold.add(4);
  const first = client.getLoginNamesForURL(1, site('first.example'));
  await until(() => helper.held.length === 1, 'first lookup to reach the helper');
  clock.advance(5000);
  await within(assert.rejects(first, /timeout/));

  // while the late reply can still arrive, the same command is refused before anything is sent
  await within(assert.rejects(client.getLoginNamesForURL(2, site('second.example')), /earlier request/));
  assert.equal(helper.sent(4).length, 1);

  // the late first.example reply drains the marker and goes nowhere
  helper.hold.clear();
  helper.held[0].release();
  await tick();
  assert.deepEqual(names(await within(client.getLoginNamesForURL(2, site('second.example')))), ['dummy@second.example']);
  // a routine slow reply does not cost the pairing
  assert.equal(client.state, 'unlocked');
  assert.equal(helper.ports.length, 1);
});

test('a reply that never comes forces a fresh pairing instead of reusing the command', async (t) => {
  const { clock, helper, client } = setup(t);
  await pair(client, helper);
  helper.hold.add(4);
  const first = client.getLoginNamesForURL(1, site('first.example'));
  await until(() => helper.held.length === 1, 'first lookup to reach the helper');
  clock.advance(5000);
  await within(assert.rejects(first, /timeout/));
  clock.advance(30_000);

  await within(assert.rejects(client.getLoginNamesForURL(2, site('second.example')), /stopped responding/));
  assert.equal(helper.sent(4).length, 1);
  assert.equal(client.state, 'disconnected');
  assert.equal(helper.ports[0].closed, true);

  helper.held[0].release();
  await tick();
  assert.equal(client.state, 'disconnected');

  helper.hold.clear();
  await within(pair(client, helper), 're-pairing');
  assert.deepEqual(names(await client.getLoginNamesForURL(2, site('second.example'))), ['dummy@second.example']);
});

test('Lock settles a pending no-timeout read and the work queued behind it', async (t) => {
  const { helper, client } = setup(t);
  await pair(client, helper);
  helper.hold.add(5);
  const read = client.getPasswordForLoginName(1, site('site.example'), { username: 'dummy' });
  const queued = client.getLoginNamesForURL(1, site('site.example'));
  await until(() => helper.held.length === 1, 'password read to reach the helper');

  client.disconnect();
  await within(assert.rejects(read), 'pending read to be cancelled');
  await within(assert.rejects(queued), 'queued lookup to be cancelled');
  assert.equal(client.state, 'disconnected');
  assert.equal(helper.ports[0].closed, true);

  helper.hold.clear();
  await within(pair(client, helper), 'a fresh pairing after Lock');
  // the old port answering now reaches nothing, and nothing old was replayed on the new port
  helper.held[0].release();
  await tick();
  assert.equal(client.state, 'unlocked');
  assert.equal(helper.sent(4, helper.ports[1]).length, 0);
  assert.equal(helper.sent(5, helper.ports[1]).length, 0);
  const cred = await within(client.getPasswordForLoginName(1, site('site.example'), { username: 'dummy' }));
  assert.equal(cred.password, 'DUMMY-PASSWORD-site.example');
});

test('native disconnect cancels pending reads, and a stale port cannot touch its replacement', async (t) => {
  const { helper, client } = setup(t);
  await pair(client, helper);
  helper.hold.add(5);
  const read = client.getPasswordForLoginName(1, site('site.example'), { username: 'dummy' });
  await until(() => helper.held.length === 1, 'password read to reach the helper');
  const old = helper.ports[0];

  helper.nativeDisconnect(old);
  await within(assert.rejects(read), 'pending read to be cancelled');
  assert.equal(client.state, 'disconnected');

  helper.hold.clear();
  await within(pair(client, helper), 'pairing on a new port');
  const current = helper.ports[1];

  // late events from the dead port: a disconnect, a re-login demand, and its held password reply
  helper.nativeDisconnect(old, 'Specified native messaging host not found.');
  helper.deliver(old, { cmd: 10 });
  helper.held[0].release();
  await tick();
  assert.equal(client.state, 'unlocked');
  assert.equal(current.closed, false);
  assert.deepEqual(names(await within(client.getLoginNamesForURL(1, site('site.example')))), ['dummy@site.example']);
});

for (const [name, cmd] of [['RELOGIN_NEEDED', 10], ['PASSWORDS_DISABLED', 9]]) {
  test(`${name} cancels pending work and user-driven pairing works again`, async (t) => {
    const { helper, client } = setup(t);
    await pair(client, helper);
    helper.hold.add(5);
    const read = client.getPasswordForLoginName(1, site('site.example'), { username: 'dummy' });
    await until(() => helper.held.length === 1, 'password read to reach the helper');

    helper.deliver(helper.ports[0], { cmd });
    await within(assert.rejects(read), 'pending read to be cancelled');
    assert.notEqual(client.state, 'unlocked');
    assert.equal(helper.ports[0].closed, true);
    await assert.rejects(client.getLoginNamesForURL(1, site('site.example')), /not unlocked/);

    helper.hold.clear();
    await within(pair(client, helper), 're-pairing');
    assert.equal(client.state, 'unlocked');
    assert.equal(helper.ports.length, 2);
  });
}

test('a request encrypted under an old session is never sent on its replacement', async (t) => {
  const { helper, client } = setup(t);
  await pair(client, helper);
  const gate = gateSubtle(t, 'encrypt');
  const stale = client.getLoginNamesForURL(1, site('old.example'));
  await until(() => gate.started > 0, 'request encryption to start');
  gate.restore();

  client.disconnect();
  await within(pair(client, helper), 'pairing a new session');
  gate.open();
  await within(assert.rejects(stale, /session changed/));
  await tick();
  assert.equal(helper.sent(4, helper.ports[1]).length, 0);
  assert.deepEqual(names(await within(client.getLoginNamesForURL(2, site('new.example')))), ['dummy@new.example']);
});

test('a verification answered after Lock cannot unlock or disturb the next pairing', async (t) => {
  const { helper, client } = setup(t);
  await client.connect();
  await client.requestChallenge();
  helper.hold.add('m2');
  const verify = client.verifyPin(helper.codes.at(-1));
  await until(() => helper.held.length === 1, 'verification to reach the helper');

  client.disconnect();
  await within(assert.rejects(verify), 'verification to be cancelled');
  helper.hold.clear();
  await client.connect();
  await client.requestChallenge();

  // the old port's success arrives after the new code is on screen
  helper.held[0].release();
  await tick();
  assert.equal(client.state, 'needs_pin');
  assert.equal(client.hasChallenge, true);
  await within(client.verifyPin(helper.codes.at(-1)));
  assert.equal(client.state, 'unlocked');
});

test('verification math still running at Lock never touches the replacement challenge', async (t) => {
  const { helper, client } = setup(t);
  await client.connect();
  await client.requestChallenge();
  const gate = gateSubtle(t, 'digest');
  const verify = client.verifyPin(helper.codes.at(-1));
  await until(() => gate.started > 0, 'verification hashing to start');
  gate.restore();

  client.disconnect();
  await client.connect();
  await client.requestChallenge();
  gate.open();
  await within(assert.rejects(verify, /session changed/));

  const m2OnNewPort = helper.sent(2, helper.ports[1]).filter((r) => r.msg.msg.QID === 'm2');
  assert.equal(m2OnNewPort.length, 0);
  assert.equal(client.state, 'needs_pin');
  assert.equal(client.hasChallenge, true);
  await within(client.verifyPin(helper.codes.at(-1)));
  assert.equal(client.state, 'unlocked');
});

test('a lost pairing hello resets the connection and pairing still works', async (t) => {
  const { clock, helper, client } = setup(t);
  await Promise.all([client.connect(), client.connect()]);
  assert.equal(helper.ports.length, 1);
  helper.hold.add('m0');
  const challenge = client.requestChallenge();
  await until(() => helper.held.length === 1, 'hello to reach the helper');

  clock.advance(5000);
  await within(assert.rejects(challenge, /timeout/));
  assert.equal(client.state, 'disconnected');
  assert.equal(helper.ports[0].closed, true);

  helper.held[0].release();
  await tick();
  assert.equal(client.hasChallenge, false);

  helper.hold.clear();
  await within(pair(client, helper), 'pairing on a new port');
  assert.equal(client.state, 'unlocked');
});

test('save acknowledgements that never arrive stay harmless and keep the session', async (t) => {
  const { clock, helper, client } = setup(t);
  await pair(client, helper);
  helper.ackSaves = false;

  for (const [i, password] of ['DUMMY-ONE', 'DUMMY-TWO'].entries()) {
    const save = client.saveLogin(1, site('site.example'), 'dummy', password);
    await until(() => helper.sent(6).length === i + 1, 'save to reach the helper');
    clock.advance(3000);
    assert.equal(await within(save), true);
  }
  assert.equal(client.state, 'unlocked');

  // a save the caller withdrew while it was queued is never sent
  assert.equal(await within(client.saveLogin(1, site('site.example'), 'dummy', 'DUMMY-THREE', { shouldSend: () => false })), false);
  await tick();
  assert.equal(helper.sent(6).length, 2);
  await until(() => helper.sent(6).every((r) => r.plain), 'helper to read the saves');
  assert.deepEqual(helper.sent(6).map((r) => r.plain.NPWD), ['DUMMY-ONE', 'DUMMY-TWO']);
  assert.deepEqual(names(await within(client.getLoginNamesForURL(1, site('site.example')))), ['dummy@site.example']);
});
