const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { test } = require('node:test');

// Exercise the shipped inline script; fake only the browser clipboard and DOM boundary.
const source = fs.existsSync('page.go') ? fs.readFileSync('page.go', 'utf8') : fs.readFileSync('server.go', 'utf8');
const script = source.match(/<script>([\s\S]*?)<\/script>/)?.[1] ?? '';

function page(readText) {
  const elements = {
    code: { value: '999999', focus() { this.focused = true; } },
    status: { textContent: '', hidden: true, dataset: {} },
    'read-clipboard': { disabled: false, addEventListener(type, listener) { this[type] = listener; } },
  };
  const navigator = readText ? { clipboard: { readText } } : {};
  vm.runInNewContext(script, { document: { getElementById: id => elements[id] }, navigator });
  return elements;
}

test('reads exactly six digits and preserves leading zeros without submitting', async () => {
  const elements = page(async () => ' \n012345\t');
  assert.equal(typeof elements['read-clipboard'].click, 'function', 'clipboard button has no click handler');
  await elements['read-clipboard'].click();
  assert.equal(elements.code.value, '012345');
  assert.equal(elements.code.focused, true);
  assert.equal(elements.status.hidden, false);
  assert.equal(elements.status.dataset.kind, 'success');
});

test('invalid clipboard content leaves the existing code intact and shows an error', async () => {
  for (const value of ['', '12345', '1234567', 'abc123456', '123\n456', '１２３４５６', '123 456']) {
    const elements = page(async () => value);
    assert.equal(typeof elements['read-clipboard'].click, 'function', 'clipboard button has no click handler');
    await elements['read-clipboard'].click();
    assert.equal(elements.code.value, '999999', JSON.stringify(value));
    assert.equal(elements.status.hidden, false);
    assert.equal(elements.status.dataset.kind, 'error');
    assert.match(elements.status.textContent, /6/);
  }
});

test('unsupported clipboard and denied permissions provide manual input guidance', async () => {
  for (const readText of [undefined, async () => { throw new Error('permission denied'); }]) {
    const elements = page(readText);
    assert.equal(typeof elements['read-clipboard'].click, 'function', 'clipboard button has no click handler');
    await elements['read-clipboard'].click();
    assert.equal(elements.code.value, '999999');
    assert.equal(elements.status.hidden, false);
    assert.match(elements.status.textContent, /手动/);
    assert.equal(elements['read-clipboard'].disabled, false);
  }
});

test('clipboard button is disabled while a read is pending and restored afterward', async () => {
  let resolve;
  const elements = page(() => new Promise(done => { resolve = done; }));
  assert.equal(typeof elements['read-clipboard'].click, 'function', 'clipboard button has no click handler');
  const pending = elements['read-clipboard'].click();
  assert.equal(elements['read-clipboard'].disabled, true);
  resolve('123456');
  await pending;
  assert.equal(elements['read-clipboard'].disabled, false);
});
