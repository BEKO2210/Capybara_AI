import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { SignedXml } from 'xml-crypto';
import { SamlAuthProvider } from '../../src/auth/saml.provider.js';

const dir = fileURLToPath(new URL('./fixtures/', import.meta.url));
const IDP_CERT = readFileSync(dir + 'saml-idp.crt', 'utf8');
const IDP_KEY = readFileSync(dir + 'saml-idp.key', 'utf8');
const CERT_BODY = IDP_CERT.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');

const ENTRY = 'https://idp.example/sso';
const SP = 'capybara-sp';
const ACS = 'https://app.example/auth/saml/callback';
const iso = (ms: number) => new Date(ms).toISOString();

/** Build a SAMLResponse whose Assertion is signed with the given PEM key. */
function signedResponse(opts: { key?: string; email?: string; audience?: string; notAfterMs?: number } = {}): string {
  const key = opts.key ?? IDP_KEY;
  const email = opts.email ?? 'alice@example.com';
  const audience = opts.audience ?? SP;
  const now = Date.now();
  const notAfter = iso(opts.notAfterMs ?? now + 300_000);
  const assertion =
    `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="${iso(now)}">` +
    `<saml:Issuer>https://idp.example/metadata</saml:Issuer>` +
    `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${email}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="${notAfter}" Recipient="${ACS}"/></saml:SubjectConfirmation></saml:Subject>` +
    `<saml:Conditions NotBefore="${iso(now - 60_000)}" NotOnOrAfter="${notAfter}"><saml:AudienceRestriction><saml:Audience>${audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${iso(now)}" SessionIndex="_a1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
    `<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>${email}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>`;

  const sig = new SignedXml({
    privateKey: key,
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
  });
  sig.addReference({
    xpath: "//*[local-name(.)='Assertion']",
    transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#'],
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
  });
  sig.getKeyInfoContent = () => `<X509Data><X509Certificate>${CERT_BODY}</X509Certificate></X509Data>`;
  sig.computeSignature(assertion, { location: { reference: "//*[local-name(.)='Issuer']", action: 'after' } });
  const signedAssertion = sig.getSignedXml();

  const response =
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="${iso(now)}" Destination="${ACS}">` +
    `<saml:Issuer>https://idp.example/metadata</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${signedAssertion}</samlp:Response>`;
  return Buffer.from(response, 'utf8').toString('base64');
}

function provider(): SamlAuthProvider {
  return new SamlAuthProvider({ entryPoint: ENTRY, issuer: SP, callbackUrl: ACS, idpCert: IDP_CERT });
}

describe('auth — SAML 2.0 SP (signature-verified, fail-closed)', () => {
  it('begin() returns an SP-initiated AuthnRequest redirect to the IdP', async () => {
    const { redirectUrl, relayState } = await provider().begin('rs-123');
    expect(redirectUrl.startsWith(ENTRY)).toBe(true);
    expect(redirectUrl).toMatch(/SAMLRequest=/);
    expect(redirectUrl).toMatch(/RelayState=rs-123/);
    expect(relayState).toBe('rs-123');
  });

  it('accepts a correctly signed assertion and extracts the identity', async () => {
    const id = await provider().complete(signedResponse());
    expect(id.subject).toBe('alice@example.com');
    expect(id.email).toBe('alice@example.com');
  });

  it('REJECTS an assertion signed by an untrusted key (fail-closed)', async () => {
    const { generateKeyPairSync } = await import('node:crypto');
    const attacker = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs1', format: 'pem' }).toString();
    await expect(provider().complete(signedResponse({ key: attacker }))).rejects.toBeTruthy();
  });

  it('REJECTS an unsigned / garbage response (fail-closed)', async () => {
    const unsigned = Buffer.from('<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>', 'utf8').toString('base64');
    await expect(provider().complete(unsigned)).rejects.toBeTruthy();
    await expect(provider().complete('bm90LXNhbWw=')).rejects.toBeTruthy();
  });

  it('REJECTS an assertion for the wrong audience', async () => {
    await expect(provider().complete(signedResponse({ audience: 'some-other-sp' }))).rejects.toBeTruthy();
  });

  it('REJECTS an expired assertion (NotOnOrAfter in the past)', async () => {
    await expect(provider().complete(signedResponse({ notAfterMs: Date.now() - 120_000 }))).rejects.toBeTruthy();
  });
});
