import * as jose from 'jose';
import { Document } from '../../src';
import { CoseSign1Signer, CoseSign1ContextualSigner, CoseSign1SigningContext } from '../../src/mdoc/model/types';

describe('Signer Callback Tests', () => {
  let issuerPrivateKey: jose.JWK;
  let issuerCertificate: Uint8Array;
  let devicePublicKey: jose.JWK;

  beforeAll(async () => {
    // Generate issuer key pair
    const issuerKeyPair = await jose.generateKeyPair('ES256');
    issuerPrivateKey = await jose.exportJWK(issuerKeyPair.privateKey);

    // Generate device key pair
    const deviceKeyPair = await jose.generateKeyPair('ES256');
    devicePublicKey = await jose.exportJWK(deviceKeyPair.publicKey);

    // Mock certificate (in real scenario this would be a proper X.509 certificate)
    issuerCertificate = new Uint8Array(64); // Mock certificate bytes
  });

  describe('Basic Signer Callback', () => {
    it('should sign using a basic signer callback', async () => {
      // Create a basic signer that mimics HSM or external signing
      const basicSigner: CoseSign1Signer = async (data: Uint8Array) => {
        // In real scenario, this would send data to HSM/external service
        // For testing, we'll sign it locally using the same method as the original implementation
        const key = await jose.importJWK(issuerPrivateKey);
        const jws = new jose.FlattenedSign(data)
          .setProtectedHeader({ alg: 'ES256' });
        const result = await jws.sign(key);
        // Return just the signature part
        return new Uint8Array(Buffer.from(result.signature, 'base64url'));
      };

      const document = await new Document('org.iso.18013.5.1.mDL')
        .addIssuerNameSpace('org.iso.18013.5.1', {
          family_name: 'Doe',
          given_name: 'John',
          birth_date: '1990-01-01',
        })
        .useDigestAlgorithm('SHA-256')
        .addValidityInfo({
          signed: new Date(),
        })
        .addDeviceKeyInfo({ deviceKey: devicePublicKey });

      // Test signing with callback
      const signedDocument = await document.sign({
        signer: basicSigner,
        issuerCertificate,
        alg: 'ES256',
      });

      expect(signedDocument).toBeDefined();
      expect(signedDocument.docType).toBe('org.iso.18013.5.1.mDL');
      expect(signedDocument.issuerSigned.issuerAuth.signature).toBeDefined();
    });
  });

  describe('Contextual Signer Callback', () => {
    it('should sign using a contextual signer callback', async () => {
      // Create a contextual signer that receives full signing context
      const contextualSigner: CoseSign1ContextualSigner = async (context: CoseSign1SigningContext) => {
        expect(context.data).toBeDefined();
        expect(context.protectedHeaders).toBeDefined();
        expect(context.algorithm).toBe('ES256');
        expect(context.payload).toBeDefined();

        // In real scenario, this would include the context in the signing request
        const key = await jose.importJWK(issuerPrivateKey);
        const jws = new jose.FlattenedSign(context.data)
          .setProtectedHeader({ alg: context.algorithm });
        const result = await jws.sign(key);
        return new Uint8Array(Buffer.from(result.signature, 'base64url'));
      };
      // Mark as contextual signer
      (contextualSigner as any).isContextualSigner = true;

      const document = await new Document('org.iso.18013.5.1.mDL')
        .addIssuerNameSpace('org.iso.18013.5.1', {
          family_name: 'Smith',
          given_name: 'Jane',
          birth_date: '1985-05-15',
        })
        .useDigestAlgorithm('SHA-256')
        .addValidityInfo({
          signed: new Date(),
        })
        .addDeviceKeyInfo({ deviceKey: devicePublicKey });

      const signedDocument = await document.sign({
        signer: contextualSigner,
        issuerCertificate,
        alg: 'ES256',
        kid: 'test-key-id',
      });

      expect(signedDocument).toBeDefined();
      expect(signedDocument.issuerSigned.issuerAuth.signature).toBeDefined();
    });
  });

  describe('Error Handling', () => {
    it('should throw error when both issuerPrivateKey and signer are provided', async () => {
      const basicSigner: CoseSign1Signer = async () => new Uint8Array(64);

      const document = new Document('org.iso.18013.5.1.mDL')
        .addIssuerNameSpace('org.iso.18013.5.1', { family_name: 'Test' });

      await expect(
        document.sign({
          issuerPrivateKey,
          signer: basicSigner,
          issuerCertificate,
          alg: 'ES256',
        }),
      ).rejects.toThrow('Cannot provide both issuerPrivateKey and signer');
    });

    it('should throw error when neither issuerPrivateKey nor signer are provided', async () => {
      const document = new Document('org.iso.18013.5.1.mDL')
        .addIssuerNameSpace('org.iso.18013.5.1', { family_name: 'Test' });

      await expect(
        document.sign({
          issuerCertificate,
          alg: 'ES256',
        } as any),
      ).rejects.toThrow('Either issuerPrivateKey or signer must be provided');
    });
  });

  describe('Backward Compatibility', () => {
    it('should still work with traditional issuerPrivateKey approach', async () => {
      const document = await new Document('org.iso.18013.5.1.mDL')
        .addIssuerNameSpace('org.iso.18013.5.1', {
          family_name: 'Legacy',
          given_name: 'User',
          birth_date: '1980-12-25',
        })
        .useDigestAlgorithm('SHA-256')
        .addValidityInfo({
          signed: new Date(),
        })
        .addDeviceKeyInfo({ deviceKey: devicePublicKey });

      const signedDocument = await document.sign({
        issuerPrivateKey,
        issuerCertificate,
        alg: 'ES256',
      });

      expect(signedDocument).toBeDefined();
      expect(signedDocument.issuerSigned.issuerAuth.signature).toBeDefined();
    });
  });
});
