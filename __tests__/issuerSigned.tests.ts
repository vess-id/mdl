import { Document, IssuerSignedDocument, parseIssuerSigned, MDoc } from '../src';
import { cborDecode } from '../src/cbor';

describe('IssuerSigned Encoding for OID4VCI', () => {
  let signedDocument: IssuerSignedDocument;

  beforeAll(async () => {
    // Create a test document
    const document = new Document('org.iso.18013.5.1.mDL')
      .addIssuerNameSpace('org.iso.18013.5.1', {
        given_name: 'John',
        family_name: 'Doe',
        birth_date: '1990-01-01',
      })
      .useDigestAlgorithm('SHA-256')
      .addValidityInfo({
        signed: new Date('2024-01-01T00:00:00Z'),
        validFrom: new Date('2024-01-01T00:00:00Z'),
        validUntil: new Date('2025-01-01T00:00:00Z'),
      });

    // Mock signing - returns a simple signature
    const signer = async (data: Uint8Array): Promise<Uint8Array> => {
      // Return a mock 64-byte signature for ES256
      return new Uint8Array(64).fill(0x42);
    };

    signedDocument = await document.sign({
      signer,
      issuerCertificate: [],
      alg: 'ES256',
      kid: 'test-kid',
    });
  });

  describe('prepareIssuerSigned', () => {
    it('should return IssuerSigned structure without docType', () => {
      const issuerSigned = signedDocument.prepareIssuerSigned();

      expect(issuerSigned).toHaveProperty('nameSpaces');
      expect(issuerSigned).toHaveProperty('issuerAuth');
      expect(issuerSigned.nameSpaces).toBeInstanceOf(Map);
    });

    it('should have nameSpaces Map with correct namespace', () => {
      const issuerSigned = signedDocument.prepareIssuerSigned();
      const nameSpaces = issuerSigned.nameSpaces;

      expect(nameSpaces.has('org.iso.18013.5.1')).toBe(true);
      const namespace = nameSpaces.get('org.iso.18013.5.1');
      expect(Array.isArray(namespace)).toBe(true);
      expect(namespace.length).toBeGreaterThan(0);
    });
  });

  describe('encodeIssuerSigned', () => {
    it('should encode IssuerSigned structure to Buffer', () => {
      const issuerSignedBuffer = signedDocument.encodeIssuerSigned();

      expect(issuerSignedBuffer).toBeInstanceOf(Buffer);
      expect(issuerSignedBuffer.length).toBeGreaterThan(0);
    });

    it('should produce CBOR-encoded data with correct structure', () => {
      const issuerSignedBuffer = signedDocument.encodeIssuerSigned();
      const decoded = cborDecode(issuerSignedBuffer);

      // Verify structure matches OID4VCI 1.0 Section A.2.4
      // cborDecode returns a Map
      expect(decoded instanceof Map).toBe(true);
      expect(decoded.has('nameSpaces')).toBe(true);
      expect(decoded.has('issuerAuth')).toBe(true);

      // OID4VCI: IssuerSigned should NOT include docType
      expect(decoded.has('docType')).toBe(false);
    });

    it('should decode to same structure as prepareIssuerSigned', () => {
      const issuerSignedBuffer = signedDocument.encodeIssuerSigned();
      const decoded = cborDecode(issuerSignedBuffer);
      const prepared = signedDocument.prepareIssuerSigned();

      // Both should have the same top-level keys (Map keys vs object keys)
      expect(decoded instanceof Map).toBe(true);
      const decodedKeys = Array.from(decoded.keys()).sort();
      expect(decodedKeys).toEqual(['issuerAuth', 'nameSpaces']);
    });

    it('should be different from full Document structure', () => {
      const issuerSignedBuffer = signedDocument.encodeIssuerSigned();
      const decodedIssuerSigned = cborDecode(issuerSignedBuffer);

      const fullDocumentMap = signedDocument.prepare();

      // Full document has docType, IssuerSigned does not
      expect(fullDocumentMap.has('docType')).toBe(true);
      expect(decodedIssuerSigned.has('docType')).toBe(false);

      // Both have issuerSigned/issuerAuth, but at different levels
      expect(fullDocumentMap.has('issuerSigned')).toBe(true);
      expect(decodedIssuerSigned.has('issuerAuth')).toBe(true);
    });

    it('should be suitable for base64url encoding', () => {
      const issuerSignedBuffer = signedDocument.encodeIssuerSigned();
      const base64url = Buffer.from(issuerSignedBuffer).toString('base64url');

      // Should be a valid base64url string
      expect(typeof base64url).toBe('string');
      expect(base64url.length).toBeGreaterThan(0);
      expect(base64url).not.toContain('+');
      expect(base64url).not.toContain('/');
      expect(base64url).not.toContain('=');
    });
  });

  describe('OID4VCI 1.0 Compliance', () => {
    it('should match OID4VCI 1.0 Section A.2.4 requirements', () => {
      const issuerSignedBuffer = signedDocument.encodeIssuerSigned();
      const decoded = cborDecode(issuerSignedBuffer);

      // OID4VCI 1.0 Section A.2.4:
      // The credential claim MUST be a base64url-encoded CBOR-encoded IssuerSigned structure

      // 1. Must be CBOR-encoded (verified by successful decode)
      expect(decoded).toBeDefined();
      expect(decoded instanceof Map).toBe(true);

      // 2. Must be IssuerSigned structure (nameSpaces + issuerAuth)
      expect(decoded.has('nameSpaces')).toBe(true);
      expect(decoded.has('issuerAuth')).toBe(true);

      // 3. Must NOT be DeviceResponse (no version, documents, status)
      expect(decoded.has('version')).toBe(false);
      expect(decoded.has('documents')).toBe(false);
      expect(decoded.has('status')).toBe(false);

      // 4. Must NOT include docType wrapper
      expect(decoded.has('docType')).toBe(false);
    });

    it('should be convertible to OID4VCI Credential Response format', () => {
      const issuerSignedBuffer = signedDocument.encodeIssuerSigned();
      const base64url = Buffer.from(issuerSignedBuffer).toString('base64url');

      // Simulate OID4VCI Credential Response structure
      const credentialResponse = {
        credentials: [
          {
            credential: base64url, // This is the correct format for OID4VCI 1.0
          },
        ],
      };

      expect(credentialResponse.credentials[0].credential).toBe(base64url);
      expect(typeof credentialResponse.credentials[0].credential).toBe('string');
    });
  });

  describe('parseIssuerSigned (OID4VCI to OID4VP)', () => {
    it('should parse IssuerSigned CBOR to IssuerSignedDocument', () => {
      const issuerSignedCbor = signedDocument.encodeIssuerSigned();

      // Parse back to IssuerSignedDocument
      const parsed = parseIssuerSigned(
        issuerSignedCbor,
        'org.iso.18013.5.1.mDL'
      );

      expect(parsed).toBeInstanceOf(IssuerSignedDocument);
      expect(parsed.docType).toBe('org.iso.18013.5.1.mDL');
      expect(parsed.issuerSignedNameSpaces).toContain('org.iso.18013.5.1');
    });

    it('should preserve namespace data after parsing', () => {
      const issuerSignedCbor = signedDocument.encodeIssuerSigned();
      const parsed = parseIssuerSigned(issuerSignedCbor, 'org.iso.18013.5.1.mDL');

      // Check that namespace data is preserved
      const namespace = parsed.getIssuerNameSpace('org.iso.18013.5.1');
      expect(namespace).toHaveProperty('given_name');
      expect(namespace.given_name).toBe('John');
      expect(namespace).toHaveProperty('family_name');
      expect(namespace.family_name).toBe('Doe');
    });

    it('should create MDoc from parsed IssuerSigned', () => {
      const issuerSignedCbor = signedDocument.encodeIssuerSigned();
      const parsed = parseIssuerSigned(issuerSignedCbor, 'org.iso.18013.5.1.mDL');

      // Create MDoc for OID4VP presentation
      const mdoc = new MDoc([parsed]);

      expect(mdoc.documents.length).toBe(1);
      expect(mdoc.documents[0].docType).toBe('org.iso.18013.5.1.mDL');
      expect(mdoc.version).toBe('1.0');
    });

    it('should encode to DeviceResponse format for OID4VP', () => {
      const issuerSignedCbor = signedDocument.encodeIssuerSigned();
      const parsed = parseIssuerSigned(issuerSignedCbor, 'org.iso.18013.5.1.mDL');

      // Create MDoc and encode to DeviceResponse
      const mdoc = new MDoc([parsed]);
      const deviceResponseCbor = mdoc.encode();

      // Decode and verify DeviceResponse structure
      const decoded = cborDecode(deviceResponseCbor);

      // DeviceResponse should have version, documents, status
      expect(decoded.has('version')).toBe(true);
      expect(decoded.has('documents')).toBe(true);
      expect(decoded.has('status')).toBe(true);

      // Verify documents structure
      const documents = decoded.get('documents');
      expect(Array.isArray(documents)).toBe(true);
      expect(documents.length).toBe(1);

      const doc = documents[0];
      expect(doc.has('docType')).toBe(true);
      expect(doc.get('docType')).toBe('org.iso.18013.5.1.mDL');
      expect(doc.has('issuerSigned')).toBe(true);
    });

    it('should throw error for invalid IssuerSigned structure', () => {
      const invalidCbor = Buffer.from('invalid');

      expect(() => {
        parseIssuerSigned(invalidCbor, 'org.iso.18013.5.1.mDL');
      }).toThrow();
    });

    it('should throw error for missing nameSpaces', () => {
      // Create CBOR with only issuerAuth
      const { cborEncode } = require('../src/cbor');
      const invalidStructure = new Map();
      invalidStructure.set('issuerAuth', []);
      const invalidCbor = cborEncode(invalidStructure);

      expect(() => {
        parseIssuerSigned(invalidCbor, 'org.iso.18013.5.1.mDL');
      }).toThrow('missing nameSpaces or issuerAuth');
    });

    it('should support full OID4VCI to OID4VP workflow', () => {
      // Step 1: OID4VCI - Encode IssuerSigned for credential response
      const issuerSignedCbor = signedDocument.encodeIssuerSigned();
      const issuerSignedBase64url = Buffer.from(issuerSignedCbor).toString('base64url');

      // Verify OID4VCI credential response format
      const credentialResponse = {
        credentials: [{ credential: issuerSignedBase64url }],
      };

      expect(credentialResponse.credentials[0].credential).toBeTruthy();

      // Step 2: Wallet receives and stores the credential
      const receivedCbor = Buffer.from(issuerSignedBase64url, 'base64url');

      // Step 3: OID4VP - Parse IssuerSigned and create DeviceResponse
      const parsed = parseIssuerSigned(receivedCbor, 'org.iso.18013.5.1.mDL');
      const mdoc = new MDoc([parsed]);
      const deviceResponseCbor = mdoc.encode();

      // Verify DeviceResponse can be created
      expect(deviceResponseCbor).toBeInstanceOf(Buffer);
      expect(deviceResponseCbor.length).toBeGreaterThan(0);

      // Verify DeviceResponse structure
      const decoded = cborDecode(deviceResponseCbor);
      expect(decoded.has('version')).toBe(true);
      expect(decoded.has('documents')).toBe(true);
    });
  });
});
