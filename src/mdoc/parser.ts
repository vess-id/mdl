import { compareVersions } from 'compare-versions';
import { Mac0, Sign1 } from 'cose-kit';
import { cborDecode } from '../cbor';
import { MDoc } from './model/MDoc';
import {
  DeviceAuth, IssuerNameSpaces, RawDeviceAuth, RawIndexedDataItem, RawIssuerAuth, RawNameSpaces,
} from './model/types';
import IssuerAuth from './model/IssuerAuth';
import { IssuerSignedItem } from './IssuerSignedItem';
import { MDLParseError } from './errors';
import { IssuerSignedDocument } from './model/IssuerSignedDocument';
import { DeviceSignedDocument } from './model/DeviceSignedDocument';

const parseIssuerAuthElement = (
  rawIssuerAuth: RawIssuerAuth,
  expectedDocType: string,
): IssuerAuth => {
  const issuerAuth = new IssuerAuth(...rawIssuerAuth);
  const { decodedPayload } = issuerAuth;
  const { docType, version } = decodedPayload;

  if (docType !== expectedDocType) {
    throw new MDLParseError(`The issuerAuth docType must be ${expectedDocType}`);
  }

  if (!version || compareVersions(version, '1.0') !== 0) {
    throw new MDLParseError("The issuerAuth version must be '1.0'");
  }

  return issuerAuth;
};

const parseDeviceAuthElement = (rawDeviceAuth: RawDeviceAuth): DeviceAuth => {
  const { deviceSignature, deviceMac } = Object.fromEntries(rawDeviceAuth);
  if (deviceSignature) {
    return { deviceSignature: new Sign1(...deviceSignature) };
  }
  return { deviceMac: new Mac0(...deviceMac) };
};

const namespaceToArray = (
  entries: RawIndexedDataItem,
): IssuerSignedItem[] => {
  return entries.map((di) => new IssuerSignedItem(di));
};

const mapIssuerNameSpaces = (namespace: RawNameSpaces): IssuerNameSpaces => {
  return Array.from(namespace.entries()).reduce((prev, [nameSpace, entries]) => {
    const mappedNamespace = namespaceToArray(entries);
    return {
      ...prev,
      [nameSpace]: mappedNamespace,
    };
  }, {});
};

const mapDeviceNameSpaces = (namespace: Map<string, Map<string, any>>) => {
  const entries = Array.from(namespace.entries()).map(([ns, attrs]) => {
    return [ns, Object.fromEntries(attrs.entries())];
  });
  return Object.fromEntries(entries);
};

/**
 * Parse an mdoc
 *
 * @param encoded - The cbor encoded mdoc
 * @returns {Promise<MDoc>} - The parsed device response
 */
export const parse = (
  encoded: Buffer | Uint8Array,
): MDoc => {
  let deviceResponse;
  try {
    deviceResponse = cborDecode(encoded) as Map<string, any>;
  } catch (err) {
    throw new MDLParseError(`Unable to decode device response: ${err.message}`);
  }

  const { version, documents, status } = Object.fromEntries(deviceResponse);

  const parsedDocuments: IssuerSignedDocument[] = documents.map((doc: Map<string, any>): IssuerSignedDocument => {
    const issuerAuth = parseIssuerAuthElement(
      doc.get('issuerSigned').get('issuerAuth'),
      doc.get('docType'),
    );

    const issuerSigned = doc.has('issuerSigned') ? {
      ...doc.get('issuerSigned'),
      nameSpaces: mapIssuerNameSpaces(
        doc.get('issuerSigned').get('nameSpaces'),
      ),
      issuerAuth,
    } : undefined;

    const deviceSigned = doc.has('deviceSigned') ? {
      ...doc.get('deviceSigned'),
      nameSpaces: mapDeviceNameSpaces(doc.get('deviceSigned').get('nameSpaces').data),
      deviceAuth: parseDeviceAuthElement(doc.get('deviceSigned').get('deviceAuth')),
    } : undefined;

    if (deviceSigned) {
      return new DeviceSignedDocument(
        doc.get('docType'),
        issuerSigned,
        deviceSigned,
      );
    }
    return new IssuerSignedDocument(
      doc.get('docType'),
      issuerSigned,
    );
  });

  return new MDoc(parsedDocuments, version, status);
};

/**
 * Parse IssuerSigned CBOR and create IssuerSignedDocument.
 * Used for OID4VCI issued credentials that only contain IssuerSigned structure.
 *
 * OID4VCI 1.0 Section A.2.4:
 * The credential claim contains a base64url-encoded CBOR-encoded IssuerSigned structure.
 *
 * @param issuerSignedCbor - CBOR-encoded IssuerSigned structure
 * @param docType - Document type (e.g., 'org.iso.18013.5.1.mDL')
 * @returns IssuerSignedDocument
 *
 * @example
 * ```typescript
 * // Parse OID4VCI issued credential
 * const issuerSignedDoc = parseIssuerSigned(credentialBytes, 'org.iso.18013.5.1.mDL');
 *
 * // Create MDoc for OID4VP presentation
 * const mdoc = new MDoc([issuerSignedDoc]);
 * ```
 */
export const parseIssuerSigned = (
  issuerSignedCbor: Uint8Array,
  docType: string,
): IssuerSignedDocument => {
  // Decode CBOR
  const decoded = cborDecode(issuerSignedCbor);

  // Validate IssuerSigned structure
  if (!decoded || typeof decoded !== 'object') {
    throw new MDLParseError('Invalid IssuerSigned CBOR');
  }

  // Check for Map structure (CBOR decodes to Map)
  if (!(decoded instanceof Map)) {
    throw new MDLParseError('IssuerSigned must be a CBOR Map');
  }

  if (!decoded.has('nameSpaces') || !decoded.has('issuerAuth')) {
    throw new MDLParseError(
      'Invalid IssuerSigned structure: missing nameSpaces or issuerAuth',
    );
  }

  // Parse issuerAuth
  const rawIssuerAuth = decoded.get('issuerAuth');
  const issuerAuth = parseIssuerAuthElement(rawIssuerAuth, docType);

  // Parse nameSpaces
  const rawNameSpaces = decoded.get('nameSpaces');
  const nameSpaces = mapIssuerNameSpaces(rawNameSpaces);

  // Create IssuerSigned object
  const issuerSigned = {
    nameSpaces,
    issuerAuth,
  };

  return new IssuerSignedDocument(docType, issuerSigned);
};
