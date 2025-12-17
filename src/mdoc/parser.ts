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
    const sign1 = new Sign1(...deviceSignature);
    return { deviceSignature: sign1 };
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
    deviceResponse = cborDecode(encoded);
  } catch (err) {
    throw new MDLParseError(`Unable to decode device response: ${err.message}`);
  }

  // Handle both Map and Object responses from cbor-x
  const isResponseMap = deviceResponse instanceof Map;

  const responseData = isResponseMap
    ? Object.fromEntries(deviceResponse)
    : deviceResponse;

  const { version, documents, status } = responseData;

  const parsedDocuments: IssuerSignedDocument[] = documents.map((doc: any): IssuerSignedDocument => {
    // Helper functions to handle both Map and Object
    const isDocMap = doc instanceof Map;
    const getDocKey = (key: string) => isDocMap ? doc.get(key) : doc[key];
    const hasDocKey = (key: string) => isDocMap ? doc.has(key) : key in doc;

    const issuerSignedData = getDocKey('issuerSigned');
    const getIssuerSignedKey = (key: string) =>
      issuerSignedData instanceof Map ? issuerSignedData.get(key) : issuerSignedData[key];

    const issuerAuth = parseIssuerAuthElement(
      getIssuerSignedKey('issuerAuth'),
      getDocKey('docType'),
    );

    const issuerSigned = hasDocKey('issuerSigned') ? {
      ...issuerSignedData,
      nameSpaces: mapIssuerNameSpaces(
        getIssuerSignedKey('nameSpaces'),
      ),
      issuerAuth,
    } : undefined;

    const deviceSigned = hasDocKey('deviceSigned') ? (() => {
      const deviceSignedData = getDocKey('deviceSigned');
      const getDeviceSignedKey = (key: string) =>
        deviceSignedData instanceof Map ? deviceSignedData.get(key) : deviceSignedData[key];
      const nameSpacesData = getDeviceSignedKey('nameSpaces');
      const nameSpacesDataValue = nameSpacesData instanceof Map ? nameSpacesData.get('data') : nameSpacesData.data;

      return {
        ...deviceSignedData,
        nameSpaces: mapDeviceNameSpaces(nameSpacesDataValue),
        deviceAuth: parseDeviceAuthElement(getDeviceSignedKey('deviceAuth')),
      };
    })() : undefined;

    if (deviceSigned) {
      return new DeviceSignedDocument(
        getDocKey('docType'),
        issuerSigned,
        deviceSigned,
      );
    }
    return new IssuerSignedDocument(
      getDocKey('docType'),
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

  // Check for Map or Object structure (cbor-x may decode to either)
  const isMap = decoded instanceof Map;
  const isObject = !isMap && typeof decoded === 'object' && decoded !== null;

  if (!isMap && !isObject) {
    throw new MDLParseError('IssuerSigned must be a CBOR Map or Object');
  }

  // Helper functions to access properties regardless of Map or Object
  const hasKey = (key: string) => isMap ? decoded.has(key) : key in decoded;
  const getKey = (key: string) => isMap ? decoded.get(key) : (decoded as any)[key];

  if (!hasKey('nameSpaces') || !hasKey('issuerAuth')) {
    throw new MDLParseError(
      'Invalid IssuerSigned structure: missing nameSpaces or issuerAuth',
    );
  }

  // Parse issuerAuth
  const rawIssuerAuth = getKey('issuerAuth');
  const issuerAuth = parseIssuerAuthElement(rawIssuerAuth, docType);

  // Parse nameSpaces
  const rawNameSpaces = getKey('nameSpaces');
  const nameSpaces = mapIssuerNameSpaces(rawNameSpaces);

  // Create IssuerSigned object
  const issuerSigned = {
    nameSpaces,
    issuerAuth,
  };

  return new IssuerSignedDocument(docType, issuerSigned);
};
