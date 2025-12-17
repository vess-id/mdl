import { ProtectedHeaders, Sign1, UnprotectedHeaders } from 'cose-kit';
import { X509Certificate } from '@peculiar/x509';
import { KeyLike } from 'jose';
import { cborDecode, cborEncode } from '../../cbor';
import { DataItem } from '../../cbor/DataItem';
import {
  MSO,
  CoseSign1SignerCallback,
  CoseSign1SigningContext,
  SupportedAlgs,
} from './types';

/**
 * The IssuerAuth which is a COSE_Sign1 message
 * as defined in https://www.iana.org/assignments/cose/cose.xhtml#messages
 */
export default class IssuerAuth extends Sign1 {
  #decodedPayload: MSO;
  #certificate: X509Certificate;

  constructor(
    protectedHeader: Map<number, unknown> | Uint8Array,
    unprotectedHeader: Map<number, unknown>,
    payload: Uint8Array,
    signature: Uint8Array,
  ) {
    super(protectedHeader, unprotectedHeader, payload, signature);
  }

  public get decodedPayload(): MSO {
    if (this.#decodedPayload) {
      return this.#decodedPayload;
    }
    let decoded = cborDecode(this.payload);
    decoded = decoded instanceof DataItem ? decoded.data : decoded;

    // Convert to plain object if it's a Map, otherwise use as-is
    if (decoded instanceof Map) {
      decoded = Object.fromEntries(decoded);
    }

    const mapValidityInfo = (validityInfo: Map<string, Uint8Array> | any) => {
      if (!validityInfo) {
        return validityInfo;
      }
      // Handle both Map and plain object
      if (validityInfo instanceof Map) {
        return Object.fromEntries(
          [...validityInfo.entries()].map(([key, value]) => {
            return [key, value instanceof Uint8Array ? cborDecode(value) : value];
          }),
        );
      }
      // Already a plain object - process values
      return Object.fromEntries(
        Object.entries(validityInfo).map(([key, value]) => {
          return [key, value instanceof Uint8Array ? cborDecode(value) : value];
        }),
      );
    };

    const convertMapToObject = (input: Map<any, any> | any) => {
      if (!input) return input;
      return input instanceof Map ? Object.fromEntries(input) : input;
    };

    const result: MSO = {
      ...decoded,
      validityInfo: mapValidityInfo(decoded.validityInfo),
      validityDigests: convertMapToObject(decoded.validityDigests),
      deviceKeyInfo: convertMapToObject(decoded.deviceKeyInfo),
    };
    this.#decodedPayload = result;
    return result;
  }

  public get certificate() {
    if (typeof this.#certificate === 'undefined' && this.x5chain?.length) {
      this.#certificate = new X509Certificate(this.x5chain[0]);
    }
    return this.#certificate;
  }

  public get countryName() {
    return this.certificate?.issuerName.getField('C')[0];
  }

  public get stateOrProvince() {
    return this.certificate?.issuerName.getField('ST')[0];
  }

  static async sign(
    protectedHeaders: ProtectedHeaders,
    unprotectedHeaders: UnprotectedHeaders | undefined,
    payload: Uint8Array,
    key: KeyLike | Uint8Array,
  ): Promise<IssuerAuth> {
    const sign1 = await Sign1.sign(
      protectedHeaders,
      unprotectedHeaders,
      payload,
      key,
    );
    return new IssuerAuth(
      sign1.protectedHeaders,
      sign1.unprotectedHeaders,
      sign1.payload,
      sign1.signature,
    );
  }

  /**
   * Sign using a callback signer for COSE_Sign1
   * This allows external signing (HSM, remote signing, etc.) without exposing private keys
   */
  static async signWithCallback(
    protectedHeaders: ProtectedHeaders,
    unprotectedHeaders: UnprotectedHeaders | undefined,
    payload: Uint8Array,
    signer: CoseSign1SignerCallback,
    algorithm: SupportedAlgs,
  ): Promise<IssuerAuth> {
    // Create the protected headers map using standard COSE header mappings
    const protectedHeadersMap = new Map();

    for (const [key, value] of Object.entries(protectedHeaders)) {
      let numericKey: number;
      let processedValue: any = value;

      // Map COSE header parameter names to their numeric keys
      switch (key) {
        case 'alg':
          numericKey = 1;
          // Convert algorithm string to COSE algorithm identifier
          if (value === 'ES256') processedValue = -7;
          else if (value === 'ES384') processedValue = -35;
          else if (value === 'ES512') processedValue = -36;
          else if (value === 'EdDSA') processedValue = -8;
          else if (typeof value === 'number') processedValue = value;
          else throw new Error(`Unsupported algorithm: ${value}`);
          break;
        case 'crit':
          numericKey = 2;
          break;
        case 'ctyp':
          numericKey = 3;
          // Convert string to UTF-8 bytes if needed
          if (typeof value === 'string') {
            processedValue = new TextEncoder().encode(value);
          }
          break;
        case 'kid':
          numericKey = 4;
          // Convert string to UTF-8 bytes
          if (typeof value === 'string') {
            processedValue = new TextEncoder().encode(value);
          }
          break;
        case 'x5chain':
          numericKey = 33;
          break;
        default: {
          // Try parsing as numeric key
          const parsedKey = typeof key === 'string' ? parseInt(key, 10) : key;
          if (Number.isNaN(parsedKey)) {
            throw new Error(`Unknown COSE header parameter: ${key}`);
          }
          numericKey = parsedKey;
          // Convert strings to bytes for consistency with cose-kit
          if (typeof value === 'string') {
            processedValue = new TextEncoder().encode(value);
          }
        }
      }

      protectedHeadersMap.set(numericKey, processedValue);
    }

    // Manually encode protected headers according to COSE specification
    // Protected headers must be a CBOR-encoded map
    const encodedProtectedHeaders = cborEncode(protectedHeadersMap);

    // Create the Sig_structure as per COSE_Sign1 specification using the private Signature1 method
    // This creates the data to be signed according to RFC 8152
    const sigStructure = (Sign1 as any).Signature1(
      encodedProtectedHeaders,
      new Uint8Array(),
      payload,
    );

    let signature: Uint8Array;

    // Determine signer type based on marker properties or parameter inspection
    const signerFunc = signer as any;
    if (signerFunc.isContextualSigner) {
      // Explicitly marked as contextual signer
      const context: CoseSign1SigningContext = {
        data: sigStructure,
        protectedHeaders,
        unprotectedHeaders,
        algorithm,
        payload,
      };
      signature = await (
        signer as (context: CoseSign1SigningContext) => Promise<Uint8Array>
      )(context);
    } else if (signerFunc.isBasicSigner || signer.length === 1) {
      // Explicitly marked as basic signer or has single parameter
      signature = await (signer as (data: Uint8Array) => Promise<Uint8Array>)(
        sigStructure,
      );
    } else {
      // Try contextual first, then fall back to basic
      try {
        const context: CoseSign1SigningContext = {
          data: sigStructure,
          protectedHeaders,
          unprotectedHeaders,
          algorithm,
          payload,
        };
        signature = await (
          signer as (context: CoseSign1SigningContext) => Promise<Uint8Array>
        )(context);
      } catch (error) {
        // If contextual signing failed, try basic signing
        signature = await (signer as (data: Uint8Array) => Promise<Uint8Array>)(
          sigStructure,
        );
      }
    }

    // Convert unprotected headers to Map if it's an object
    let unprotectedHeadersMap: Map<number, unknown>;
    if (unprotectedHeaders) {
      if (unprotectedHeaders instanceof Map) {
        unprotectedHeadersMap = unprotectedHeaders;
      } else {
        unprotectedHeadersMap = new Map();

        for (const [key, value] of Object.entries(unprotectedHeaders)) {
          let numericKey: number;
          let processedValue: any = value;

          // if value is undefined, skip
          if (value === undefined) {
            continue;
          }

          // Map COSE header parameter names to their numeric keys
          switch (key) {
            case 'alg':
              numericKey = 1;
              // Convert algorithm string to COSE algorithm identifier
              if (value === 'ES256') processedValue = -7;
              else if (value === 'ES384') processedValue = -35;
              else if (value === 'ES512') processedValue = -36;
              else if (value === 'EdDSA') processedValue = -8;
              else if (typeof value === 'number') processedValue = value;
              else throw new Error(`Unsupported algorithm: ${value}`);
              break;
            case 'crit':
              numericKey = 2;
              break;
            case 'ctyp':
              numericKey = 3;
              // Convert string to UTF-8 bytes if needed
              if (typeof value === 'string') {
                processedValue = new TextEncoder().encode(value);
              }
              break;
            case 'kid':
              numericKey = 4;
              // RFC 8152: kid must be encoded as byte string (bstr)
              if (typeof value === 'string') {
                processedValue = new TextEncoder().encode(value);
              } else if (value instanceof Uint8Array) {
                processedValue = value; // Already byte array
              } else {
                throw new Error('kid parameter must be a string or Uint8Array');
              }
              break;
            case 'x5chain':
              numericKey = 33;
              break;
            default: {
              // Try parsing as numeric key
              const parsedKey = typeof key === 'string' ? parseInt(key, 10) : key;
              if (Number.isNaN(parsedKey)) {
                throw new Error(`Unknown COSE header parameter: ${key}`);
              }
              numericKey = parsedKey;
              // Convert strings to bytes for consistency with cose-kit
              if (typeof value === 'string') {
                processedValue = new TextEncoder().encode(value);
              }
            }
          }

          unprotectedHeadersMap.set(numericKey, processedValue);
        }
      }
    } else {
      unprotectedHeadersMap = new Map();
    }

    return new IssuerAuth(
      protectedHeadersMap,
      unprotectedHeadersMap,
      payload,
      signature,
    );
  }
}
