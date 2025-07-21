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
    decoded = Object.fromEntries(decoded);
    const mapValidityInfo = (validityInfo: Map<string, Uint8Array>) => {
      if (!validityInfo) {
        return validityInfo;
      }
      return Object.fromEntries(
        [...validityInfo.entries()].map(([key, value]) => {
          return [key, value instanceof Uint8Array ? cborDecode(value) : value];
        }),
      );
    };
    const result: MSO = {
      ...decoded,
      validityInfo: mapValidityInfo(decoded.validityInfo),
      validityDigests: decoded.validityDigests
        ? Object.fromEntries(decoded.validityDigests)
        : decoded.validityDigests,
      deviceKeyInfo: decoded.deviceKeyInfo
        ? Object.fromEntries(decoded.deviceKeyInfo)
        : decoded.deviceKeyInfo,
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
    // Create the protected headers map and encode it
    const protectedHeadersMap = new Map(
      Object.entries(protectedHeaders).map(([key, value]) => {
        // Map COSE header parameter names to their numeric keys
        let numericKey: number;
        let numericValue: any = value;
        if (key === 'alg') {
          numericKey = 1; // COSE alg parameter
          // Convert algorithm string to COSE algorithm identifier
          if (value === 'ES256') numericValue = -7;
          else if (value === 'ES384') numericValue = -35;
          else if (value === 'ES512') numericValue = -36;
          else if (value === 'EdDSA') numericValue = -8;
          else numericValue = value; // Keep original if not recognized
        } else {
          numericKey = typeof key === 'string' ? parseInt(key, 10) : key;
        }
        return [numericKey, numericValue];
      }),
    );

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
        unprotectedHeadersMap = new Map(
          Object.entries(unprotectedHeaders).map(([key, value]) => {
            // Map COSE header parameter names to their numeric keys
            let numericKey: number;
            if (key === 'x5chain') {
              numericKey = 33; // COSE x5chain parameter
            } else if (key === 'kid') {
              numericKey = 4; // COSE kid parameter
            } else {
              numericKey = typeof key === 'string' ? parseInt(key, 10) : key;
            }
            return [numericKey, value];
          }),
        );
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
