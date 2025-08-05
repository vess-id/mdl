[![npm version](https://badge.fury.io/js/@vess-id%2Fmdl.svg)](https://badge.fury.io/js/@vess-id%2Fmdl)

# mDL

[ISO 18013-5](https://www.iso.org/standard/69084.html) defines mDL (mobile Driver Licenses): an ISO standard for digital driver licenses.

This is a Node.js library to issue and verify mDL [CBOR encoded](https://cbor.io/) documents in accordance with **ISO 18013-7 (draft's date: 2023-08-02)**.

## Installation

```bash
npm i @vess-id/mdl
```

## Verifying a credential

```javascript
import { Verifier } from "@vess-id/mdl";
import { inspect } from "node:util";
import fs from "node:fs";

(async () => {
  const encodedDeviceResponse = Buffer.from(encodedDeviceResponseHex, "hex");
  const encodedSessionTranscript = Buffer.from(
    encodedSessionTranscriptHex,
    "hex"
  );
  const ephemeralReaderKey = Buffer.from(ephemeralReaderKeyHex, "hex");

  const trustedCerts = [fs.readFileSync("./caCert1.pem") /*, ... */];
  const verifier = new Verifier(trustedCerts);
  const mdoc = await verifier.verify(encodedDeviceResponse, {
    ephemeralReaderKey,
    encodedSessionTranscript,
  });

  //at this point the issuer and device signature are valids.
  inspect(mdoc);
})();
```

## Getting diagnostic information

```javascript
import { Verifier } from "@vess-id/mdl";
import { inspect } from "node:util";
import fs from "node:fs";

(async () => {
  const encodedDeviceResponse = Buffer.from(encodedDeviceResponseHex, "hex");
  const encodedSessionTranscript = Buffer.from(
    encodedSessionTranscriptHex,
    "hex"
  );
  const ephemeralReaderKey = Buffer.from(ephemeralReaderKeyHex, "hex");

  const trustedCerts = [fs.readFileSync("./caCert1.pem") /*, ... */];
  const verifier = new Verifier(trustedCerts);

  const diagnosticInfo = await verifier.getDiagnosticInformation(
    encodedDeviceResponse,
    {
      ephemeralReaderKey,
      encodedSessionTranscript,
    }
  );

  inspect(diagnosticInfo);
})();
```

## Issuing a credential

### Traditional approach with private key

```js
import { MDoc, Document } from "@vess-id/mdl";
import { inspect } from "node:util";

(async () => {
  const document = await new Document("org.iso.18013.5.1.mDL")
    .addIssuerNameSpace("org.iso.18013.5.1", {
      family_name: "Jones",
      given_name: "Ava",
      birth_date: "2007-03-25",
    })
    .useDigestAlgorithm("SHA-256")
    .addValidityInfo({
      signed: new Date(),
    })
    .addDeviceKeyInfo({ deviceKey: publicKeyJWK })
    .sign({
      issuerPrivateKey,
      issuerCertificate,
      alg: 'ES256',
    });

  const mdoc = new MDoc([document]).encode();

  inspect(mdoc);
})();
```

### Using external signer (HSM, KMS, or remote signing)

```js
import { MDoc, Document, CoseSign1Signer, CoseSign1ContextualSigner } from "@vess-id/mdl";

(async () => {
  // Basic signer - receives only the data to sign
  const basicSigner: CoseSign1Signer = async (data: Uint8Array) => {
    // Send data to HSM/KMS/remote service for signing
    const signature = await externalSigningService.sign(data);
    return new Uint8Array(signature);
  };

  // Or use contextual signer for more control
  const contextualSigner: CoseSign1ContextualSigner = async (context) => {
    console.log('Signing algorithm:', context.algorithm);
    console.log('Payload size:', context.payload.length);
    
    // Use context information for signing
    const signature = await externalSigningService.signWithContext({
      data: context.data,
      algorithm: context.algorithm,
      // ... other context data
    });
    return new Uint8Array(signature);
  };
  // Mark as contextual signer
  (contextualSigner as any).isContextualSigner = true;

  const document = await new Document("org.iso.18013.5.1.mDL")
    .addIssuerNameSpace("org.iso.18013.5.1", {
      family_name: "Jones",
      given_name: "Ava",
      birth_date: "2007-03-25",
    })
    .useDigestAlgorithm("SHA-256")
    .addValidityInfo({
      signed: new Date(),
    })
    .addDeviceKeyInfo({ deviceKey: publicKeyJWK })
    .sign({
      signer: basicSigner, // or contextualSigner
      issuerCertificate,
      alg: 'ES256',
    });

  const mdoc = new MDoc([document]).encode();
})();
```

### Real-world examples

#### AWS KMS Integration
```js
import { KMSClient, SignCommand } from "@aws-sdk/client-kms";
import { CoseSign1Signer } from "@vess-id/mdl";

const kmsClient = new KMSClient({ region: "us-east-1" });

const kmsSigner: CoseSign1Signer = async (data: Uint8Array) => {
  const command = new SignCommand({
    KeyId: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
    Message: data,
    SigningAlgorithm: "ECDSA_SHA_256",
  });
  
  const response = await kmsClient.send(command);
  return new Uint8Array(response.Signature!);
};
```

#### Hardware Security Module (HSM)
```js
import { CoseSign1Signer } from "@vess-id/mdl";

const hsmSigner: CoseSign1Signer = async (data: Uint8Array) => {
  // Example using PKCS#11
  const session = await hsm.openSession();
  try {
    const signature = await session.sign({
      mechanism: "ECDSA",
      data: data,
      keyHandle: privateKeyHandle,
    });
    return new Uint8Array(signature);
  } finally {
    await session.close();
  }
};
```

## Generating a device response

```js
import { DeviceResponse, MDoc } from "@vess-id/mdl";

(async () => {
  let issuerMDoc;
  let deviceResponseMDoc;

  /**
   * This is what the MDL issuer does to generate a credential:
   */
  {
    let issuerPrivateKey;
    let issuerCertificate;
    let devicePublicKey; // the public key for the device, as a JWK

    const document = await new Document("org.iso.18013.5.1.mDL")
      .addIssuerNameSpace("org.iso.18013.5.1", {
        family_name: "Jones",
        given_name: "Ava",
        birth_date: "2007-03-25",
      })
      .useDigestAlgorithm("SHA-256")
      .addValidityInfo({
        signed: new Date(),
      })
      .addDeviceKeyInfo({ deviceKey: devicePublicKey })
      .sign({
        issuerPrivateKey,
        issuerCertificate,
        alg: "ES256",
      });

    issuerMDoc = new MDoc([document]).encode();
  }

  /**
   * This is what the DEVICE does to generate a response...
   */
  {
    let devicePrivateKey; // the private key for the device, as a JWK

    // Parameters coming from the OID4VP transaction
    let mdocGeneratedNonce, clientId, responseUri, verifierGeneratedNonce;
    let presentationDefinition = {
      id: "family_name_only",
      input_descriptors: [
        {
          id: "org.iso.18013.5.1.mDL",
          format: { mso_mdoc: { alg: ["EdDSA", "ES256"] } },
          constraints: {
            limit_disclosure: "required",
            fields: [
              {
                path: ["$['org.iso.18013.5.1']['family_name']"],
                intent_to_retain: false,
              },
            ],
          },
        },
      ],
    };

    deviceResponseMDoc = await DeviceResponse.from(issuerMDoc)
      .usingPresentationDefinition(presentationDefinition)
      .usingSessionTranscriptForOID4VP(
        mdocGeneratedNonce,
        clientId,
        responseUri,
        verifierGeneratedNonce
      )
      .authenticateWithSignature(devicePrivateKey, "ES256")
      .sign();
  }
})();
```

## License

Apache-2.0

## Credits
Thanks to:

- [auth0/mdl](https://github.com/auth0-lab/mdl) for the mdl implementation on which this repository is based.