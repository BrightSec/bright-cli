import { Pkcs11PublicKey } from './Pkcs11PublicKey';
import { CLIENT, EC_CLIENT, OTHER } from './__fixtures__/certificates';
import { X509Certificate } from 'node:crypto';

const P256 = Buffer.from('06082a8648ce3d030107', 'hex');

const jwkOf = (pem: string) =>
  new X509Certificate(pem).publicKey.export({ format: 'jwk' });

const bytes = (value?: string) => Buffer.from(value ?? '', 'base64url');

const spkiOf = (pem: string) =>
  new X509Certificate(pem).publicKey.export({ type: 'spki', format: 'der' });

const ecPoint = (pem: string) => {
  const { x, y } = jwkOf(pem);

  return Buffer.concat([Buffer.from([0x04]), bytes(x), bytes(y)]);
};

describe('Pkcs11PublicKey', () => {
  describe('fromAttributes', () => {
    it('should rebuild an RSA key from its modulus and exponent', () => {
      // arrange
      const { n, e } = jwkOf(CLIENT);

      // act
      const result = Pkcs11PublicKey.fromAttributes({
        modulus: bytes(n),
        publicExponent: bytes(e)
      });

      // assert
      expect(result).toEqual(spkiOf(CLIENT));
      expect(result).not.toEqual(spkiOf(OTHER));
    });

    it('should ignore leading zero bytes in the modulus', () => {
      // arrange
      const { n, e } = jwkOf(CLIENT);

      // act
      const result = Pkcs11PublicKey.fromAttributes({
        modulus: Buffer.concat([Buffer.from([0]), bytes(n)]),
        publicExponent: bytes(e)
      });

      // assert
      expect(result).toEqual(spkiOf(CLIENT));
    });

    it('should rebuild an EC key from a point wrapped in an OCTET STRING', () => {
      // arrange
      const point = ecPoint(EC_CLIENT);

      // act
      const result = Pkcs11PublicKey.fromAttributes({
        ecParams: P256,
        ecPoint: Buffer.concat([Buffer.from([0x04, point.length]), point])
      });

      // assert
      expect(result).toEqual(spkiOf(EC_CLIENT));
    });

    it('should rebuild an EC key from a bare point', () => {
      // act
      const result = Pkcs11PublicKey.fromAttributes({
        ecParams: P256,
        ecPoint: ecPoint(EC_CLIENT)
      });

      // assert
      expect(result).toEqual(spkiOf(EC_CLIENT));
    });

    it.each([
      { name: 'no attributes', attributes: {} },
      { name: 'an EC key without its point', attributes: { ecParams: P256 } },
      {
        name: 'a point that is not on the curve',
        attributes: { ecParams: P256, ecPoint: Buffer.alloc(65, 1) }
      }
    ])('should return undefined for $name', ({ attributes }) => {
      // act
      const result = Pkcs11PublicKey.fromAttributes(attributes);

      // assert
      expect(result).toBeUndefined();
    });
  });

  describe('fromCertificate', () => {
    it.each([
      { format: 'PEM', value: CLIENT },
      { format: 'DER', value: new X509Certificate(CLIENT).raw }
    ])('should read the public key of a $format certificate', ({ value }) => {
      // act
      const result = Pkcs11PublicKey.fromCertificate(value);

      // assert
      expect(result).toEqual(spkiOf(CLIENT));
    });

    it('should return undefined for a value that is not a certificate', () => {
      // act
      const result = Pkcs11PublicKey.fromCertificate(Buffer.from('garbage'));

      // assert
      expect(result).toBeUndefined();
    });
  });
});
