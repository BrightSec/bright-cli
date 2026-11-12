import { Pkcs11PinStore } from './Pkcs11PinStore';
import { Pkcs11Cert } from '../Pkcs11Cert';

describe('Pkcs11PinStore', () => {
  const cert = (): Pkcs11Cert => ({
    hostname: 'example.com',
    cert: 'token',
    maxConcurrency: 1
  });

  describe('get', () => {
    it('should return the PIN of the same entry only', () => {
      // arrange
      const store = new Pkcs11PinStore();
      const entry = cert();
      store.set(entry, '1234');

      // act
      const results = [store.get(entry), store.get(cert())];

      // assert
      expect(results).toEqual(['1234', undefined]);
    });
  });
});
