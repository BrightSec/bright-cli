import { Pkcs11Uri } from './Pkcs11Uri';

describe('Pkcs11Uri', () => {
  describe('build', () => {
    it('should prefer the id over the label', () => {
      // act
      const uri = Pkcs11Uri.build({
        token: 'card',
        type: 'private',
        id: Buffer.from([0x01, 0xab]),
        object: 'client'
      });

      // assert
      expect(uri).toBe('pkcs11:token=card;id=%01%ab;type=private');
    });

    it('should use the label when there is no id', () => {
      // act
      const uri = Pkcs11Uri.build({
        token: 'card',
        type: 'cert',
        id: Buffer.alloc(0),
        object: 'client'
      });

      // assert
      expect(uri).toBe('pkcs11:token=card;object=client;type=cert');
    });

    it('should percent-encode characters that would split the URI', () => {
      // act
      const uri = Pkcs11Uri.build({
        token: 'PIV Card;1',
        type: 'private',
        object: 'a=b?c',
        pin: '12;?&%'
      });

      // assert
      expect(uri).toBe(
        'pkcs11:token=PIV%20Card%3b1;object=a%3db%3fc;type=private?pin-value=12%3b%3f%26%25'
      );
    });

    it('should encode a non-ASCII label as UTF-8', () => {
      // act
      const uri = Pkcs11Uri.build({ token: 'карта', type: 'cert' });

      // assert
      expect(uri).toBe('pkcs11:token=%d0%ba%d0%b0%d1%80%d1%82%d0%b0;type=cert');
    });
  });
});
