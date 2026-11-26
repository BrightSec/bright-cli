import { CurlHeadersParser } from './CurlHeadersParser';

const raw = (...lines: string[]) =>
  Buffer.from(lines.join('\r\n') + '\r\n\r\n', 'latin1');

describe('CurlHeadersParser', () => {
  describe('parse', () => {
    it.each([
      ['name:', 'name'],
      ['name: ', 'name'],
      ['name:   ', 'name']
    ])('should return an empty string for "%s"', (line, name) => {
      // arrange
      const input = raw('HTTP/1.1 200 OK', line);

      // act
      const result = CurlHeadersParser.parse(input);

      // assert
      expect(result).toEqual({ [name]: '' });
    });

    it('should accept a value without a space after the colon', () => {
      // arrange
      const input = raw('HTTP/1.1 200 OK', 'name:value');

      // act
      const result = CurlHeadersParser.parse(input);

      // assert
      expect(result).toEqual({ name: 'value' });
    });

    it('should trim optional whitespace around the value', () => {
      // arrange
      const input = raw('HTTP/1.1 200 OK', 'name: \t  value \t ');

      // act
      const result = CurlHeadersParser.parse(input);

      // assert
      expect(result).toEqual({ name: 'value' });
    });

    it('should keep colons inside the value', () => {
      // arrange
      const input = raw(
        'HTTP/1.1 302 Found',
        'location: https://a.test:8443/x'
      );

      // act
      const result = CurlHeadersParser.parse(input);

      // assert
      expect(result).toEqual({ location: 'https://a.test:8443/x' });
    });

    it('should collect repeated names into an array in order', () => {
      // arrange
      const input = raw(
        'HTTP/1.1 200 OK',
        'Link: <a>; rel=1',
        'Vary: accept',
        'Link: <b>; rel=2'
      );

      // act
      const result = CurlHeadersParser.parse(input);

      // assert
      expect(result).toEqual({
        link: ['<a>; rel=1', '<b>; rel=2'],
        vary: 'accept'
      });
    });

    it('should merge names that differ only by case', () => {
      // arrange
      const input = raw('HTTP/1.1 200 OK', 'X-Test: one', 'x-test: two');

      // act
      const result = CurlHeadersParser.parse(input);

      // assert
      expect(result).toEqual({ 'x-test': ['one', 'two'] });
    });

    it('should return set-cookie as an array even for a single field', () => {
      // arrange
      const input = raw('HTTP/1.1 200 OK', 'Set-Cookie: a=1');

      // act
      const result = CurlHeadersParser.parse(input);

      // assert
      expect(result).toEqual({ 'set-cookie': ['a=1'] });
    });

    it('should decode valid UTF-8 values so they round-trip', () => {
      // arrange
      const input = Buffer.from(
        'HTTP/1.1 200 OK\r\nset-cookie: n=é\r\ncontent-disposition: attachment; filename="日本.txt"\r\n\r\n',
        'utf8'
      );

      // act
      const result = CurlHeadersParser.parse(input);

      // assert
      expect(result).toEqual({
        'set-cookie': ['n=é'],
        'content-disposition': 'attachment; filename="日本.txt"'
      });
    });

    it('should keep bytes that are not valid UTF-8 as latin1 code points', () => {
      // arrange
      const input = Buffer.concat([
        Buffer.from('HTTP/1.1 200 OK\r\nx-raw: a'),
        Buffer.from([0x80, 0xff, 0xe9]),
        Buffer.from('b\r\n\r\n')
      ]);

      // act
      const result = CurlHeadersParser.parse(input);

      // assert
      expect(Buffer.from(result['x-raw'] as string, 'latin1')).toEqual(
        Buffer.from([0x61, 0x80, 0xff, 0xe9, 0x62])
      );
    });

    it.each(['content-type', 'content-length', 'location'])(
      'should keep the last value of a duplicated %s as a string',
      (name) => {
        // arrange
        const input = raw(
          'HTTP/1.1 200 OK',
          `${name}: first`,
          `${name}: second`
        );

        // act
        const result = CurlHeadersParser.parse(input);

        // assert
        expect(result).toEqual({ [name]: 'second' });
      }
    );

    it('should join an obsolete folded continuation line with a single space', () => {
      // arrange
      const input = raw('HTTP/1.1 200 OK', 'x-fold: first', '\t second');

      // act
      const result = CurlHeadersParser.parse(input);

      // assert
      expect(result).toEqual({ 'x-fold': 'first second' });
    });

    it('should return only the last block when there are 1xx or redirect blocks', () => {
      // arrange
      const input = Buffer.from(
        [
          'HTTP/1.1 100 Continue',
          '',
          'HTTP/1.1 302 Found',
          'location: /next',
          'x-only-first:',
          '',
          'HTTP/1.1 200 OK',
          'content-length: 0',
          'x-empty:',
          '',
          ''
        ].join('\r\n'),
        'latin1'
      );

      // act
      const result = CurlHeadersParser.parse(input);

      // assert
      expect(result).toEqual({ 'content-length': '0', 'x-empty': '' });
    });

    it('should accept bare LF line endings', () => {
      // arrange
      const input = Buffer.from('HTTP/1.1 200 OK\nx-a: 1\nx-b:\n\n');

      // act
      const result = CurlHeadersParser.parse(input);

      // assert
      expect(result).toEqual({ 'x-a': '1', 'x-b': '' });
    });

    it('should skip lines without a colon', () => {
      // arrange
      const input = raw('HTTP/1.1 200 OK', 'garbage', 'x-a: 1');

      // act
      const result = CurlHeadersParser.parse(input);

      // assert
      expect(result).toEqual({ 'x-a': '1' });
    });

    it('should return an empty object for an empty buffer', () => {
      // act
      const result = CurlHeadersParser.parse(Buffer.alloc(0));

      // assert
      expect(result).toEqual({});
    });
  });
});
