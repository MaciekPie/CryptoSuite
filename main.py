# main.py - prosty CLI do testów
import argparse
from crypto.hybrid import hybrid_encrypt_file, hybrid_decrypt_file
from crypto.rsa_cipher import generate_rsa_keypair

def main():
    parser = argparse.ArgumentParser(description='CryptoSuite - hybrydowy RSA+AES')
    sub = parser.add_subparsers(dest='cmd')

    gen = sub.add_parser('gen-keys', help='Wygeneruj parę kluczy RSA')
    gen.add_argument('--bits', type=int, default=2048)
    gen.add_argument('--out', default='keys/')

    enc = sub.add_parser('encrypt', help='Zaszyfruj plik (hybrydowo)')
    enc.add_argument('infile')
    enc.add_argument('outfile')
    enc.add_argument('--pubkey', required=True)

    dec = sub.add_parser('decrypt', help='Odszyfruj plik (hybrydowo)')
    dec.add_argument('infile')
    dec.add_argument('outfile')
    dec.add_argument('--privkey', required=True)

    args = parser.parse_args()

    if args.cmd == 'gen-keys':
        generate_rsa_keypair(bits=args.bits, outdir=args.out)
    elif args.cmd == 'encrypt':
        hybrid_encrypt_file(args.infile, args.outfile, args.pubkey)
    elif args.cmd == 'decrypt':
        hybrid_decrypt_file(args.infile, args.outfile, args.privkey)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
