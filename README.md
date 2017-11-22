# Electrum seed modifier

Electrum seed modifier to move between wallet types with only small changes in the seed

# Example

## Standart seed

```
kit venture inmate circle ski prevent burst zoo upon rather angle ancient
```

## Segwit seed

```
kit venture inmate circle ski prevent burst zoo upon rather angle scale
```

# Todo:

- BIP39
  - replace words
  - extend length if necessary
- make seed generation
  + html layout
  + detect type of the seed
  - separate view and logic
  - highlight changes
- detect typos (words not from the list)
- all types of seeds (01, 100, 101, bip39, check trezor etc)
- detect language
- python implementation