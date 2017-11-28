# Electrum seed modifier

This tool can slightly modify the seed you already remember to make it work with another type of wallet. For example, you can upgrade from standart electrum wallet to a segwit wallet, or to switch from electrum to BIP-39 compatible wallet.

**Be careful!** You are entering your private key here! It is strongly recommended to open this page in incognito mode without any browser extensions, switch off your internet connection completely, and only after that enter your seed in the field below. Don't forget to close this site before connecting to the internet again.

The script doesn't rely on any frameworks or libraries and it doesn't require internet connection. Feel free to download source code and use it on air-gapped offline computer.

# Example

## Standart seed

```
kit venture inmate circle ski prevent burst zoo upon rather angle ancient
```

## Segwit seed

```
kit venture inmate circle ski prevent burst zoo upon rather angle scale
```

## 2FA seed

```
kit venture inmate circle ski prevent burst zoo upon spring angle ancient
```

## BIP-39 seed

```
kit venture inmate circle ski prevent burst zoo upon rather angle animal
```

# Contribution

Everyone is welcome to contribute anything that you think will make the tool better. Including grammar and style fixes, documentation improvements, design or code optimization. 

There are a few basic principles that I find crucial:

- **No external dependencies** like jquery, vue.js, bitcoinjs or whatever. It's too easy to include a single line of code there to steal private keys (like what mybtgwallet.com did)
- **Should work offline** without running a server or whatever. Just opening an index.html file should be enough to get the tool working

# ToDo:

- BIP39: extend seed length if number of words is wrong based on hash
- refactor code to separate view and logic functions
- add different languages support
- test with other wallets
- make a python implementation for command line fans