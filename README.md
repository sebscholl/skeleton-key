# SkeletonKey

A Ruby gem for [describe purpose].

## Installation

```bash
gem install skeleton_key
```

Great call — this is the kind of thing that gets muddy fast in crypto libraries. If you want `SkeletonKey` to feel solid, you need sharp definitions. Here’s a convention you can adopt (and bake into docs/tests):

---

# 🔑 Naming Conventions

### **Entropy**

* **Definition**: Random bytes from a secure source (`SecureRandom`, hardware RNG, dice rolls, etc.).
* **Typical size**: 128–256 bits.
* **Usage**: Input for creating mnemonics or seeds.
* **Analogy**: The raw randomness you start with.
* **Naming**: `Entropy` (never call this a seed or secret).

---

### **Mnemonic**

* **Definition**: Human-readable representation of entropy (BIP-39 or SLIP-39 words).
* **Size**: Depends on entropy length (128-256 bits entropy → 12–24 words).
* **Usage**: Backup/recovery format for entropy (and by extension the seed).
* **Naming**: `Mnemonic` (never confuse this with the seed itself).

---

### **Seed**

* **Definition**: Deterministic byte string derived from entropy/mnemonic (e.g., BIP-39 PBKDF2 output, SLIP-39 master secret).
* **Size**: 32–64 bytes depending on scheme (Trezor SLIP-39 master secret = 32 bytes, BIP-39 seed = 64 bytes).
* **Usage**: Input to BIP-32/SLIP-10 master key generation.
* **Naming**: `Seed` → "root material for derivation".

---

### **Master Key**

* **Definition**: The root keypair (and chain code) generated from a seed via BIP-32/SLIP-10.
* **Usage**: Top of the HD wallet tree.
* **Naming**: `MasterKey`.

---

### **Secret Key (Private Key)**

* **Definition**: A single account’s private key (may be derived at any path).
* **Usage**: Signs transactions/messages.
* **Naming**: `PrivateKey` or `SecretKey` (prefer `PrivateKey` unless you want Solana-style “secret key” which is 64-bytes = priv+pub).

---

### **Public Key**

* **Definition**: The public half of a keypair.
* **Usage**: Basis for addresses.
* **Naming**: `PublicKey`.

---

### **Address**

* **Definition**: Chain-specific encoding of a public key (base58 for Solana, bech32 for Bitcoin, hex checksum for Ethereum).
* **Naming**: `Address`.

---

# 🧩 Example Flow in `SkeletonKey`

```ruby
entropy   = SkeletonKey::Entropy.generate(256)
mnemonic  = SkeletonKey::Mnemonic.from_entropy(entropy)
seed      = SkeletonKey::Seed.from_mnemonic(mnemonic)
master    = SkeletonKey::MasterKey.from_seed(seed)

btc_key   = SkeletonKey::Bitcoin::Key.from_master(master, account: 0, index: 0)
eth_key   = SkeletonKey::Ethereum::Key.from_master(master, account: 0, index: 0)
sol_key   = SkeletonKey::Solana::Key.from_master(master, account: 0, index: 0)

btc_key.private_key
btc_key.public_key
btc_key.address
```
