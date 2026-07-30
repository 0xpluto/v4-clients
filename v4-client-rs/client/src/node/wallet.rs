use super::client::NodeClient;
use super::sequencer::Nonce;
use crate::indexer::{Address, Subaccount};
use anyhow::{anyhow as err, Error};
use bip32::{DerivationPath, Language, Mnemonic, Seed};
use cosmrs::{
    crypto::{secp256k1::SigningKey, PublicKey},
    tx, AccountId,
};
use delegate::delegate;
use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    str::FromStr,
};

/// account prefix https://docs.cosmos.network/main/learn/beginner/accounts
const BECH32_PREFIX_DYDX: &str = "dydx";

/// Hierarchical Deterministic (HD) [wallet](https://dydx.exchange/crypto-learning/glossary?#wallet)
/// which allows to have multiple addresses and signing keys from one master seed.
///
/// [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) introduced a wallet standard to derive multiple accounts
/// for different chains from a single seed (which allows to recover the whole tree of keys).
/// This `Wallet` hardcodes Cosmos ATOM token so it can derive multiple addresses from their corresponding indices.
///
/// See also [Mastering Bitcoin](https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch05_wallets.adoc).
pub struct Wallet {
    seed: Seed,
}

impl Wallet {
    /// Derive a seed from a 24-words English mnemonic phrase.
    pub fn from_mnemonic(mnemonic: &str) -> Result<Self, Error> {
        let seed = Mnemonic::new(mnemonic, Language::English)?.to_seed("");
        Ok(Self { seed })
    }

    /// Derive a dYdX account with updated account and sequence numbers.
    pub async fn account(&self, index: u32, client: &mut NodeClient) -> Result<Account, Error> {
        let mut account = self.account_offline(index)?;
        (
            account.public.account_number,
            account.public.sequence_number,
        ) = client.query_address(account.address()).await?;
        Ok(account)
    }

    /// Derive a dYdX account with zero'ed account and sequence numbers.
    pub fn account_offline(&self, index: u32) -> Result<Account, Error> {
        self.derive_account(index, BECH32_PREFIX_DYDX)
    }

    #[cfg(feature = "noble")]
    /// Noble-specific `Wallet` operations.
    pub fn noble(&self) -> noble::WalletOps<'_> {
        noble::WalletOps::new(self)
    }

    fn derive_account(&self, index: u32, prefix: &str) -> Result<Account, Error> {
        // https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        let derivation_str = format!("m/44'/118'/0'/0/{index}");
        let derivation_path = DerivationPath::from_str(&derivation_str)?;
        let private_key = SigningKey::derive_from_path(&self.seed, &derivation_path)?;
        let public_key = private_key.public_key();
        let account_id = public_key.account_id(prefix).map_err(Error::msg)?;
        let address = account_id.to_string().parse()?;
        Ok(Account {
            public: PublicAccount {
                address,
                account_number: 0,
                sequence_number: 0,
                next_nonce: None,
            },
            account_id,
            index: Some(index),
            key: private_key,
            auths: AuthenticatorsManager::default(),
        })
    }
}

/// Represents an account, either derived from a [`Wallet`] or built directly
/// from a private key.
pub struct Account {
    /// `None` when the account was created from a private key directly: there
    /// is no derivation path, so any index would be a fabrication.
    index: Option<u32>,
    // The `String` representation of the `AccountId`
    key: SigningKey,
    // The `String` representation of the `AccountId`
    #[allow(dead_code)]
    account_id: AccountId,
    /// List of accounts/IDs which authorize this account.
    auths: AuthenticatorsManager,
    // Self public data
    public: PublicAccount,
}

/// Represents an account with only publicly-available data.
/// Also provides methods to be used as an authenticator account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicAccount {
    address: Address,
    // Online attributes
    account_number: u64,
    sequence_number: u64,
    next_nonce: Option<Nonce>,
}

/// Manages authentication relationships for an account.
#[derive(Clone, Debug, Default)]
pub struct AuthenticatorsManager {
    // Optimally the key would be a PublicAccount, however it may need to be mutable
    auths: HashMap<Address, (PublicAccount, Vec<u64>)>,
}

impl Account {
    /// Build an account directly from a secp256k1 private key.
    ///
    /// [`Wallet`] derives accounts from a BIP-39 mnemonic, which is the only
    /// route this client otherwise offers. That forces any integration whose
    /// key material is provisioned out of band — an HSM export, a per-service
    /// key, a key held in a secret manager — to invent a mnemonic it does not
    /// have and does not want.
    ///
    /// The key IS the account here: there is no seed and no derivation path, so
    /// [`Account::index`] is `None`. The resulting address is the standard
    /// bech32 `dydx1…` address for this key, identical to what any Cosmos
    /// tooling computes — which is what makes funds recoverable by importing
    /// the key elsewhere.
    ///
    /// `account_number` and `sequence_number` are zeroed, exactly as
    /// [`Wallet::account_offline`] leaves them; use
    /// [`NodeClient::query_address`] to populate them before signing.
    pub fn from_private_key(key: impl AsRef<[u8]>) -> Result<Self, Error> {
        let key = SigningKey::from_slice(key.as_ref()).map_err(Error::msg)?;
        let account_id = key
            .public_key()
            .account_id(BECH32_PREFIX_DYDX)
            .map_err(Error::msg)?;
        let address = account_id.to_string().parse()?;
        Ok(Self {
            public: PublicAccount {
                address,
                account_number: 0,
                sequence_number: 0,
                next_nonce: None,
            },
            account_id,
            index: None,
            key,
            auths: AuthenticatorsManager::default(),
        })
    }

    /// The BIP-44 index this account was derived at, or `None` when it was
    /// built from a private key via [`Account::from_private_key`].
    pub fn index(&self) -> Option<u32> {
        self.index
    }

    /// A public key associated with the account.
    pub fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }

    /// Sign [`SignDoc`](tx::SignDoc) with a corresponding private key.
    pub fn sign(&self, doc: tx::SignDoc) -> Result<tx::Raw, Error> {
        doc.sign(&self.key)
            .map_err(|e| err!("Failure to sign doc: {e}"))
    }

    /// Access the authenticators manager
    pub fn authenticators(&self) -> &AuthenticatorsManager {
        &self.auths
    }

    /// Access the authenticators manager as mut
    pub fn authenticators_mut(&mut self) -> &mut AuthenticatorsManager {
        &mut self.auths
    }

    delegate! {
        to self.public {
            /// An address of the account.
            pub fn address(&self) -> &Address;
            /// A subaccount from a corresponding index.
            pub fn subaccount(&self, number: u32) -> Result<Subaccount, Error>;
            /// The account number.
            pub fn account_number(&self) -> u64;
            /// Set a new account number.
            pub fn set_account_number(&mut self, account_number: u64);
            /// The account sequence number.
            pub fn sequence_number(&self) -> u64;
            /// Set a new sequence number.
            pub fn set_sequence_number(&mut self, sequence_number: u64);
            /// Gets the [`Nonce`] to be used in the next transaction.
            pub fn next_nonce(&self) -> Option<&Nonce>;
            /// Set the [`Nonce`] to be used in the next transaction.
            pub fn set_next_nonce(&mut self, nonce: Nonce);
        }
    }
}

impl PublicAccount {
    /// Creates an updated public account using its address.
    pub async fn updated(address: Address, client: &mut NodeClient) -> Result<Self, Error> {
        let mut account = PublicAccount::new(address);
        account.update(client).await?;
        Ok(account)
    }

    /// Creates a public account from its address.
    /// Online attributes are zero'ed.
    pub fn new(address: Address) -> Self {
        Self {
            address,
            account_number: 0,
            sequence_number: 0,
            next_nonce: None,
        }
    }

    /// Sets the account and sequencer numbers using online data.
    pub async fn update(&mut self, client: &mut NodeClient) -> Result<(), Error> {
        (self.account_number, self.sequence_number) = client.query_address(self.address()).await?;
        Ok(())
    }

    /// An address of the account.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// A subaccount from a corresponding index.
    pub fn subaccount(&self, number: u32) -> Result<Subaccount, Error> {
        Ok(Subaccount::new(self.address.clone(), number.try_into()?))
    }

    /// The account number.
    pub fn account_number(&self) -> u64 {
        self.account_number
    }

    /// The account sequence number.
    pub fn sequence_number(&self) -> u64 {
        self.sequence_number
    }

    /// Set a new account number.
    ///
    /// The counterpart to [`PublicAccount::set_sequence_number`]. Both are
    /// needed to bring an offline-built account — from
    /// [`Wallet::account_offline`] or [`Account::from_private_key`] — up to
    /// date via [`NodeClient::query_address`] before signing.
    pub fn set_account_number(&mut self, account_number: u64) {
        self.account_number = account_number;
    }

    /// Set a new sequence number.
    pub fn set_sequence_number(&mut self, sequence_number: u64) {
        self.sequence_number = sequence_number;
    }

    /// Gets the [`Nonce`] to be used in the next transaction.
    pub fn next_nonce(&self) -> Option<&Nonce> {
        self.next_nonce.as_ref()
    }

    /// Set the [`Nonce`] to be used in the next transaction.
    pub fn set_next_nonce(&mut self, nonce: Nonce) {
        if let Nonce::Sequence(number) = nonce {
            self.sequence_number = number
        }
        self.next_nonce = Some(nonce);
    }
}

impl AuthenticatorsManager {
    /// Get the list of IDs associated with an authorizing account.
    pub fn get(&self, authing: &Address) -> Option<&(PublicAccount, Vec<u64>)> {
        self.auths.get(authing)
    }

    /// Get the mutable list of IDs associated with an authorizing account.
    pub fn get_mut(&mut self, authing: &Address) -> Option<&mut (PublicAccount, Vec<u64>)> {
        self.auths.get_mut(authing)
    }

    /// Add an ID for a specific authenticator.
    pub fn add(&mut self, auth: PublicAccount, id: u64) {
        if let Some(ids) = self.auths.get_mut(auth.address()) {
            ids.1.push(id);
        } else {
            self.auths.insert(auth.address().clone(), (auth, vec![id]));
        }
    }

    /// Remove an authenticator and all its IDs.
    pub fn remove(&mut self, authing: &Address) -> Option<(PublicAccount, Vec<u64>)> {
        self.auths.remove(authing)
    }
}

impl Hash for PublicAccount {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.address.hash(state);
    }
}

impl From<Address> for PublicAccount {
    fn from(address: Address) -> Self {
        PublicAccount::new(address)
    }
}

#[cfg(feature = "noble")]
mod noble {
    use super::*;
    use crate::noble::NobleClient;

    const BECH32_PREFIX_NOBLE: &str = "noble";

    /// Noble-specific wallet operations
    pub struct WalletOps<'w> {
        wallet: &'w Wallet,
    }

    impl<'w> WalletOps<'w> {
        /// Create a new Noble-specific wallet operations dispatcher.
        pub fn new(wallet: &'w Wallet) -> Self {
            Self { wallet }
        }

        /// Derive a Noble account with updated account and sequence numbers.
        pub async fn account(
            &self,
            index: u32,
            client: &mut NobleClient,
        ) -> Result<Account, Error> {
            let mut account = self.account_offline(index)?;
            (
                account.public.account_number,
                account.public.sequence_number,
            ) = client.query_address(account.address()).await?;
            Ok(account)
        }

        /// Derive a Noble account with zero'ed account and sequence numbers.
        pub fn account_offline(&self, index: u32) -> Result<Account, Error> {
            self.wallet.derive_account(index, BECH32_PREFIX_NOBLE)
        }
    }
}

#[cfg(test)]
mod private_key_tests {
    use super::*;
    use bip32::XPrv;

    /// The canonical BIP-39 test vector for 32 bytes of zero entropy.
    /// 24 words, because that is all this client's `Mnemonic` accepts.
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                                 abandon abandon abandon abandon abandon abandon abandon abandon \
                                 abandon abandon abandon abandon abandon abandon abandon art";

    /// A key-built account must land on the SAME address as the mnemonic path
    /// for the same underlying key.
    ///
    /// This is the property that makes the constructor safe to fund: if the two
    /// routes disagreed, money sent to a key-built address would be unreachable
    /// by anyone importing the mnemonic, and vice versa.
    #[test]
    fn from_private_key_matches_the_mnemonic_derivation() {
        let derived = Wallet::from_mnemonic(TEST_MNEMONIC)
            .expect("valid mnemonic")
            .account_offline(0)
            .expect("derives");

        // Independently recover the raw key at the same path, then build an
        // account from the bytes alone.
        let seed = Mnemonic::new(TEST_MNEMONIC, Language::English)
            .expect("valid mnemonic")
            .to_seed("");
        let path: DerivationPath = "m/44'/118'/0'/0/0".parse().expect("valid path");
        let xprv = XPrv::derive_from_path(&seed, &path).expect("derives");
        let from_key = Account::from_private_key(xprv.to_bytes()).expect("builds");

        assert_eq!(
            derived.address(),
            from_key.address(),
            "key-built address must equal the mnemonic-derived one"
        );
        // The index is the one thing that legitimately differs: a raw key has
        // no derivation path, so claiming index 0 would be a fabrication.
        assert_eq!(derived.index(), Some(0));
        assert_eq!(from_key.index(), None);

        // Pinned against an EXTERNAL vector, not our own arithmetic. This
        // mnemonic at m/44'/118'/0'/0/0 is published across the Cosmos
        // ecosystem as `cosmos1r5v5srda7xfth3hn2s26txvrcrntldjumt8mhl`; the
        // 20-byte payload below is that address re-encoded under the `dydx`
        // HRP (same payload, different bech32 checksum). If this line ever
        // fails, the address derivation has drifted and funds would be sent
        // somewhere the key cannot reach.
        assert_eq!(
            from_key.address().to_string(),
            "dydx1r5v5srda7xfth3hn2s26txvrcrntldjujjflhg"
        );
    }

    #[test]
    fn from_private_key_rejects_malformed_keys() {
        assert!(Account::from_private_key([]).is_err(), "empty");
        assert!(Account::from_private_key([0u8; 31]).is_err(), "too short");
        assert!(Account::from_private_key([0u8; 32]).is_err(), "zero key");
    }
}
