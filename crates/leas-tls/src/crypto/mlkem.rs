//! ML-KEM-768 primitives via `RustCrypto` `ml-kem` (FIPS 203).
//!
//! This module wraps `ml_kem::MlKem768` to provide keypair generation,
//! encapsulation, and decapsulation for TLS 1.3 hybrid key shares
//! (`X25519MLKEM768`, `SecP256r1MLKEM768`), REALITY's hybrid provisioner, and
//! VLESS encryption (`mlkem768x25519plus`).
//!
//! The former liboqs backend (`oqs` -> `oqs-sys` -> `CMake` + `bindgen`/`libclang` +
//! C/C++ toolchain) was removed on 2026-09-18: `x86_64-pc-windows-gnu` is a
//! first-class target of this workspace (`rust-toolchain.toml`, `deny.toml`)
//! and cannot assume that toolchain. The FIPS 203 byte encodings are identical
//! across the swap — the migration KAT at the bottom of this file pins the
//! seed -> encapsulation-key bytes against both the retired liboqs
//! implementation and Go 1.27.1's stdlib `crypto/mlkem`.
//!
//! Key sizes (FIPS 203 / RFC 9180):
//! - Public key: 1184 bytes
//! - Secret key: the 64-byte keygen seed (`d || z`); liboqs exposed the
//!   2400-byte expanded encoding, `RustCrypto` serializes the seed
//! - Ciphertext: 1088 bytes
//! - Shared secret: 32 bytes
//!
//! Backend: `RustCrypto` `ml-kem` 0.3.2 (`no_std`, `unsafe_code = "deny"`,
//! `zeroize` feature on), `default-features = false` so ciphertexts and shared
//! secrets are inline arrays rather than boxed ones — the allocation-free
//! entry points ([`Mlkem768::encapsulate_into`]) stay allocation-free.
use core::convert::Infallible;
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate as _, Encapsulate as _, KeyExport as _};
use ml_kem::{Ciphertext as KemCiphertext, DecapsulationKey, EncapsulationKey, MlKem768};
use rand_core::{TryCryptoRng, TryRng};
use ring::rand::SecureRandom as _;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// ML-KEM-768 public key (1184 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey([u8; 1184]);

/// ML-KEM-768 decapsulation key.
///
/// Holds the `RustCrypto` key, built from (and serializable back to) the 64-byte
/// FIPS 203 keygen seed: that seed is the form xray's VLESS `decryption`
/// config carries (Go `mlkem.NewDecapsulationKey768`). The wrapped key wipes
/// itself on drop (`RustCrypto`'s `zeroize` feature), so this wrapper owns no
/// key buffer of its own; `Debug` prints the seed length only — the derive
/// would dump key material into any log line.
#[derive(Clone)]
pub struct SecretKey(DecapsulationKey<MlKem768>);

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretKey(<{} byte seed>)", self.to_seed().len())
    }
}

/// ML-KEM-768 ciphertext (1088 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext([u8; 1088]);

/// ML-KEM-768 shared secret (32 bytes).
///
/// Wipes on drop; `Debug` prints the length only.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct SharedSecret([u8; 32]);

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SharedSecret(<{} bytes redacted>)", self.0.len())
    }
}

/// Errors from ML-KEM operations.
#[derive(Debug, Error)]
pub enum MlkemError {
    #[error("invalid encapsulation key (rejected by the FIPS 203 input check)")]
    InvalidPublicKey,
    #[error("invalid public key length: expected 1184, got {0}")]
    InvalidPublicKeyLength(usize),
    #[error("invalid ciphertext length: expected 1088, got {0}")]
    InvalidCiphertextLength(usize),
    #[error("invalid shared secret length: expected 32, got {0}")]
    InvalidSharedSecretLength(usize),
}

/// `rand_core` 0.10 adapter over ring's CSPRNG.
///
/// One RNG provider for the whole workspace: the ML-KEM keygen seed and the
/// encapsulation randomness come from the same `SystemRandom` as every other
/// key byte in this crate, instead of a second OS-RNG path behind
/// `ml-kem`'s `getrandom` feature. `Error = Infallible` (ring's CSPRNG
/// failure is not a recoverable condition anywhere else either — the call
/// sites say `.expect("ring CSPRNG fills")`), which makes the blanket
/// `Rng`/`CryptoRng` impls apply.
#[derive(Debug, Clone, Copy, Default)]
struct RingRng;

impl TryRng for RingRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        self.try_fill_bytes(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        self.try_fill_bytes(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        ring::rand::SystemRandom::new()
            .fill(dst)
            .expect("ring CSPRNG fills");
        Ok(())
    }
}

impl TryCryptoRng for RingRng {}

impl PublicKey {
    /// Create a [`PublicKey`] from raw bytes: copied once into the fixed
    /// array, no `Vec` allocation.
    pub const fn from_bytes(bytes: &[u8]) -> Result<Self, MlkemError> {
        if bytes.len() != 1184 {
            return Err(MlkemError::InvalidPublicKeyLength(bytes.len()));
        }
        let mut arr = [0u8; 1184];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Get the raw bytes of the public key.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl SecretKey {
    /// Build a key from the 64-byte FIPS 203 keygen seed (`d || z`) — the form
    /// xray's VLESS `decryption` config carries (Go
    /// `mlkem.NewDecapsulationKey768`).
    #[must_use]
    pub fn from_seed(seed: &[u8; 64]) -> Self {
        Self(DecapsulationKey::from_seed(Array::from(*seed)))
    }

    /// The 64-byte seed this key was built from (wiped on drop).
    #[must_use]
    pub fn to_seed(&self) -> Zeroizing<[u8; 64]> {
        let seed = self
            .0
            .to_seed()
            .expect("decapsulation key is always built from a seed");
        let mut out = Zeroizing::new([0u8; 64]);
        out.copy_from_slice(seed.as_slice());
        out
    }
}

impl Ciphertext {
    /// Create a [`Ciphertext`] from raw bytes: copied once into the fixed
    /// array, no `Vec` allocation. Length is the only check FIPS 203 puts on a
    /// ciphertext (`ML-KEM.Decaps` takes it as-is).
    pub const fn from_bytes(bytes: &[u8]) -> Result<Self, MlkemError> {
        if bytes.len() != 1088 {
            return Err(MlkemError::InvalidCiphertextLength(bytes.len()));
        }
        let mut arr = [0u8; 1088];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Get the raw bytes of the ciphertext.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl SharedSecret {
    /// Create a [`SharedSecret`] from raw bytes.
    pub const fn from_bytes(bytes: &[u8]) -> Result<Self, MlkemError> {
        if bytes.len() != 32 {
            return Err(MlkemError::InvalidSharedSecretLength(bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Get the raw bytes of the shared secret.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// ML-KEM-768 primitive operations.
pub struct Mlkem768;

impl Mlkem768 {
    /// Copy an [`EncapsulationKey`] into the fixed-size public-key type.
    fn public_from_ek(ek: &EncapsulationKey<MlKem768>) -> PublicKey {
        let bytes = ek.to_bytes();
        let mut out = [0u8; 1184];
        out.copy_from_slice(bytes.as_slice());
        PublicKey(out)
    }

    /// Generate a new ML-KEM-768 keypair from a fresh 64-byte seed drawn from
    /// the ring CSPRNG (FIPS 203 `KeyGen_internal`).
    ///
    /// Returns ([`PublicKey`], [`SecretKey`]) where:
    /// - [`PublicKey`] is 1184 bytes (encapsulation key)
    /// - [`SecretKey`] is the 64-byte keygen seed
    ///
    /// # Panics
    /// If the OS CSPRNG fails — `rand_core`'s `TryRng` is implemented with
    /// `Error = Infallible` and the adapter says `.expect("ring CSPRNG fills")`,
    /// the workspace's uniform policy for a CSPRNG failure (ring's
    /// `SystemRandom` has no recoverable error path, and `RustCrypto`'s own
    /// `generate_keypair` panics on the same condition).
    #[must_use]
    pub fn generate_keypair() -> (PublicKey, SecretKey) {
        let mut seed = Zeroizing::new([0u8; 64]);
        RingRng
            .try_fill_bytes(seed.as_mut_slice())
            .expect("infallible");
        Self::keypair_from_seed(&seed)
    }

    /// Derive a keypair from the 64-byte FIPS 203 keygen seed (`d || z`).
    ///
    /// Deterministic: the same seed always yields the same keypair. This is
    /// the seed form xray's VLESS `mlkem768x25519plus` server config carries
    /// (`decryption` key segment — Go `mlkem.NewDecapsulationKey768`), so the
    /// e2e harness can derive the encapsulation key the client string must
    /// carry from the very seed the server config holds.
    #[must_use]
    pub fn keypair_from_seed(seed: &[u8; 64]) -> (PublicKey, SecretKey) {
        let dk = DecapsulationKey::<MlKem768>::from_seed(Array::from(*seed));
        let pk = Self::public_from_ek(dk.encapsulation_key());
        (pk, SecretKey(dk))
    }

    /// Encapsulate a shared secret to the given public key.
    ///
    /// Returns ([`Ciphertext`], [`SharedSecret`]) where:
    /// - [`Ciphertext`] is 1088 bytes (to be sent to the key holder)
    /// - [`SharedSecret`] is 32 bytes (the derived secret)
    ///
    /// # Errors
    /// [`MlkemError::InvalidPublicKey`] when the encapsulation key fails the
    /// FIPS 203 input check.
    pub fn encapsulate(pk: &PublicKey) -> Result<(Ciphertext, SharedSecret), MlkemError> {
        let mut ct = [0u8; 1088];
        let mut ss = Zeroizing::new([0u8; 32]);
        Self::encapsulate_into(pk, &mut ct, &mut ss)?;
        // `encapsulate_into` leaves the shared secret in a plain caller
        // buffer; the copy into `SharedSecret` wipes on its own drop.
        Ok((Ciphertext(ct), SharedSecret(*ss)))
    }

    /// Encapsulate a shared secret into caller buffers: the ciphertext
    /// lands in `ct_out`, the shared secret in `ss_out`.
    ///
    /// The allocation-free counterpart of [`Self::encapsulate`]: handshake
    /// code sealing straight into a flight buffer skips the intermediate
    /// [`Ciphertext`] copies. `ss_out` is a plain buffer (no wipe hook) —
    /// wrap it in [`Zeroizing`] when it outlives this call.
    ///
    /// # Errors
    /// [`MlkemError::InvalidPublicKey`] when the encapsulation key fails the
    /// FIPS 203 input check.
    pub fn encapsulate_into(
        pk: &PublicKey,
        ct_out: &mut [u8; 1088],
        ss_out: &mut [u8; 32],
    ) -> Result<(), MlkemError> {
        let ek = EncapsulationKey::<MlKem768>::new(&Array::from(pk.0))
            .map_err(|_| MlkemError::InvalidPublicKey)?;
        let (ct, mut ss) = ek.encapsulate_with_rng(&mut RingRng);
        ct_out.copy_from_slice(ct.as_slice());
        ss_out.copy_from_slice(ss.as_slice());
        // The array is a plain stack value in `RustCrypto`'s API; wipe it once
        // the caller's copy exists.
        ss.zeroize();
        Ok(())
    }

    /// Decapsulate a shared secret from the given ciphertext using the secret key.
    ///
    /// Returns [`SharedSecret`] (32 bytes). FIPS 203 decapsulation is total:
    /// an invalid ciphertext yields an implicit-rejection secret rather than
    /// an error, so this cannot fail.
    #[must_use]
    pub fn decapsulate(sk: &SecretKey, ct: &Ciphertext) -> SharedSecret {
        let mut shared = sk.0.decapsulate(&KemCiphertext::<MlKem768>::from(ct.0));
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(shared.as_slice());
        shared.zeroize();
        SharedSecret(*out)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_roundtrip() {
        let (pk, sk) = Mlkem768::generate_keypair();
        assert_eq!(pk.as_bytes().len(), 1184);
        assert_eq!(sk.to_seed().len(), 64);
    }

    #[test]
    fn encapsulate_decapsulate_shared_secret() {
        let (pk, sk) = Mlkem768::generate_keypair();
        let (ct, ss1) = Mlkem768::encapsulate(&pk).expect("encapsulation failed");
        let ss2 = Mlkem768::decapsulate(&sk, &ct);

        assert_eq!(ct.as_bytes().len(), 1088);
        assert_eq!(ss1.as_bytes().len(), 32);
        assert_eq!(ss2.as_bytes().len(), 32);
        assert_eq!(ss1, ss2, "shared secrets must match");
    }

    #[test]
    fn multiple_encapsulations_produce_different_ciphertexts() {
        let (pk, sk) = Mlkem768::generate_keypair();
        let (ct1, ss1) = Mlkem768::encapsulate(&pk).expect("encapsulation 1 failed");
        let (ct2, ss2) = Mlkem768::encapsulate(&pk).expect("encapsulation 2 failed");

        // Each encapsulation should produce a different ciphertext (IND-CCA2)
        assert_ne!(ct1, ct2, "ciphertexts should differ");
        // But decapsulation with the same secret key should recover the respective shared secrets
        let ss1_dec = Mlkem768::decapsulate(&sk, &ct1);
        let ss2_dec = Mlkem768::decapsulate(&sk, &ct2);
        assert_eq!(ss1, ss1_dec);
        assert_eq!(ss2, ss2_dec);
    }

    #[test]
    fn public_key_serialization() {
        let (pk, _) = Mlkem768::generate_keypair();
        let pk_bytes = pk.as_bytes();
        let pk2 = PublicKey::from_bytes(pk_bytes).expect("public key deserialization failed");
        assert_eq!(pk, pk2);
    }

    #[test]
    fn secret_key_seed_roundtrip() {
        let mut seed = [0u8; 64];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = u8::try_from(i).expect("fits u8");
        }
        let sk = SecretKey::from_seed(&seed);
        assert_eq!(sk.to_seed().as_slice(), &seed[..]);
        // Seed round-trip is key-preserving: the rebuilt key decapsulates the
        // same ciphertext to the same secret.
        let (pk, _) = Mlkem768::keypair_from_seed(&seed);
        let (ct, ss1) = Mlkem768::encapsulate(&pk).expect("encapsulation failed");
        let rebuilt = SecretKey::from_seed(sk.to_seed().as_slice().try_into().expect("64 bytes"));
        let ss2 = Mlkem768::decapsulate(&rebuilt, &ct);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn ciphertext_serialization() {
        let (pk, _) = Mlkem768::generate_keypair();
        let (ct, _) = Mlkem768::encapsulate(&pk).expect("encapsulation failed");
        let ct_bytes = ct.as_bytes();
        let ct2 = Ciphertext::from_bytes(ct_bytes).expect("ciphertext deserialization failed");
        assert_eq!(ct, ct2);
    }

    #[test]
    fn seed_keypair_is_deterministic_and_roundtrips() {
        let mut seed = [0u8; 64];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = u8::try_from(i).expect("fits u8");
        }
        let (pk1, sk1) = Mlkem768::keypair_from_seed(&seed);
        let (pk2, sk2) = Mlkem768::keypair_from_seed(&seed);
        assert_eq!(pk1.as_bytes().len(), 1184);
        assert_eq!(sk1.to_seed().len(), 64);
        assert_eq!(pk1, pk2, "same seed must yield the same encapsulation key");
        assert_eq!(sk1.to_seed(), sk2.to_seed());
        // The derived pair is a working ML-KEM-768 pair.
        let (ct, ss1) = Mlkem768::encapsulate(&pk1).expect("encapsulation failed");
        let ss2 = Mlkem768::decapsulate(&sk1, &ct);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn shared_secret_serialization() {
        let (pk, _sk) = Mlkem768::generate_keypair();
        let (_, ss) = Mlkem768::encapsulate(&pk).expect("encapsulation failed");
        let ss_bytes = ss.as_bytes();
        let ss2 = SharedSecret::from_bytes(ss_bytes).expect("shared secret deserialization failed");
        assert_eq!(ss, ss2);
    }

    #[test]
    fn invalid_public_key_length() {
        let err = PublicKey::from_bytes(&[0u8; 100]).unwrap_err();
        assert!(matches!(err, MlkemError::InvalidPublicKeyLength(100)));
    }

    #[test]
    fn invalid_ciphertext_length() {
        let err = Ciphertext::from_bytes(&[0u8; 100]).unwrap_err();
        assert!(matches!(err, MlkemError::InvalidCiphertextLength(100)));
    }

    #[test]
    fn invalid_shared_secret_length() {
        let err = SharedSecret::from_bytes(&[0u8; 100]).unwrap_err();
        assert!(matches!(err, MlkemError::InvalidSharedSecretLength(100)));
    }

    // ── migration KAT (2026-09-18): seed → encapsulation key ───────────────
    //
    // FIPS 203 `KeyGen_internal(d, z)` is deterministic, so a seed fixes the
    // encapsulation key byte-for-byte. Both constants were captured twice and
    // found identical: from the liboqs implementation this module was built on
    // before the `RustCrypto` `ml-kem` swap, and independently from Go 1.27.1's
    // stdlib `crypto/mlkem` (the peer's implementation family — xray uses
    // cloudflare/circl). This test is what proves the swap re-keys nothing: the
    // ek is the byte string a VLESS client publishes and a Go peer must accept.
    //
    // Generator (Go 1.27.1), for seed A = [0u8; 64] and seed B = 0..63:
    //     dk, err := mlkem.NewDecapsulationKey768(seed)
    //     hex.EncodeToString(dk.EncapsulationKey().Bytes())
    const KAT_SEED_A: [u8; 64] = [0; 64];
    const KAT_SEED_B: [u8; 64] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    ];
    /// Encapsulation key for [`KAT_SEED_A`], hex (1184 bytes).
    const KAT_EK_SEED_A: &str = "254a797885c63b1440aa389c65340ef33520cc039aa8d749ae7095ba8485a2444f80700741327c363a457b8538b13b6e\
        d6f13c29b232518c704e1286a74867d3aab607295d1a7483876593dce803b1fa42656cbb535531d3b76d18f930f3d19d\
        f4a02d4c6888d5596b3fb382257a41e3e252eb4865d9105e87d7888f643485f5b300bd755e2705e9d366c73786eda71d\
        10b1516461c8d1cb91cf9721498672128c935e04512e07223772b806871123b08c4059a7a75415c4ba85fd07603d3861\
        3e01b9867203c3a12a19f84efb9b8e697b3581455833cc48439533520cad13bbb01171863641b32e2231f8870e50655b\
        9c258cb547ada7d78722acce5a89cbbbdb16273c776c76a453aa7a1e93a1035094e9fb5f7909755671384141cfc2680f\
        4f7751f9a1c1dfb7b9e563581eb9752555b1ab1865a7690123664a6e560f8407bef86bc4da18c008c6864a4758bca62d\
        a5a18baa331c897b49fcb02c2b471521632f59f1cf03166862b124a1ac3581f3bf8a351ec79c87428463364b0b3bd15d\
        359760d9ab8fabb17be9078741a1a29afc5aa478772ecb3e33e0b081195c12e5c159434d29bc29ab120d6d184e116846\
        da879b6bf8a9b96702612613a9aa214e4ba2b7b1ba7fb408d1541d8983b50a0cbb4e08467f3572c49b4dc82aa4a11aa2\
        6a850970689b4ee9aa9487b60ed65362571785b44c3dec3282b9897843a68c437a2c381b66095fff79597ff107cdcb18\
        13b100eda23dbdf6a239f404b48a57da66234ba7c070f569f0f8b9e125ac888707f1707d2b4562893a27e4dc5ba91b72\
        b65b7357ba5c3c339fea9c3e78b421f431c314421e51176834e59e2b899a99c38e484792d3bc2873e87842d3c55f684a\
        4a940c6a63a2a168a3eb3368fbe83f8de53524e787c182421ab28617b120d00978111bb58e01b0efb463d3eb769fc66e\
        4a59b94af6a7abe454e960ae3e0b3b4e6b913bb73ffc7b2b345377b9251bc6613a74d01877541b8cc3138f299a6f2728\
        aaeb89c5d208a3471f71a8864a9bcc530580251a6741535a62d8a0e171812bf98846a2840570499db41932640488487b\
        108c72d42b7a7dc544b971a32fda8066769cb4700905e2265b7a4370d8c03ee27f8c1976a499c134c82512413778f884\
        b1771a9e7987321890c64aa19cd78f4d1923f5949448048fa5e7135a9343db6691e6b18056779044667115fbc1443b6e\
        74a923279586cf27629ae285ca100e1062ccf56c96b9d720eda92e81b8ae1994a508588a50330f73d46f998199f73870\
        1146a4ddb41e785c988fc51eb71b8e49275b7f7ba5e59300ae12ca0fd152d039c76df0526ce34dbeaba17d11a6b0060c\
        a61401cec35fe9b175e27517a41c4b8a07056fc10ec6f62677f62b76840bd91a9520c4a819c83d80430941247a596462\
        96ccbea7dc1ab30170de38624e8a33b4c2ba2dc97bf73a71d9ac35a480a83f1bb1e1c4777409d0a065782a1a707b068d\
        4bf2205101202fcbc71ab94b2929cb44e2c547ec10b5a72d8c8759fb2920adc80b85713975414b7b20b983e848d3a0c3\
        bc433bbf26b700a1a40322a84de5c87eb9877ad68abe9886f7db6989964002ea566cc616463b17e0e783e5a96217a200\
        6d3ae406763c50457d1481402aafc7e23f43f9d1d7c0af7060ac1daa9ecb0e67";
    /// Encapsulation key for [`KAT_SEED_B`], hex (1184 bytes).
    const KAT_EK_SEED_B: &str = "298aa10d423c8dda069d02bc59e6cdf03a096b8b3da4cab9b80ca4a14907672ccef1ec4faf234a0bc5b7e9d473f2b313\
        3b3b26a1d175cb67a7805919699c02f76531b99c5f89180704bb4ca4535c5b8972679c660a07c5e514b87009c862eb8f\
        5157695efb3fc40a9def6b81c1cc02a249ae4f094ad0d9bd3485c1c1c68080520a7c8c632032cee738154e5c5176c07d\
        a56024776a430fe76eacf665a3f7b832102215bc82f10939c8355704336a8fac1d81e4bb0485aa5d7c74d6b59bbe5c5e\
        972a0d8bac411b55b5d5557cd680a1a8f71b4eb86bc48c9a0509731a54bd9d7290b27963e4372dc9b199cfdcac0b01ac\
        d28a62395112e4c43648d622c48c8234d01440e8cc376c927f23a5afc9ac0474c662274e424525c8552ece3b3fe26516\
        de901bc7d515bde89558e626c95c80b93342f8010004f39e6c6c94871c5e344cab3966c835f9a96a59afd31c40286b38\
        b1c1a78470bab947518934453ce86736a919f1f5a6d510a86f5454fc3980cb5c765bd2bd5f7b36b1410d6635c8ceb47c\
        4dda0d76a28eac939c71c3024804866c71626658442163c2c22117e50acefce6378a985652302a4ef0c2ce0cc716b779\
        6e2b6b2e3777dfa1ac3da259a31b5a9b530f8cb638a81a62ac301849abaf95a7301bda30068909bfdb7e67dbccbb38a5\
        551a25b1a3a0f685748ad5753d8880f0016c627486166384c5571fe2365900364d038311e2d875db366686932b5ec602\
        430a369e87a6ef5c338786657825bd4c057aceb923eb0935e6905e63b4ced7f80857a773dd64b150d26612ea9ac12052\
        db2017bf1843ccb4b3281b690dc728adfa85c00281b8e3c09287335f856b4fc2892f69a2f57921ada01914c40988662d\
        57769662a786351b9b66493dab79594d986de2100d65ba0ff4ea58b81538d24a4435a258fac25404aa7f41f658b13850\
        65e158dcb60115732720f40459aaac15e406953a90ac52997d1ccd070060efc65db9e653354467fad56ec713c86e7540\
        c423acf2669f52fa6f4ac6888d871ef3e847c029a8aafbb92e17b24aa079b1f419ba6175b442afb11909d4a56b70a033\
        5b28739218aa7c9348e2c3c2f3eb3d15a41e6417c0dd94bfeb21419b311a7bb13a180bbe833218a9a6b17447cc85f225\
        859587a73077049acbcfd44d0f025438e15d1538270d586e1bf83192a9459cf63c0e972f85297679831ecf121509851c\
        b8340f6f107b0fa1a0efd1b36a8189bc085c4f5cb784e553f41b918f80397ce1956f785bee377ca9aa8be6998ada30c2\
        6b7c3d8c6b55254cc96203b20c42aee0ac4e1ebb408e49a9e3f879d0ab0785eb7025425d1305a2299c015e120d163b0e\
        19494ce57253d0246d182745cb8197ab7438b3c1bb7972bec5a306eba3567855c014699fef65ae54c770a0d85c18400c\
        f642aedc660777ba4b138502bd5a7812f621f84a48296b98dd4322b6f15828b8a8f0e00a8ba44a53c3a8b143571b0740\
        abd567daf1cde9c79c204b6d5e259d1766a31bbbcb4e6a05cf4502176b301c1c2f41247750157bcec85e809b30a4d60d\
        7747cdd0f5b99aa8c826987517793aaa8080a0b124a8558df72bbe37b75f4edbb6be8216d6c633fb2b2280e25113d869\
        5e43481c3eeb397eb192505229b67a201ea893c3e2cb32da8bc342fa4dea0578";

    fn hex_encode(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            write!(out, "{b:02x}").expect("string write");
        }
        out
    }

    #[test]
    fn mlkem768_seed_derivation_matches_liboqs_and_go_stdlib() {
        for (seed, expected) in [(&KAT_SEED_A, KAT_EK_SEED_A), (&KAT_SEED_B, KAT_EK_SEED_B)] {
            let (ek, _) = Mlkem768::keypair_from_seed(seed);
            assert_eq!(ek.as_bytes().len(), 1184);
            assert_eq!(
                hex_encode(ek.as_bytes()),
                expected,
                "seed→ek derivation drifted from the pinned vectors"
            );
        }
    }
}
