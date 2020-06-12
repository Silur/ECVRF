pub use rand_os::OsRng;
pub use sha3::{Digest, Sha3_256 as SHA3};
pub use curve25519_dalek::scalar::Scalar;
pub use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
pub use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
pub use curve25519_dalek::ristretto::RistrettoPoint;
pub use curve25519_dalek::edwards::EdwardsPoint;

pub fn sha3(b: Vec<u8>) -> [u8; 32] {
    let mut hasher = SHA3::default();
    hasher.input(b);
    let r = hasher.result();
    let mut ret = [0 as u8; 32];
    for i in 0..r.len() {
        ret[i] = r[i];
    }
    ret
}

pub mod curve25519 {
    pub use super::*;
    pub use super::ED25519_BASEPOINT_POINT as g;
    pub type EcPoint = EdwardsPoint;
    pub struct VrfProof {
        gamma: EcPoint,
        c: [u8; 32],
        s: Scalar,
    }
    fn hash_to_point(b: Vec<u8>) -> EcPoint {
        let hash = sha3(b);
        let s = Scalar::from_bytes_mod_order(hash);
        g * s
    }
    fn serialize_point(p: EcPoint) -> [u8; 32] {
        p.to_montgomery().to_bytes()
    }
    pub fn prove(input: &[u8], privkey: &Scalar) -> ([u8; 32], VrfProof) {
        let h = hash_to_point(input.to_vec());
        let gamma = h * privkey;
        let mut csprng: OsRng = OsRng::new().unwrap();
        let k: Scalar = Scalar::random(&mut csprng);
        let mut hasher = SHA3::default();
        hasher.input(serialize_point(g));
        hasher.input(serialize_point(h));
        hasher.input(serialize_point(g * privkey));
        hasher.input(serialize_point(h * privkey));
        hasher.input(serialize_point(g * k));
        hasher.input(serialize_point(h * k));
        let mut c = [0 as u8; 32];
        let hres = hasher.result();
        for i in 0..hres.len() {
            c[i] = hres[i];
        }
        let c_scalar = Scalar::from_bytes_mod_order(c);
        let s = k - c_scalar * privkey;
        let beta = sha3(serialize_point(gamma).to_vec());
        (beta, VrfProof { gamma, c, s })
    }

    pub fn verify(input: &[u8], pubkey: &EcPoint, output: &[u8; 32], proof: &VrfProof) -> bool {
        let c_scalar = Scalar::from_bytes_mod_order(proof.c);
        let u = pubkey * c_scalar + g * proof.s;
        let h = hash_to_point(input.to_vec());
        let v = proof.gamma * c_scalar + h * proof.s;

        let mut hasher = SHA3::default();
        hasher.input(serialize_point(g));
        hasher.input(serialize_point(h));
        hasher.input(serialize_point(*pubkey));
        hasher.input(serialize_point(proof.gamma));
        hasher.input(serialize_point(u));
        hasher.input(serialize_point(v));
        let mut local_c = [0 as u8; 32];
        let hres = hasher.result();
        for i in 0..hres.len() {
            local_c[i] = hres[i];
        }
        sha3(serialize_point(proof.gamma).to_vec()) == *output && local_c == proof.c
    }
}
pub mod ristretto {
    pub use super::*;
    pub use super::RISTRETTO_BASEPOINT_POINT as g;
    pub use curve25519_dalek::ristretto::CompressedRistretto;
    pub type EcPoint = RistrettoPoint;
    pub struct VrfProof {
        gamma: EcPoint,
        c: [u8; 32],
        s: Scalar,
    }
    impl VrfProof{
        pub fn to_bytes(&self) -> [u8;96]{
            let mut ret = [0;96];
            let gamma = self.gamma.compress().to_bytes();
            let c = self.c;
            let s = self.s.to_bytes();
            for i in 0..31{
                ret[i]=gamma[i];
                ret[32+i]=c[i];
                ret[64+i]=s[i];
            }
            ret
        }

        pub fn from_slices(gamma : [u8;32], c : [u8;32], s : [u8;32]) -> VrfProof{
            VrfProof{
                gamma : CompressedRistretto::from_slice(&gamma).decompress().expect("invalid compressed RisrettoPoint"),
                c : c,
                s : Scalar::from_bytes_mod_order(s)
            }
        }

        pub fn from_bytes(input : [u8;96]) -> VrfProof{
            let mut gamma : [u8;32]=[0;32];
            let mut c : [u8;32]=[0;32];
            let mut s : [u8;32]=[0;32];
            gamma.copy_from_slice(&input[0..31]); 
            c.copy_from_slice(&input[32..63]); 
            s.copy_from_slice(&input[64..95]); 
            VrfProof::from_slices(gamma,c,s)
        }

    }

    fn hash_to_point(b: Vec<u8>) -> EcPoint {
        let hash = sha3(b);
        let s = Scalar::from_bytes_mod_order(hash);
        g * s
    }
    fn serialize_point(p: EcPoint) -> [u8; 32] {
        p.compress().to_bytes()
    }
    pub fn prove(input: &[u8], privkey: &Scalar) -> ([u8; 32], VrfProof) {
        let privkey = privkey.clone();
        let h = hash_to_point(input.to_vec());
        let gamma = h * privkey;
        let mut csprng: OsRng = OsRng::new().unwrap();
        let k: Scalar = Scalar::random(&mut csprng);
        let mut hasher = SHA3::default();
        hasher.input(serialize_point(g));
        hasher.input(serialize_point(h));
        hasher.input(serialize_point(g * privkey));
        hasher.input(serialize_point(h * privkey));
        hasher.input(serialize_point(g * k));
        hasher.input(serialize_point(h * k));
        let mut c = [0 as u8; 32];
        let hres = hasher.result();
        for i in 0..hres.len() {
            c[i] = hres[i];
        }
        let c_scalar = Scalar::from_bytes_mod_order(c);
        let s = k - c_scalar * privkey;
        let beta = sha3(serialize_point(gamma).to_vec());
        (beta, VrfProof { gamma, c, s })
    }

    pub fn verify(input: &[u8], pubkey: EcPoint, output: [u8; 32], proof: VrfProof) -> bool {
        let c_scalar = Scalar::from_bytes_mod_order(proof.c);
        let u = pubkey * c_scalar + g * proof.s;
        let h = hash_to_point(input.to_vec());
        let v = proof.gamma * c_scalar + h * proof.s;

        let mut hasher = SHA3::default();
        hasher.input(serialize_point(g));
        hasher.input(serialize_point(h));
        hasher.input(serialize_point(pubkey));
        hasher.input(serialize_point(proof.gamma));
        hasher.input(serialize_point(u));
        hasher.input(serialize_point(v));
        let mut local_c = [0 as u8; 32];
        let hres = hasher.result();
        for i in 0..hres.len() {
            local_c[i] = hres[i];
        }
        sha3(serialize_point(proof.gamma).to_vec()) == output && local_c == proof.c
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as g;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as rg;
    use curve25519_dalek::scalar::Scalar;
    use rand_os::OsRng;

    #[test]
    fn curve25519() {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let privkey: Scalar = Scalar::random(&mut csprng);
        let pubkey = g * privkey;
        let input = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let (output, proof) = curve25519::prove(&input, &privkey);
        assert!(curve25519::verify(&input, &pubkey, &output, &proof));
    }
 /*   #[bench]
    fn bench_curve25519(b: &mut Bencher) {
        b.iter(|| curve25519());
    } */
    #[test]
    fn ristretto() {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let privkey: Scalar = Scalar::random(&mut csprng);
        let pubkey = rg * privkey;
        let input = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let (output, proof) = ristretto::prove(&input, &privkey);
        assert!(ristretto::verify(&input, pubkey, output, proof));
    }
}
