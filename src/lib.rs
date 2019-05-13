pub mod ec_vrf {
    extern crate rand_os;
    extern crate curve25519_dalek;
    extern crate sha3;
    use rand_os::OsRng;
    use sha3::{Digest, Sha3_256 as SHA3};
    use curve25519_dalek::scalar::{Scalar};
    pub mod curve25519 {
        use super::*;
        use curve25519_dalek::edwards::{EdwardsPoint};
        use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as g;
        type EcPoint = EdwardsPoint;
        pub struct VrfProof {
            gamma: EcPoint,
            c: [u8; 32],
            s: Scalar
        }
        fn sha3(b: Vec<u8>) -> [u8; 32] {
            let mut hasher = SHA3::default();
            hasher.input(b);
            let r = hasher.result();
            let mut ret = [0 as u8; 32];
            for i in 0..r.len() {
                ret[i] = r[i];
            }
            ret
        }
        fn hash_to_point(b: Vec<u8>) -> EcPoint {
            let hash = sha3(b);
            let s = Scalar::from_bytes_mod_order(hash);
            return g*s
        }
        fn serialize_point(p: EcPoint) -> [u8; 32] {
            return p.to_montgomery().to_bytes();
        }
        pub fn prove(input: &Vec<u8>, privkey: Scalar) -> 
            ([u8; 32], VrfProof) {
                let h = hash_to_point(input.to_vec());
                let gamma = h*privkey;
                let mut csprng: OsRng = OsRng::new().unwrap();
                let k: Scalar = Scalar::random(&mut csprng);
                let mut hasher = SHA3::default();
                hasher.input(serialize_point(g));
                hasher.input(serialize_point(h));
                hasher.input(serialize_point(g*privkey));
                hasher.input(serialize_point(h*privkey));
                hasher.input(serialize_point(g*k));
                hasher.input(serialize_point(h*k));
                let mut c = [0 as u8; 32];
                let hres = hasher.result();
                for i in 0..hres.len() {
                    c[i] = hres[i];
                }
                let c_scalar = Scalar::from_bytes_mod_order(c);
                let s = k - c_scalar*privkey;
                let beta = sha3(serialize_point(gamma).to_vec());
                (beta, VrfProof {gamma: gamma, c: c, s: s})
            }

        pub fn verify(input: &Vec<u8>, pubkey: EcPoint, output: [u8; 32], 
                      proof: VrfProof) -> bool {
            let c_scalar = Scalar::from_bytes_mod_order(proof.c);
            let u = pubkey*c_scalar + g*proof.s;
            let h = hash_to_point(input.to_vec());
            let v = proof.gamma*c_scalar + h*proof.s;

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
            sha3(serialize_point(proof.gamma).to_vec()) == output &&
                local_c == proof.c
        }
    }
    pub mod ristretto {
        use super::*;
        use curve25519_dalek::ristretto::{RistrettoPoint};
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as g;
        type EcPoint = RistrettoPoint;
        pub struct VrfProof {
            gamma: EcPoint,
            c: [u8; 32],
            s: Scalar
        }
        fn sha3(b: Vec<u8>) -> [u8; 32] {
            let mut hasher = SHA3::default();
            hasher.input(b);
            let r = hasher.result();
            let mut ret = [0 as u8; 32];
            for i in 0..r.len() {
                ret[i] = r[i];
            }
            ret
        }
        fn hash_to_point(b: Vec<u8>) -> EcPoint {
            let hash = sha3(b);
            let s = Scalar::from_bytes_mod_order(hash);
            return g*s
        }
        fn serialize_point(p: EcPoint) -> [u8; 32] {
            return p.compress().to_bytes();
        }
        pub fn prove(input: &Vec<u8>, privkey: Scalar) -> 
            ([u8; 32], VrfProof) {
                let h = hash_to_point(input.to_vec());
                let gamma = h*privkey;
                let mut csprng: OsRng = OsRng::new().unwrap();
                let k: Scalar = Scalar::random(&mut csprng);
                let mut hasher = SHA3::default();
                hasher.input(serialize_point(g));
                hasher.input(serialize_point(h));
                hasher.input(serialize_point(g*privkey));
                hasher.input(serialize_point(h*privkey));
                hasher.input(serialize_point(g*k));
                hasher.input(serialize_point(h*k));
                let mut c = [0 as u8; 32];
                let hres = hasher.result();
                for i in 0..hres.len() {
                    c[i] = hres[i];
                }
                let c_scalar = Scalar::from_bytes_mod_order(c);
                let s = k - c_scalar*privkey;
                let beta = sha3(serialize_point(gamma).to_vec());
                (beta, VrfProof {gamma: gamma, c: c, s: s})
            }

        pub fn verify(input: &Vec<u8>, pubkey: EcPoint, output: [u8; 32], 
                      proof: VrfProof) -> bool {
            let c_scalar = Scalar::from_bytes_mod_order(proof.c);
            let u = pubkey*c_scalar + g*proof.s;
            let h = hash_to_point(input.to_vec());
            let v = proof.gamma*c_scalar + h*proof.s;

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
            sha3(serialize_point(proof.gamma).to_vec()) == output &&
                local_c == proof.c
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate rand_os;
    use curve25519_dalek::scalar::{Scalar};
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as g;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as rg;
    use rand_os::OsRng;
    use super::*;

    #[test]
    fn curve25519() {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let privkey: Scalar = Scalar::random(&mut csprng);
        let pubkey = g*privkey;
        let input = vec![1,2,3,4,5,6,7,8];
        let (output, proof) = ec_vrf::curve25519::prove(&input, privkey);
        assert!(ec_vrf::curve25519::verify(&input, pubkey, output, proof));
    }

    #[test]
    fn ristretto() {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let privkey: Scalar = Scalar::random(&mut csprng);
        let pubkey = rg*privkey;
        let input = vec![1,2,3,4,5,6,7,8];
        let (output, proof) = ec_vrf::ristretto::prove(&input, privkey);
        assert!(ec_vrf::ristretto::verify(&input, pubkey, output, proof));
    }
}
