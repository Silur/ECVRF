pub mod ec_vrf {
    extern crate rand_os;
    extern crate curve25519_dalek;
    extern crate sha3;
    use curve25519_dalek::scalar::{Scalar};
    use curve25519_dalek::edwards::{EdwardsPoint};
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as g;
    use rand_os::OsRng;
    use sha3::{Digest, Sha3_256 as SHA3};
    pub struct VrfProof {
        gamma: EdwardsPoint,
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
    fn hash_to_point(b: Vec<u8>) -> EdwardsPoint {
        let hash = sha3(b);
        let s = Scalar::from_bytes_mod_order(hash);
        g*s
    }
    pub fn prove(input: &Vec<u8>, privkey: Scalar) -> 
        ([u8; 32], VrfProof) {
        let h = hash_to_point(input.to_vec());
        let gamma = h*privkey;
        let mut csprng: OsRng = OsRng::new().unwrap();
        let k: Scalar = Scalar::random(&mut csprng);
        let mut hasher = SHA3::default();
        hasher.input(g.to_montgomery().to_bytes());
        hasher.input(h.to_montgomery().to_bytes());
        hasher.input((g*privkey).to_montgomery().to_bytes());
        hasher.input((h*privkey).to_montgomery().to_bytes());
        hasher.input((g*k).to_montgomery().to_bytes());
        hasher.input((h*k).to_montgomery().to_bytes());
        let mut c = [0 as u8; 32];
        let hres = hasher.result();
        for i in 0..hres.len() {
            c[i] = hres[i];
        }
        let c_scalar = Scalar::from_bytes_mod_order(c);
        let s = k - c_scalar*privkey;
        let beta = sha3(gamma.to_montgomery().to_bytes().to_vec());
        (beta, VrfProof {gamma: gamma, c: c, s: s})
    }

    pub fn verify(input: &Vec<u8>, pubkey: EdwardsPoint, output: [u8; 32], 
                  proof: VrfProof) -> bool {
        let c_scalar = Scalar::from_bytes_mod_order(proof.c);
        let u = pubkey*c_scalar + g*proof.s;
        let h = hash_to_point(input.to_vec());
        let v = proof.gamma*c_scalar + h*proof.s;
        
        let mut hasher = SHA3::default();
        hasher.input(g.to_montgomery().to_bytes());
        hasher.input(h.to_montgomery().to_bytes());
        hasher.input(pubkey.to_montgomery().to_bytes());
        hasher.input(proof.gamma.to_montgomery().to_bytes());
        hasher.input(u.to_montgomery().to_bytes());
        hasher.input(v.to_montgomery().to_bytes());
        let mut local_c = [0 as u8; 32];
        let hres = hasher.result();
        for i in 0..hres.len() {
            local_c[i] = hres[i];
        }
        sha3(proof.gamma.to_montgomery().to_bytes().to_vec()) == output &&
            local_c == proof.c
    }
}

#[cfg(test)]
mod tests {
    extern crate rand_os;
    use curve25519_dalek::scalar::{Scalar};
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as g;
    use rand_os::OsRng;
    use super::*;

    #[test]
    fn it_works() {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let privkey: Scalar = Scalar::random(&mut csprng);
        let pubkey = g*privkey;
        let input = vec![1,2,3,4,5,6,7,8];
        let (output, proof) = ec_vrf::prove(&input, privkey);
        assert!(ec_vrf::verify(&input, pubkey, output, proof));
    }
}
