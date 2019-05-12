# ECVRF

VRFs (Verifiable random functions) are great tools in decentralized systems because they can introduce random oracles into a protocol without the fear of data manipulation from a trusted party. These oracle functions are proven to be as hard to manipulate as breaking a particular cryptographic trapdoor. 

See more in Micali's groundbreaking publication: https://people.csail.mit.edu/silvio/Selected%20Scientific%20Papers/Pseudo%20Randomness/Verifiable_Random_Functions.pdf

This elliptic curve instantiation was originally subject to exhaustive research in order to improve DNSSEC and proven to have the Trusted Uniqueness and Selective Pseudorandomness properties: https://eprint.iacr.org/2014/905.pdf

## Usage

```rust
    extern crate rand_os;
    use curve25519_dalek::scalar::{Scalar};
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as g;
    use rand_os::OsRng;
    use ec_vrf::{prove, verify};

   
    fn main() {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let privkey: Scalar = Scalar::random(&mut csprng);
        let pubkey = g*privkey;
        let input = vec![1,2,3,4,5,6,7,8];
        let (output, proof) = ec_vrf::prove(&input, privkey);
        assert!(ec_vrf::verify(&input, pubkey, output, proof));
    }
}

```



## Disclaimer

This distribution includes cryptographic software. The country in which you currently reside may have restrictions on the import, possession, use, and/or re-export to another country, of encryption software. BEFORE using any encryption software, please check your country's laws, regulations and policies concerning the import, possession, or use, and 
re-export of encryption software, to see if this is permitted. See <http://www.wassenaar.org/> for more information.