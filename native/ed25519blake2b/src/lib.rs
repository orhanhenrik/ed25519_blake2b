#[macro_use]
extern crate rustler;
// #[macro_use]
extern crate rustler_codegen;
// #[macro_use]
extern crate blake2;
extern crate ed25519_dalek;
extern crate lazy_static;

use blake2::digest::{Input, VariableOutput};
use blake2::Blake2b;
use blake2::VarBlake2b;
use ed25519_dalek::{verify_batch, Keypair, PublicKey, SecretKey, Signature};
use rustler::schedule::SchedulerFlags;
use rustler::types::binary::{Binary, OwnedBinary};
use rustler::types::list::ListIterator;
use rustler::{Encoder, Env, NifResult, Term};
use std::io::Write;

mod atoms {
    rustler_atoms! {
        atom ok;
        atom error;
        //atom __true__ = "true";
        //atom __false__ = "false";

        // ERRORS
        atom invalid_secret_key;
        atom invalid_public_key;
        atom invalid_keypair;
        atom invalid_signature;
        atom invalid_message;
    }
}

rustler_export_nifs! {
    "Elixir.Ed25519Blake2b.Native",
    [
        ("derive_public_key", 1, derive_public_key),
        ("sign", 2, sign),
        ("verify", 3, verify),
        ("verify_batch", 3, verify_batch_nif, SchedulerFlags::DirtyCpu),
        ("hash", 2, hash)
    ],
    None
}

fn derive_public_key<'a>(env: Env<'a>, args: &[Term<'a>]) -> NifResult<Term<'a>> {
    let secret_key_bytes = args[0].decode::<Binary>()?.as_slice();

    let secret_key: SecretKey = match SecretKey::from_bytes(secret_key_bytes) {
        Err(_) => return Ok((atoms::error(), atoms::invalid_secret_key()).encode(env)),
        Ok(r) => r,
    };

    let public_key: PublicKey = PublicKey::from_secret::<Blake2b>(&secret_key);

    let result = public_key.to_bytes();

    let mut bin = OwnedBinary::new(result.len()).unwrap();
    bin.as_mut_slice().write(&result).unwrap();

    Ok((atoms::ok(), bin.release(env)).encode(env))
}

fn sign<'a>(env: Env<'a>, args: &[Term<'a>]) -> NifResult<Term<'a>> {
    let key_bytes = args[0].decode::<Binary>()?.as_slice();
    let message = args[1].decode::<Binary>()?.as_slice();

    let keypair: Keypair = match Keypair::from_bytes(key_bytes) {
        Err(_) => return Ok((atoms::error(), atoms::invalid_keypair()).encode(env)),
        Ok(r) => r,
    };

    let sig: Signature = keypair.sign::<Blake2b>(&message);
    let result = sig.to_bytes();

    let mut bin = OwnedBinary::new(result.len()).unwrap();
    bin.as_mut_slice().write(&result).unwrap();

    Ok((atoms::ok(), bin.release(env)).encode(env))
}

fn verify<'a>(env: Env<'a>, args: &[Term<'a>]) -> NifResult<Term<'a>> {
    let message: &[u8] = args[0].decode::<Binary>()?.as_slice();
    let signature_bytes: &[u8] = args[1].decode::<Binary>()?.as_slice();
    let public_key_bytes: &[u8] = args[2].decode::<Binary>()?.as_slice();

    let public_key: PublicKey = match PublicKey::from_bytes(public_key_bytes) {
        Err(_) => return Ok((atoms::error(), atoms::invalid_public_key()).encode(env)),
        Ok(r) => r,
    };
    let signature: Signature = match Signature::from_bytes(signature_bytes) {
        Err(_) => return Ok((atoms::error(), atoms::invalid_signature()).encode(env)),
        Ok(r) => r,
    };

    match public_key.verify::<Blake2b>(message, &signature) {
        Err(_) => Ok((atoms::error(), atoms::invalid_signature()).encode(env)),
        Ok(_) => Ok(atoms::ok().encode(env)),
    }
}

fn verify_batch_nif<'a>(env: Env<'a>, args: &[Term<'a>]) -> NifResult<Term<'a>> {
    let message_iter: ListIterator = args[0].decode()?;
    let sig_iter: ListIterator = args[1].decode()?;
    let pk_iter: ListIterator = args[2].decode()?;

    let messages: Vec<&[u8]> = message_iter
        .map(|x| x.decode::<Binary>())
        .collect::<NifResult<Vec<Binary>>>()?
        .iter()
        .map(|x| x.as_slice())
        .collect::<Vec<&[u8]>>();

    let pk_result: Result<Vec<PublicKey>, _> = pk_iter
        .map(|x| x.decode::<Binary>())
        .collect::<NifResult<Vec<Binary>>>()?
        .iter()
        .map(|x| PublicKey::from_bytes(x.as_slice()))
        .collect::<Result<Vec<PublicKey>, _>>();

    let public_keys: Vec<PublicKey> = match pk_result {
        Err(_) => return Ok((atoms::error(), atoms::invalid_public_key()).encode(env)),
        Ok(r) => r,
    };
    let sig_result: Result<Vec<Signature>, _> = sig_iter
        .map(|x| x.decode::<Binary>())
        .collect::<NifResult<Vec<Binary>>>()?
        .iter()
        .map(|x| Signature::from_bytes(x.as_slice()))
        .collect::<Result<Vec<Signature>, _>>();

    let signatures: Vec<Signature> = match sig_result {
        Err(_) => return Ok((atoms::error(), atoms::invalid_signature()).encode(env)),
        Ok(r) => r,
    };

    match verify_batch::<Blake2b>(&messages[..], &signatures[..], &public_keys[..]) {
        Err(_) => return Ok((atoms::error(), atoms::invalid_signature()).encode(env)),
        Ok(_) => return Ok(atoms::ok().encode(env)),
    };
}

fn hash<'a>(env: Env<'a>, args: &[Term<'a>]) -> NifResult<Term<'a>> {
    let message = args[0].decode::<Binary>()?.as_slice();
    let digest_size = args[1].decode::<usize>()?;

    let mut hasher = VarBlake2b::new(digest_size).unwrap();
    hasher.input(message);
    let result = hasher.vec_result();
    let mut bin = OwnedBinary::new(result.len()).unwrap();
    bin.as_mut_slice().write(&result).unwrap();

    return Ok(bin.release(env).encode(env));
}
