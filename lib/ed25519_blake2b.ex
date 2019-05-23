defmodule Ed25519Blake2b do
  @moduledoc """
  This module is a Rustler NIF to work with ed25519 signatures that use the blake2b hash function instead of the default sha2 hash.
  """

  @type secret_key :: <<_::256>>
  @type public_key :: <<_::256>>
  @typedoc """
  Keypair is secret_key concatenated with public key: `secret_key<>public_key`
  """
  @type keypair :: <<_::512>>
  @type signature :: <<_::512>>

  @doc """
  Derives a public key from the given secret key

  ## Examples
    iex> secret_key = <<0::size(256)>>
    iex> Ed25519Blake2b.derive_public_key(secret_key)
    {:ok, <<25, 211, 217, 25, 71, 93, 238, 212, 105, 107, 93, 19, 1, 129, 81, 209, 175,
      136, 178, 189, 59, 207, 240, 72, 180, 80, 49, 193, 243, 109, 24, 88>>}
  """
  @spec derive_public_key(secret_key()) :: {:ok, public_key()} | {:error, :invalid_secret_key}
  defdelegate derive_public_key(secret_key), to: Ed25519Blake2b.Native

  @doc """
  Signs a message with the given keypair. If one only has the secret key available, use derive_public_key/1 to get the public key.

  ## Examples
    iex> secret_key = <<0::size(256)>>
    iex> {:ok, public_key} = Ed25519Blake2b.derive_public_key(secret_key)
    iex> Ed25519Blake2b.sign(secret_key<>public_key, <<1,2,3>>)
    {:ok, <<243, 9, 109, 70, 37, 126, 5, 16, 109, 224, 98, 241, 73, 133, 99, 45, 129, 124,
      203, 148, 20, 11, 163, 171, 84, 107, 144, 194, 34, 12, 21, 11, 222, 17, 36,
      206, 253, 136, 26, 169, 153, 90, 49, 179, 160, 248, 248, 45, 63, 111, 181, 6,
      241, 254, 48, 185, 6, 190, 205, 135, 205, 23, 121, 1>>}
  """
  @spec sign(keypair(), binary()) :: {:ok, signature()} | {:error, :invalid_keypair}
  defdelegate sign(keypair, message), to: Ed25519Blake2b.Native

  @doc """
  Verifies that the signature is valid for the given message and public key.

  ## Examples
    iex> secret_key = <<0::size(256)>>
    iex> {:ok, public_key} = Ed25519Blake2b.derive_public_key(secret_key)
    iex> {:ok, signature} = Ed25519Blake2b.sign(secret_key<>public_key, <<1,2,3>>)
    iex> Ed25519Blake2b.verify(<<1,2,3>>, signature, public_key)
    :ok
    iex> Ed25519Blake2b.verify(<<3,2,1>>, signature, public_key)
    {:error, :invalid_signature}
  """
  @spec verify(binary(), signature(), public_key()) ::
          :ok | {:error, :invalid_public_key | :invalid_signature}
  defdelegate verify(message, signature, public_key), to: Ed25519Blake2b.Native

  @doc """
  Verifies that the signatures are valid for the given messages and public keys.
  The length of each input list should be equal. Each signature will be verified against the message and public key at the corresponding index.
  The function will return an error if any signature is invalid.

  ## Examples
    iex> sk1 = <<0::size(256)>>
    iex> sk2 = <<1::size(256)>>
    iex> {:ok, pk1} = Ed25519Blake2b.derive_public_key(sk1)
    iex> {:ok, pk2} = Ed25519Blake2b.derive_public_key(sk2)
    iex> msg1 = <<1,2,3>>
    iex> msg2 = <<1,2,3,4,5,6,7,8>>
    iex> {:ok, sig1} = Ed25519Blake2b.sign(sk1<>pk1, msg1)
    iex> {:ok, sig2} = Ed25519Blake2b.sign(sk2<>pk2, msg2)
    iex> Ed25519Blake2b.verify_batch([msg1, msg2], [sig1, sig2], [pk1, pk2])
    :ok
    iex> Ed25519Blake2b.verify_batch([msg1, msg2, msg2], [sig1, sig2, sig2], [pk1, pk2, pk1])
    {:error, :invalid_signature}
  """
  @spec verify_batch([binary()], [signature()], [public_key()]) ::
          :ok | {:error, :invalid_public_key | :invalid_signature}
  defdelegate verify_batch(messages, signatures, public_keys), to: Ed25519Blake2b.Native
end
