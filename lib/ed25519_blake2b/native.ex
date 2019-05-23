defmodule Ed25519Blake2b.Native do
  use Rustler, otp_app: :ed25519_blake2b, crate: :ed25519blake2b

  @spec derive_public_key(binary()) :: {:ok, binary()} | {:error, :invalid_secret_key}
  def derive_public_key(_secret_key), do: :erlang.nif_error(:nif_not_loaded)

  @spec sign(binary(), binary()) :: {:ok, binary()} | {:error, :invalid_keypair}
  def sign(_keypair, _message), do: :erlang.nif_error(:nif_not_loaded)

  @spec verify(binary(), binary(), binary()) ::
          :ok | {:error, :invalid_public_key | :invalid_signature}
  def verify(_message, _signature, _public_key), do: :erlang.nif_error(:nif_not_loaded)

  @spec verify_batch([binary()], [binary()], [binary()]) ::
          :ok | {:error, :invalid_public_key | :invalid_signature}
  def verify_batch(_messages, _signatures, _public_keys), do: :erlang.nif_error(:nif_not_loaded)

  @spec hash(binary(), pos_integer()) :: binary()
  def hash(_message, _digest_size), do: :erlang.nif_error(:nif_not_loaded)
end
