msg1 = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10>>
msg2 = msg1 <> msg1 <> msg1 <> msg1 <> msg1 <> msg1 <> msg1 <> msg1 <> msg1 <> msg1

sk = <<123::size(256)>>
{:ok, pk} = Ed25519Blake2b.derive_public_key(sk)
keypair = sk <> pk

{:ok, sig1} = Ed25519Blake2b.sign(keypair, msg1)

Benchee.run(%{
  :derive_public_key => fn ->
    {:ok, public} = Ed25519Blake2b.derive_public_key(sk)
  end,
  :sign_10_bytes => fn ->
    {:ok, sig} = Ed25519Blake2b.sign(keypair, msg1)
  end,
  :sign_100_bytes => fn ->
    {:ok, sig} = Ed25519Blake2b.sign(keypair, msg2)
  end,
  :verify => fn ->
    :ok = Ed25519Blake2b.verify(msg1, sig1, pk)
  end,
  :verify_64x => fn ->
    msgs = for _ <- 1..64, do: msg1
    sigs = for _ <- 1..64, do: sig1
    pks = for _ <- 1..64, do: pk
    :ok = Ed25519Blake2b.verify_batch(msgs, sigs, pks)
  end
})
