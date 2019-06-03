defmodule Ed25519Blake2b.MixProject do
  use Mix.Project

  def project do
    [
      app: :ed25519_blake2b,
      package: package(),
      version: "0.2.0",
      elixir: "~> 1.8",
      docs: docs(),
      start_permanent: Mix.env() == :prod,
      compilers: [:rustler] ++ Mix.compilers(),
      rustler_crates: rustler_crates(),
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:rustler, "~> 0.20.0"},
      {:benchee, "~> 1.0", only: [:dev]},
      {:ex_doc, "~> 0.19", only: [:dev], runtime: false}
    ]
  end

  defp docs do
    [
      name: "Ed25519Blake2b",
      extras: ["README.md"],
      main: "readme",
      source_url: "https://github.com/orhanhenrik/ed25519_blake2b"
    ]
  end

  defp package do
    [
      name: :ed25519_blake2b,
      description:
        "Ed25519Blake2b is a NIF library to work with ed25519 signatures with blake2b hashing",
      files: ["lib", "native", ".formatter.exs", "README*", "LICENSE*", "mix.exs"],
      maintainers: ["Orhan Henrik Hirsch"],
      licenses: ["MIT"],
      links: %{
        "GitHub" => "https://github.com/orhanhenrik/ed25519_blake2b"
      }
    ]
  end

  defp rustler_crates do
    [
      ed25519blake2b: [
        mode: rustc_mode(Mix.env(), System.get_env("OPTIMIZE_NIF") == "true")
      ]
    ]
  end

  defp rustc_mode(_, true), do: :release
  defp rustc_mode(:prod, _), do: :release
  defp rustc_mode(_, _), do: :debug
end
