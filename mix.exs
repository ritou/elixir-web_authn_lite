defmodule WebAuthnLite.MixProject do
  use Mix.Project

  def project do
    [
      app: :web_authn_lite,
      version: "0.1.0",
      elixir: "~> 1.4",
      start_permanent: Mix.env() == :prod,
      description: "WebAuthnLite is W3C Web Authentication API (a.k.a. WebAuthN / FIDO 2.0) RP library in Elixir.",
      package: [
        maintainers: ["Ryo Ito"],
        licenses: ["MIT"],
        links: %{"GitHub" => "https://github.com/ritou/elixir-web_authn_lite"}
      ],
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:jose, "~> 1.8"},
      {:jason, "~> 1.1"},

      {:ex_doc, ">= 0.0.0", only: :dev}
    ]
  end
end
