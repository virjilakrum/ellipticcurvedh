defmodule EllipticCurveDH do
  @moduledoc """
  Elliptic Curve Diffie-Hellman (ECDH) anahtar değişim işlemlerini gerçekleştiren modül.
  """

  @supported_curves [:secp256r1, :secp384r1, :secp521r1]

  @doc """
  Desteklenen eğrilerin listesini döndürür.
  """
  def supported_curves do
    @supported_curves
  end

  @doc """
  Belirtilen eğri için özel ve genel anahtar çifti oluşturur.
  """
  def generate_key_pair(curve) when curve in @supported_curves do
    :crypto.generate_key(:ecdh, curve)
  end

  def generate_key_pair(curve) do
    {:error, :unsupported_curve}
  end

  @doc """
  İki genel anahtar kullanarak ortak bir anahtar hesaplar.
  """
  def compute_key_agreement(peer_public_key, my_private_key, curve) do
    :crypto.compute_key(:ecdh, peer_public_key, my_private_key, curve)
  end

  @doc """
  Her iki tarafın da özel anahtarları ve diğer tarafın genel anahtarını kullanarak gizli bir anahtar oluşturur.
  """
  def derive_shared_secret(my_private_key, peer_public_key, curve) do
    compute_key_agreement(peer_public_key, my_private_key, curve)
  end
end

defmodule EllipticCurveDHTests do
  use ExUnit.Case

  test "supported_curves fonksiyonu doğru eğrileri döndürür" do
    assert Enum.sort(EllipticCurveDH.supported_curves()) ==
             Enum.sort([:secp256r1, :secp384r1, :secp521r1])
  end

  test "generate_key_pair fonksiyonu desteklenen eğriler için anahtar çifti oluşturur" do
    for curve <- @supported_curves do
      {:ok, private_key, public_key} = EllipticCurveDH.generate_key_pair(curve)
      assert is_binary(private_key)
      assert is_binary(public_key)
    end
  end

  test "generate_key_pair fonksiyonu desteklenmeyen eğriler için hata döndürür" do
    assert {:error, :unsupported_curve} == EllipticCurveDH.generate_key_pair(:unsupported_curve)
  end

  test "compute_key_agreement fonksiyonu ortak anahtar hesaplar" do
    for curve <- @supported_curves do
      {:ok, private_key1, public_key1} = EllipticCurveDH.generate_key_pair(curve)
      {:ok, private_key2, public_key2} = EllipticCurveDH.generate_key_pair(curve)

      shared_secret1 = EllipticCurveDH.compute_key_agreement(public_key2, private_key1, curve)
      shared_secret2 = EllipticCurveDH.compute_key_agreement(public_key1, private_key2, curve)

      assert shared_secret1 == shared_secret2
    end
  end

  test "derive_shared_secret fonksiyonu gizli anahtar oluşturur" do
    for curve <- @supported_curves do
      {:ok, private_key1, public_key1} = EllipticCurveDH.generate_key_pair(curve)
      {:ok, private_key2, public_key2} = EllipticCurveDH.generate_key_pair(curve)

      shared_secret1 = EllipticCurveDH.derive_shared_secret(private_key1, public_key2, curve)
      shared_secret2 = EllipticCurveDH.derive_shared_secret(private_key2, public_key1, curve)

      assert shared_secret1 == shared_secret2
    end
  end
end
