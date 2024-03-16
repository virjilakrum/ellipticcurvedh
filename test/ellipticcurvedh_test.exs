defmodule EllipticCurveDHTests do
  use ExUnit.Case

  test "supported_curves fonksiyonu doğru eğrileri döndürür" do
    assert Enum.sort(EllipticCurveDH.supported_curves()) == Enum.sort([:secp256r1, :secp384r1, :secp521r1])
  end

  test "generate_key_pair fonksiyonu desteklenen eğriler için anahtar çifti oluşturur" do
    for curve <- @supported_curves do
      {:ok, private_key, public_key} = EllipticCurveDH.generate_key_pair(curve)
      assert is_binary(private_key)
      assert is_binary(public_key)

      # Özel anahtarın uzunluğu eğriye göre değişir.
      case curve do
        :secp256r1 -> assert byte_size(private_key) == 32
        :secp384r1 -> assert byte_size(private_key) == 48
        :secp521r1 -> assert byte_size(private_key) == 66
      end
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
      assert byte_size(shared_secret1) > 0
    end
  end

  test "derive_shared_secret fonksiyonu gizli anahtar oluşturur" do
    for curve <- @supported_curves do
      {:ok, private_key1, public_key1} = EllipticCurveDH.generate_key_pair(curve)
      {:ok, private_key2, public_key2} = EllipticCurveDH.generate_key_pair(curve)

      shared_secret1 = EllipticCurveDH.derive_shared_secret(private_key1, public_key2, curve)
      shared_secret2 = EllipticCurveDH.derive_shared_secret(private_key2, public_key1, curve)

      assert shared_secret1 == shared_secret2
      assert byte_size(shared_secret1) > 0
    end
  end

  test "farklı eğriler ile anahtar değişiminin yapılamayacağını test eder" do
    {:ok, private_key1, public_key1} = EllipticCurveDH.generate_key_pair(:secp256r1)
    {:ok, private_key2, public_key2} = EllipticCurveDH.generate_key_pair(:secp384r1)

    assert {:error, :invalid_curve} == EllipticCurveDH.compute_key_agreement(public_key2, private_key1, :secp256r1)
    assert {:error, :invalid_curve} == EllipticCurveDH.compute_key_agreement(public_key1, private_key2, :secp384r1)

    assert {:error, :invalid_curve} == EllipticCurveDH.derive_shared_secret(private_key1, public_key2, :secp256r1)
    assert {:error, :invalid_curve} == EllipticCurveDH.derive_shared_secret(private_key2, public_key1, :secp384r1)
  end

  test "geçersiz anahtarlarla hata döndürür" do
    invalid_public_key = "invalid_public_key"
    invalid_private_key = "invalid_private_key"

    assert {:error, :invalid_public_key} == El
