import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def generate_and_save_keypair(private_filename, public_filename):
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    with open(private_filename, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open(public_filename, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"✅ Üretildi: {private_filename} / {public_filename}")

if __name__ == "__main__":
    os.makedirs("keys", exist_ok=True)
    print("🛡️ Sentinel HQ - Sıfır Güven (Zero Trust) Anahtarları Üretiliyor...\n")
    generate_and_save_keypair("keys/gks_private.pem", "keys/gks_public.pem")
    generate_and_save_keypair("keys/uav_private.pem", "keys/uav_public.pem")
    print("\n🚀 İşlem Tamam! Anahtarlar hazır.")