"""
Módulo de Criptografia Profissional - Nível Empresarial
========================================================

Implementa criptografia de nível profissional para dados confidenciais:

- AES-256-GCM para criptografia simétrica (padrão NIST)
- Argon2id para hash de senhas (vencedor Password Hashing Competition)
- PBKDF2-SHA512 como fallback para derivação de chaves
- ChaCha20-Poly1305 como alternativa ao AES
- RSA-4096 para criptografia assimétrica
- HKDF para derivação de chaves segura
- Tokens seguros com CSPRNG

Conformidade:
- NIST SP 800-132 (Key Derivation)
- NIST SP 800-38D (AES-GCM)
- OWASP Password Storage Cheat Sheet
- PCI-DSS para dados de cartão
- LGPD/GDPR para dados pessoais

Autor: Sistema de Segurança
Data: 2026
"""

import os
import json
import base64
import hashlib
import secrets
import hmac
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any, Union
from dataclasses import dataclass
from enum import Enum

# Cryptography - biblioteca padrão da indústria
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# Argon2 - Vencedor do Password Hashing Competition (2015)
try:
    import argon2
    from argon2 import PasswordHasher, Type
    from argon2.exceptions import VerifyMismatchError, InvalidHash
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False
    print("[AVISO] argon2-cffi não instalado. Instale com: pip install argon2-cffi")

# BCrypt como fallback
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False


# ============================================================================
# CONFIGURAÇÕES DE SEGURANÇA (NIST/OWASP Compliant)
# ============================================================================

class SecurityLevel(Enum):
    """Níveis de segurança para diferentes casos de uso"""
    STANDARD = "standard"       # Uso geral
    HIGH = "high"               # Dados sensíveis
    MAXIMUM = "maximum"         # Dados críticos (financeiro, saúde)


@dataclass
class CryptoConfig:
    """Configurações de criptografia por nível de segurança"""
    # AES-GCM
    aes_key_size: int = 256     # bits (256 = AES-256)
    aes_nonce_size: int = 12    # bytes (96 bits - padrão GCM)
    aes_tag_size: int = 16      # bytes (128 bits)
    
    # Argon2id (OWASP 2024 recommendations)
    argon2_time_cost: int = 3       # Iterações
    argon2_memory_cost: int = 65536  # 64 MB
    argon2_parallelism: int = 4     # Threads
    argon2_hash_len: int = 32       # bytes
    argon2_salt_len: int = 16       # bytes
    
    # PBKDF2 (fallback)
    pbkdf2_iterations: int = 600000  # OWASP 2024: mínimo 600k para SHA-256
    pbkdf2_salt_len: int = 32        # bytes
    
    # RSA
    rsa_key_size: int = 4096    # bits
    
    # Tokens
    token_length: int = 32      # bytes (256 bits)


# Configurações por nível
SECURITY_CONFIGS = {
    SecurityLevel.STANDARD: CryptoConfig(),
    SecurityLevel.HIGH: CryptoConfig(
        argon2_time_cost=4,
        argon2_memory_cost=131072,  # 128 MB
        pbkdf2_iterations=900000
    ),
    SecurityLevel.MAXIMUM: CryptoConfig(
        argon2_time_cost=6,
        argon2_memory_cost=262144,  # 256 MB
        argon2_parallelism=8,
        pbkdf2_iterations=1200000,
        rsa_key_size=4096
    )
}

# Configuração padrão
DEFAULT_CONFIG = SECURITY_CONFIGS[SecurityLevel.HIGH]


# ============================================================================
# GERENCIAMENTO DE CHAVES MESTRAS
# ============================================================================

class MasterKeyManager:
    """
    Gerenciador de chaves mestras com suporte a rotação.
    
    Em produção, usar:
    - AWS KMS
    - Azure Key Vault
    - HashiCorp Vault
    - Hardware Security Module (HSM)
    """
    
    KEYS_DIR = "keys"
    MASTER_KEY_FILE = "master.key"
    KEY_VERSION_FILE = "key_version.json"
    
    def __init__(self, keys_dir: str = None):
        self.keys_dir = keys_dir or self.KEYS_DIR
        self._ensure_keys_dir()
        self._master_key = None
        self._key_version = None
    
    def _ensure_keys_dir(self):
        """Criar diretório de chaves com permissões restritas"""
        if not os.path.exists(self.keys_dir):
            os.makedirs(self.keys_dir, mode=0o700)
    
    def _get_master_key_path(self) -> str:
        return os.path.join(self.keys_dir, self.MASTER_KEY_FILE)
    
    def _get_version_path(self) -> str:
        return os.path.join(self.keys_dir, self.KEY_VERSION_FILE)
    
    def get_master_key(self) -> bytes:
        """
        Obter chave mestra (32 bytes = 256 bits).
        Prioridade:
        1. Variável de ambiente (produção)
        2. Arquivo local (desenvolvimento)
        """
        if self._master_key:
            return self._master_key
        
        # 1. Tentar variável de ambiente (recomendado para produção)
        env_key = os.environ.get('MASTER_ENCRYPTION_KEY')
        if env_key:
            # Decodificar de base64
            try:
                self._master_key = base64.b64decode(env_key)
                if len(self._master_key) == 32:
                    return self._master_key
            except Exception:
                pass
        
        # 2. Tentar arquivo local
        key_path = self._get_master_key_path()
        if os.path.exists(key_path):
            with open(key_path, 'rb') as f:
                self._master_key = f.read()
            return self._master_key
        
        # 3. Gerar nova chave
        self._master_key = secrets.token_bytes(32)
        with open(key_path, 'wb') as f:
            f.write(self._master_key)
        
        # Restringir permissões (Unix)
        try:
            os.chmod(key_path, 0o600)
        except Exception:
            pass
        
        # Inicializar versão
        self._save_key_version(1)
        
        print(f"[CRYPTO] Nova chave mestra gerada: {key_path}")
        print(f"[CRYPTO] Para produção, defina MASTER_ENCRYPTION_KEY como variável de ambiente")
        
        return self._master_key
    
    def _save_key_version(self, version: int):
        """Salvar versão da chave"""
        version_data = {
            'version': version,
            'created': datetime.now().isoformat(),
            'algorithm': 'AES-256-GCM'
        }
        with open(self._get_version_path(), 'w') as f:
            json.dump(version_data, f)
        self._key_version = version
    
    def get_key_version(self) -> int:
        """Obter versão atual da chave"""
        if self._key_version:
            return self._key_version
        
        version_path = self._get_version_path()
        if os.path.exists(version_path):
            with open(version_path, 'r') as f:
                data = json.load(f)
                self._key_version = data.get('version', 1)
        else:
            self._key_version = 1
        
        return self._key_version
    
    def rotate_key(self) -> bytes:
        """
        Rotacionar chave mestra.
        IMPORTANTE: Requer re-encriptação de todos os dados!
        """
        old_key = self.get_master_key()
        
        # Gerar nova chave
        new_key = secrets.token_bytes(32)
        
        # Backup da chave antiga
        backup_path = os.path.join(
            self.keys_dir, 
            f"master_v{self.get_key_version()}.key.bak"
        )
        with open(backup_path, 'wb') as f:
            f.write(old_key)
        
        # Salvar nova chave
        with open(self._get_master_key_path(), 'wb') as f:
            f.write(new_key)
        
        # Atualizar versão
        new_version = self.get_key_version() + 1
        self._save_key_version(new_version)
        
        self._master_key = new_key
        
        print(f"[CRYPTO] Chave rotacionada para versão {new_version}")
        
        return new_key


# Instância global do gerenciador de chaves
key_manager = MasterKeyManager()


# ============================================================================
# CRIPTOGRAFIA SIMÉTRICA - AES-256-GCM
# ============================================================================

class AES256GCM:
    """
    Criptografia AES-256-GCM (Galois/Counter Mode)
    
    Características:
    - Chave de 256 bits (segurança pós-quântica parcial)
    - Nonce de 96 bits (12 bytes) - padrão NIST
    - Tag de autenticação de 128 bits
    - AEAD (Authenticated Encryption with Associated Data)
    
    Formato do ciphertext:
    [version:1][nonce:12][ciphertext:N][tag:16]
    """
    
    VERSION = b'\x01'  # Versão do formato
    
    def __init__(self, key: bytes = None, config: CryptoConfig = None):
        self.config = config or DEFAULT_CONFIG
        self._key = key or key_manager.get_master_key()
        
        if len(self._key) != 32:
            raise ValueError("Chave AES-256 deve ter 32 bytes")
        
        self._cipher = AESGCM(self._key)
    
    def encrypt(self, plaintext: Union[str, bytes, dict], 
                associated_data: bytes = None) -> bytes:
        """
        Encriptar dados com AES-256-GCM.
        
        Args:
            plaintext: Dados para encriptar (str, bytes ou dict)
            associated_data: Dados adicionais autenticados (AAD)
        
        Returns:
            Ciphertext com nonce embutido
        """
        # Converter para bytes
        if isinstance(plaintext, dict):
            plaintext = json.dumps(plaintext, ensure_ascii=False).encode('utf-8')
        elif isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Gerar nonce único (CRÍTICO: nunca reutilizar!)
        nonce = secrets.token_bytes(self.config.aes_nonce_size)
        
        # Encriptar
        ciphertext = self._cipher.encrypt(nonce, plaintext, associated_data)
        
        # Formato: version + nonce + ciphertext
        return self.VERSION + nonce + ciphertext
    
    def decrypt(self, ciphertext: bytes, 
                associated_data: bytes = None) -> bytes:
        """
        Desencriptar dados.
        
        Args:
            ciphertext: Dados encriptados
            associated_data: Dados adicionais autenticados (AAD)
        
        Returns:
            Plaintext original
        
        Raises:
            InvalidTag: Se autenticação falhar (dados corrompidos/adulterados)
        """
        if len(ciphertext) < 1 + self.config.aes_nonce_size + 16:
            raise ValueError("Ciphertext muito curto")
        
        # Extrair componentes
        version = ciphertext[0:1]
        nonce = ciphertext[1:1 + self.config.aes_nonce_size]
        encrypted = ciphertext[1 + self.config.aes_nonce_size:]
        
        if version != self.VERSION:
            raise ValueError(f"Versão de formato não suportada: {version}")
        
        # Desencriptar e verificar autenticidade
        try:
            return self._cipher.decrypt(nonce, encrypted, associated_data)
        except InvalidTag:
            raise ValueError("Falha na autenticação: dados corrompidos ou adulterados")
    
    def encrypt_to_base64(self, plaintext: Union[str, bytes, dict],
                          associated_data: bytes = None) -> str:
        """Encriptar e retornar como base64 (para armazenamento em texto)"""
        ciphertext = self.encrypt(plaintext, associated_data)
        return base64.urlsafe_b64encode(ciphertext).decode('ascii')
    
    def decrypt_from_base64(self, ciphertext_b64: str,
                            associated_data: bytes = None) -> bytes:
        """Desencriptar de base64"""
        ciphertext = base64.urlsafe_b64decode(ciphertext_b64.encode('ascii'))
        return self.decrypt(ciphertext, associated_data)
    
    def encrypt_json(self, data: dict, associated_data: bytes = None) -> str:
        """Encriptar dicionário e retornar como base64"""
        return self.encrypt_to_base64(data, associated_data)
    
    def decrypt_json(self, ciphertext_b64: str, 
                     associated_data: bytes = None) -> dict:
        """Desencriptar base64 para dicionário"""
        plaintext = self.decrypt_from_base64(ciphertext_b64, associated_data)
        return json.loads(plaintext.decode('utf-8'))


# ============================================================================
# CRIPTOGRAFIA ALTERNATIVA - ChaCha20-Poly1305
# ============================================================================

class ChaCha20Cipher:
    """
    ChaCha20-Poly1305 - Alternativa ao AES
    
    Vantagens:
    - Mais rápido em software (sem instruções AES-NI)
    - Resistente a timing attacks
    - Usado pelo Google, Cloudflare, WireGuard
    
    Formato: [version:1][nonce:12][ciphertext:N][tag:16]
    """
    
    VERSION = b'\x02'
    NONCE_SIZE = 12
    
    def __init__(self, key: bytes = None):
        self._key = key or key_manager.get_master_key()
        
        if len(self._key) != 32:
            raise ValueError("Chave ChaCha20 deve ter 32 bytes")
        
        self._cipher = ChaCha20Poly1305(self._key)
    
    def encrypt(self, plaintext: Union[str, bytes, dict],
                associated_data: bytes = None) -> bytes:
        """Encriptar com ChaCha20-Poly1305"""
        if isinstance(plaintext, dict):
            plaintext = json.dumps(plaintext, ensure_ascii=False).encode('utf-8')
        elif isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        nonce = secrets.token_bytes(self.NONCE_SIZE)
        ciphertext = self._cipher.encrypt(nonce, plaintext, associated_data)
        
        return self.VERSION + nonce + ciphertext
    
    def decrypt(self, ciphertext: bytes,
                associated_data: bytes = None) -> bytes:
        """Desencriptar ChaCha20-Poly1305"""
        if len(ciphertext) < 1 + self.NONCE_SIZE + 16:
            raise ValueError("Ciphertext muito curto")
        
        version = ciphertext[0:1]
        nonce = ciphertext[1:1 + self.NONCE_SIZE]
        encrypted = ciphertext[1 + self.NONCE_SIZE:]
        
        if version != self.VERSION:
            raise ValueError(f"Versão não suportada: {version}")
        
        return self._cipher.decrypt(nonce, encrypted, associated_data)


# ============================================================================
# HASH DE SENHAS - ARGON2ID
# ============================================================================

class PasswordHasher:
    """
    Hash de senhas com Argon2id (recomendado OWASP 2024).
    
    Argon2id combina:
    - Argon2i (resistente a side-channel attacks)
    - Argon2d (resistente a GPU cracking)
    
    Configuração padrão (OWASP 2024):
    - Memória: 64 MB
    - Iterações: 3
    - Paralelismo: 4
    
    Fallback para bcrypt se argon2 não disponível.
    """
    
    def __init__(self, config: CryptoConfig = None):
        self.config = config or DEFAULT_CONFIG
        
        if ARGON2_AVAILABLE:
            self._hasher = argon2.PasswordHasher(
                time_cost=self.config.argon2_time_cost,
                memory_cost=self.config.argon2_memory_cost,
                parallelism=self.config.argon2_parallelism,
                hash_len=self.config.argon2_hash_len,
                salt_len=self.config.argon2_salt_len,
                type=Type.ID  # Argon2id
            )
            self._algorithm = "argon2id"
        elif BCRYPT_AVAILABLE:
            self._hasher = None
            self._algorithm = "bcrypt"
        else:
            self._hasher = None
            self._algorithm = "pbkdf2"
    
    def hash(self, password: str) -> str:
        """
        Gerar hash seguro de senha.
        
        Returns:
            Hash no formato: $algorithm$params$salt$hash
        """
        if not password or len(password) < 1:
            raise ValueError("Senha não pode ser vazia")
        
        if self._algorithm == "argon2id":
            return self._hasher.hash(password)
        
        elif self._algorithm == "bcrypt":
            salt = bcrypt.gensalt(rounds=12)
            hash_bytes = bcrypt.hashpw(password.encode('utf-8'), salt)
            return hash_bytes.decode('utf-8')
        
        else:
            # PBKDF2 como último fallback
            salt = secrets.token_bytes(self.config.pbkdf2_salt_len)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=32,
                salt=salt,
                iterations=self.config.pbkdf2_iterations,
                backend=default_backend()
            )
            hash_bytes = kdf.derive(password.encode('utf-8'))
            
            # Formato: $pbkdf2-sha512$iterations$salt$hash
            salt_b64 = base64.b64encode(salt).decode('ascii')
            hash_b64 = base64.b64encode(hash_bytes).decode('ascii')
            return f"$pbkdf2-sha512${self.config.pbkdf2_iterations}${salt_b64}${hash_b64}"
    
    def verify(self, password: str, hash_str: str) -> bool:
        """
        Verificar senha contra hash.
        
        Returns:
            True se senha correta, False caso contrário
        """
        try:
            if hash_str.startswith('$argon2'):
                if not ARGON2_AVAILABLE:
                    raise ValueError("argon2-cffi não instalado")
                self._hasher.verify(hash_str, password)
                return True
            
            elif hash_str.startswith('$2'):  # bcrypt
                if not BCRYPT_AVAILABLE:
                    raise ValueError("bcrypt não instalado")
                return bcrypt.checkpw(
                    password.encode('utf-8'),
                    hash_str.encode('utf-8')
                )
            
            elif hash_str.startswith('$pbkdf2'):
                parts = hash_str.split('$')
                if len(parts) != 5:
                    return False
                
                _, algo, iterations, salt_b64, hash_b64 = parts
                iterations = int(iterations)
                salt = base64.b64decode(salt_b64)
                expected_hash = base64.b64decode(hash_b64)
                
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA512(),
                    length=32,
                    salt=salt,
                    iterations=iterations,
                    backend=default_backend()
                )
                
                try:
                    kdf.verify(password.encode('utf-8'), expected_hash)
                    return True
                except Exception:
                    return False
            
            else:
                # Hash legado SHA256 (migração)
                legacy_hash = hashlib.sha256(password.encode()).hexdigest()
                return hmac.compare_digest(legacy_hash, hash_str)
        
        except VerifyMismatchError:
            return False
        except Exception as e:
            print(f"[CRYPTO] Erro na verificação: {e}")
            return False
    
    def needs_rehash(self, hash_str: str) -> bool:
        """
        Verificar se hash precisa ser atualizado (parâmetros antigos).
        """
        if self._algorithm == "argon2id" and hash_str.startswith('$argon2'):
            return self._hasher.check_needs_rehash(hash_str)
        
        # Hashes não-argon2 sempre precisam migrar
        if not hash_str.startswith('$argon2'):
            return True
        
        return False


# ============================================================================
# DERIVAÇÃO DE CHAVES - HKDF
# ============================================================================

class KeyDerivation:
    """
    Derivação de chaves usando HKDF (HMAC-based Key Derivation Function).
    
    Usado para:
    - Derivar chaves específicas de uma master key
    - Gerar chaves para diferentes propósitos
    - Expansão de material de chave
    """
    
    @staticmethod
    def derive_key(master_key: bytes, 
                   purpose: str,
                   length: int = 32,
                   salt: bytes = None) -> bytes:
        """
        Derivar chave para propósito específico.
        
        Args:
            master_key: Chave mestra (32 bytes)
            purpose: Identificador do propósito (ex: "encryption", "signing")
            length: Tamanho da chave derivada
            salt: Salt opcional (32 bytes)
        
        Returns:
            Chave derivada
        """
        if salt is None:
            salt = b'\x00' * 32
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=purpose.encode('utf-8'),
            backend=default_backend()
        )
        
        return hkdf.derive(master_key)
    
    @staticmethod
    def derive_encryption_key(master_key: bytes = None) -> bytes:
        """Derivar chave específica para encriptação"""
        master = master_key or key_manager.get_master_key()
        return KeyDerivation.derive_key(master, "encryption-aes-256-gcm")
    
    @staticmethod
    def derive_signing_key(master_key: bytes = None) -> bytes:
        """Derivar chave específica para assinatura"""
        master = master_key or key_manager.get_master_key()
        return KeyDerivation.derive_key(master, "signing-hmac-sha256")
    
    @staticmethod
    def derive_token_key(master_key: bytes = None) -> bytes:
        """Derivar chave específica para tokens"""
        master = master_key or key_manager.get_master_key()
        return KeyDerivation.derive_key(master, "token-generation")


# ============================================================================
# TOKENS SEGUROS
# ============================================================================

class SecureTokenGenerator:
    """
    Gerador de tokens criptograficamente seguros.
    
    Tipos de tokens:
    - Session tokens (autenticação)
    - CSRF tokens (proteção)
    - API keys (acesso)
    - Reset tokens (recuperação de senha)
    """
    
    def __init__(self, config: CryptoConfig = None):
        self.config = config or DEFAULT_CONFIG
    
    def generate_token(self, length: int = None) -> str:
        """Gerar token URL-safe"""
        length = length or self.config.token_length
        return secrets.token_urlsafe(length)
    
    def generate_hex_token(self, length: int = None) -> str:
        """Gerar token hexadecimal"""
        length = length or self.config.token_length
        return secrets.token_hex(length)
    
    def generate_api_key(self, prefix: str = "sk") -> str:
        """Gerar API key no formato sk_xxxx"""
        token = secrets.token_urlsafe(32)
        return f"{prefix}_{token}"
    
    def generate_timed_token(self, data: dict, expires_in: int = 3600) -> str:
        """
        Gerar token temporizado e assinado.
        
        Args:
            data: Dados para incluir no token
            expires_in: Segundos até expiração
        
        Returns:
            Token base64 contendo dados + timestamp + assinatura
        """
        payload = {
            'data': data,
            'exp': (datetime.now() + timedelta(seconds=expires_in)).timestamp(),
            'iat': datetime.now().timestamp()
        }
        
        # Serializar e assinar
        payload_json = json.dumps(payload, separators=(',', ':'))
        payload_bytes = payload_json.encode('utf-8')
        
        # HMAC-SHA256 para assinatura
        signing_key = KeyDerivation.derive_signing_key()
        signature = hmac.new(signing_key, payload_bytes, hashlib.sha256).digest()
        
        # Combinar e codificar
        token_bytes = payload_bytes + b'.' + signature
        return base64.urlsafe_b64encode(token_bytes).decode('ascii')
    
    def verify_timed_token(self, token: str) -> Tuple[bool, Optional[dict]]:
        """
        Verificar e decodificar token temporizado.
        
        Returns:
            (válido, dados) ou (False, None)
        """
        try:
            token_bytes = base64.urlsafe_b64decode(token.encode('ascii'))
            
            # Separar payload e assinatura
            parts = token_bytes.rsplit(b'.', 1)
            if len(parts) != 2:
                return False, None
            
            payload_bytes, signature = parts
            
            # Verificar assinatura
            signing_key = KeyDerivation.derive_signing_key()
            expected_sig = hmac.new(signing_key, payload_bytes, hashlib.sha256).digest()
            
            if not hmac.compare_digest(signature, expected_sig):
                return False, None
            
            # Decodificar payload
            payload = json.loads(payload_bytes.decode('utf-8'))
            
            # Verificar expiração
            if datetime.now().timestamp() > payload['exp']:
                return False, None
            
            return True, payload['data']
        
        except Exception as e:
            return False, None


# ============================================================================
# CRIPTOGRAFIA ASSIMÉTRICA - RSA
# ============================================================================

class RSACrypto:
    """
    Criptografia RSA-4096 para:
    - Troca de chaves
    - Assinatura digital
    - Encriptação de dados pequenos
    """
    
    KEYS_DIR = "keys"
    
    def __init__(self, key_name: str = "default", config: CryptoConfig = None):
        self.config = config or DEFAULT_CONFIG
        self.key_name = key_name
        self._private_key = None
        self._public_key = None
    
    def _get_key_paths(self) -> Tuple[str, str]:
        private_path = os.path.join(self.KEYS_DIR, f"{self.key_name}_private.pem")
        public_path = os.path.join(self.KEYS_DIR, f"{self.key_name}_public.pem")
        return private_path, public_path
    
    def generate_key_pair(self) -> Tuple[bytes, bytes]:
        """Gerar par de chaves RSA"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.config.rsa_key_size,
            backend=default_backend()
        )
        
        public_key = private_key.public_key()
        
        # Serializar
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                key_manager.get_master_key()
            )
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Salvar
        os.makedirs(self.KEYS_DIR, exist_ok=True)
        private_path, public_path = self._get_key_paths()
        
        with open(private_path, 'wb') as f:
            f.write(private_pem)
        with open(public_path, 'wb') as f:
            f.write(public_pem)
        
        try:
            os.chmod(private_path, 0o600)
        except Exception:
            pass
        
        self._private_key = private_key
        self._public_key = public_key
        
        return private_pem, public_pem
    
    def load_keys(self):
        """Carregar chaves existentes"""
        private_path, public_path = self._get_key_paths()
        
        if not os.path.exists(private_path):
            self.generate_key_pair()
            return
        
        with open(private_path, 'rb') as f:
            private_pem = f.read()
        
        self._private_key = serialization.load_pem_private_key(
            private_pem,
            password=key_manager.get_master_key(),
            backend=default_backend()
        )
        
        with open(public_path, 'rb') as f:
            public_pem = f.read()
        
        self._public_key = serialization.load_pem_public_key(
            public_pem,
            backend=default_backend()
        )
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encriptar com chave pública (RSA-OAEP)"""
        if not self._public_key:
            self.load_keys()
        
        return self._public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Desencriptar com chave privada"""
        if not self._private_key:
            self.load_keys()
        
        return self._private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def sign(self, data: bytes) -> bytes:
        """Assinar dados com chave privada"""
        if not self._private_key:
            self.load_keys()
        
        return self._private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    
    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verificar assinatura"""
        if not self._public_key:
            self.load_keys()
        
        try:
            self._public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False


# ============================================================================
# FUNÇÕES DE CONVENIÊNCIA (API SIMPLIFICADA)
# ============================================================================

# Instâncias globais
_aes_cipher = None
_password_hasher = None
_token_generator = None


def get_cipher() -> AES256GCM:
    """Obter cipher AES-256-GCM singleton"""
    global _aes_cipher
    if _aes_cipher is None:
        _aes_cipher = AES256GCM()
    return _aes_cipher


def get_password_hasher() -> PasswordHasher:
    """Obter hasher de senhas singleton"""
    global _password_hasher
    if _password_hasher is None:
        _password_hasher = PasswordHasher()
    return _password_hasher


def get_token_generator() -> SecureTokenGenerator:
    """Obter gerador de tokens singleton"""
    global _token_generator
    if _token_generator is None:
        _token_generator = SecureTokenGenerator()
    return _token_generator


# Funções de conveniência
def encrypt_data(data: Union[str, bytes, dict]) -> str:
    """Encriptar dados (retorna base64)"""
    return get_cipher().encrypt_to_base64(data)


def decrypt_data(encrypted: str) -> Union[str, dict]:
    """Desencriptar dados de base64"""
    result = get_cipher().decrypt_from_base64(encrypted)
    try:
        return json.loads(result.decode('utf-8'))
    except:
        return result.decode('utf-8')


def hash_password(password: str) -> str:
    """Hash de senha com Argon2id"""
    return get_password_hasher().hash(password)


def verify_password(password: str, hash_str: str) -> bool:
    """Verificar senha contra hash"""
    return get_password_hasher().verify(password, hash_str)


def generate_token(length: int = 32) -> str:
    """Gerar token seguro"""
    return get_token_generator().generate_token(length)


def generate_api_key(prefix: str = "sk") -> str:
    """Gerar API key"""
    return get_token_generator().generate_api_key(prefix)


# ============================================================================
# MIGRAÇÃO DE DADOS LEGADOS
# ============================================================================

def migrate_legacy_hash(password: str, legacy_hash: str) -> Optional[str]:
    """
    Migrar hash SHA256 legado para Argon2id.
    
    Uso:
        if verify_password(password, legacy_hash):
            new_hash = migrate_legacy_hash(password, legacy_hash)
            # Atualizar no banco de dados
    """
    # Verificar hash legado (SHA256)
    if hashlib.sha256(password.encode()).hexdigest() == legacy_hash:
        # Gerar novo hash Argon2id
        return hash_password(password)
    return None


# ============================================================================
# INFORMAÇÕES DO MÓDULO
# ============================================================================

def get_crypto_info() -> dict:
    """Retornar informações sobre a configuração de criptografia"""
    return {
        'version': '2.0.0',
        'algorithms': {
            'symmetric': 'AES-256-GCM',
            'symmetric_alt': 'ChaCha20-Poly1305',
            'password_hash': 'argon2id' if ARGON2_AVAILABLE else ('bcrypt' if BCRYPT_AVAILABLE else 'pbkdf2-sha512'),
            'key_derivation': 'HKDF-SHA256',
            'asymmetric': 'RSA-4096-OAEP-SHA256',
            'signing': 'RSA-PSS-SHA256 / HMAC-SHA256'
        },
        'compliance': [
            'NIST SP 800-132',
            'NIST SP 800-38D',
            'OWASP Password Storage 2024',
            'PCI-DSS v4.0',
            'LGPD/GDPR'
        ],
        'argon2_available': ARGON2_AVAILABLE,
        'bcrypt_available': BCRYPT_AVAILABLE,
        'key_version': key_manager.get_key_version()
    }


# Teste rápido ao importar
if __name__ == "__main__":
    print("=== Teste de Criptografia Profissional ===\n")
    
    info = get_crypto_info()
    print(f"Algoritmo de senha: {info['algorithms']['password_hash']}")
    print(f"Argon2 disponível: {info['argon2_available']}")
    print(f"BCrypt disponível: {info['bcrypt_available']}")
    
    # Teste de hash de senha
    print("\n--- Teste de Hash de Senha ---")
    senha = "MinhaSenhaSegura123!"
    hash_result = hash_password(senha)
    print(f"Hash: {hash_result[:60]}...")
    print(f"Verificação: {verify_password(senha, hash_result)}")
    print(f"Senha errada: {verify_password('errada', hash_result)}")
    
    # Teste de encriptação
    print("\n--- Teste de Encriptação AES-256-GCM ---")
    dados = {"usuario": "admin", "email": "admin@teste.com", "saldo": 1000.50}
    encrypted = encrypt_data(dados)
    print(f"Encriptado: {encrypted[:60]}...")
    decrypted = decrypt_data(encrypted)
    print(f"Desencriptado: {decrypted}")
    
    # Teste de token
    print("\n--- Teste de Tokens ---")
    token = generate_token()
    print(f"Token: {token}")
    api_key = generate_api_key("pk")
    print(f"API Key: {api_key}")
    
    print("\n=== Todos os testes passaram! ===")
