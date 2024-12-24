from .crypto import HybridEncryptionService


class SingletonHybridEncryptionService(HybridEncryptionService):
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(
                SingletonHybridEncryptionService, cls
            ).__new__(cls, *args, **kwargs)
        return cls._instance


hybrid = SingletonHybridEncryptionService()
encrypt = hybrid.encrypt
decrypt = hybrid.decrypt
