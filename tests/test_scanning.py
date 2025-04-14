import unittest
from src.escaneo_hook_dlls import has_authenticode_signature

class TestScanner(unittest.TestCase):
    def test_signature_verification(self):
        # Deberías tener un archivo de prueba firmado
        self.assertTrue(has_authenticode_signature("C:\\Windows\\System32\\kernel32.dll"))
        
if __name__ == '__main__':
    unittest.main()
