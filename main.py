import hmac
import hashlib
import time
import json

# Terminal logları için renk kodları (Log Screen simülasyonu)
class LogColors:
    OK = '\033[92m'       # Yeşil
    WARNING = '\033[93m'  # Sarı
    FAIL = '\033[91m'     # Kırmızı
    INFO = '\033[96m'     # Cam Göbeği
    ENDC = '\033[0m'      # Rengi Sıfırla

class SecureCommunicator:
    def __init__(self, secret_key: str, max_time_drift: int = 60):
        """
        Sistemin temel güvenlik sınıfı.
        :param secret_key: Gönderici ve alıcı arasındaki paylaşılan gizli anahtar
        :param max_time_drift: Replay saldırılarını önlemek için saniye cinsinden maksimum geçerlilik süresi
        """
        self.secret_key = secret_key.encode('utf-8')
        self.max_time_drift = max_time_drift

    def generate_hmac(self, message: str, timestamp: float) -> str:
        """
        Mesaj ve zaman damgasını birleştirerek SHA-256 tabanlı HMAC üretir.
        """
        data_to_sign = f"{message}|{timestamp}".encode('utf-8')
        mac = hmac.new(self.secret_key, data_to_sign, hashlib.sha256)
        return mac.hexdigest()

    def create_secure_packet(self, message: str) -> str:
        """
        Ağ üzerinden gönderilecek paketi hazırlar.
        """
        timestamp = time.time()
        signature = self.generate_hmac(message, timestamp)
        
        packet = {
            "message": message,
            "timestamp": timestamp,
            "signature": signature
        }
        return json.dumps(packet)

    def verify_packet(self, packet_json: str) -> tuple[bool, str]:
        """
        Gelen paketi doğrulayan ve güvenlik testlerinden geçiren ana metot.
        """
        try:
            packet = json.loads(packet_json)
            received_message = packet.get("message")
            received_timestamp = packet.get("timestamp")
            received_signature = packet.get("signature")

            if received_message is None or received_timestamp is None or received_signature is None:
                return False, "Error: Missing Signature or Data"

            current_time = time.time()
            time_difference = current_time - received_timestamp
            
            if time_difference > self.max_time_drift:
                return False, f"Error: Replay Attack Detected! Packet is {time_difference:.2f}s old."
            elif time_difference < 0:
                return False, "Error: Invalid Timestamp (Future time)."

            expected_signature = self.generate_hmac(received_message, received_timestamp)

            if hmac.compare_digest(expected_signature, received_signature):
                return True, "200 OK - Message Verified"
            else:
                return False, "Error: Integrity or Auth Failed (Avalanche Effect Triggered)"

        except json.JSONDecodeError:
            return False, "Error: Invalid JSON Format"
        except Exception as e:
            return False, f"Error: System Exception - {str(e)}"


def run_security_tests():
    print(f"\n{LogColors.INFO}{'='*50}")
    print(" GÜVENLİK MİMARİSİ TEST SÜRECİ BAŞLATILIYOR ")
    print(f"{'='*50}{LogColors.ENDC}\n")

    alice = SecureCommunicator("Shared_Secret_Key_2026")
    bob = SecureCommunicator("Shared_Secret_Key_2026")
    eve_attacker = SecureCommunicator("Wrong_Fake_Key_0000")

    test_results = []

    def run_test(test_id, description, is_valid_expected, packet_json):
        print(f"{LogColors.INFO}[{test_id}] {description}{LogColors.ENDC}")
        
        start_time = time.perf_counter()
        is_valid, log_message = bob.verify_packet(packet_json)
        end_time = time.perf_counter()
        
        execution_time = (end_time - start_time) * 1000
        
        if is_valid == is_valid_expected:
            print(f"{LogColors.OK}  [✔] PASS - Beklenen Sonuç Alındı: {log_message} ({execution_time:.3f} ms){LogColors.ENDC}\n")
            test_results.append(True)
        else:
            print(f"{LogColors.FAIL}  [✘] FAIL - Beklenmeyen Sonuç: {log_message}{LogColors.ENDC}\n")
            test_results.append(False)

    # ------------------ TEST SENARYOLARI ------------------
    packet_01 = alice.create_secure_packet("Hesap bakiyesi guncellendi.")
    run_test("TS-01", "Normal İşleyiş (Geçerli Paket)", True, packet_01)

    packet_dict_02 = json.loads(alice.create_secure_packet("Transfer: 100 TL"))
    packet_dict_02["message"] = "Transfer: 900 TL"
    run_test("TS-02", "MITM Saldırısı - Veri Değiştirme (Integrity Check)", False, json.dumps(packet_dict_02))

    packet_03 = eve_attacker.create_secure_packet("Sunucuyu kapat komutu")
    run_test("TS-03", "Sahte Anahtar İle İmza (Authentication Check)", False, packet_03)

    old_timestamp = time.time() - 300 
    old_signature = alice.generate_hmac("Gecerli eski komut", old_timestamp)
    packet_04 = json.dumps({"message": "Gecerli eski komut", "timestamp": old_timestamp, "signature": old_signature})
    run_test("TS-04", "Replay Saldırısı - Süresi Dolmuş Paket", False, packet_04)

    packet_dict_05 = json.loads(alice.create_secure_packet("Gizli veri aktarimi"))
    packet_dict_05["signature"] = packet_dict_05["signature"][:-1] + "0" 
    run_test("TS-05", "İmza Tahrifatı (Bozuk HMAC Değeri)", False, json.dumps(packet_dict_05))

    packet_06 = alice.create_secure_packet("Türkçe Karakter Testi: ŞğÜÖÇı € ₺")
    run_test("TS-06", "UTF-8 ve Özel Karakter Testi", True, packet_06)

    packet_07 = alice.create_secure_packet("")
    run_test("TS-07", "Boş Veri Yükü (Edge Case)", True, packet_07)

    packet_dict_08 = json.loads(alice.create_secure_packet("Sisteme giris yapildi"))
    del packet_dict_08["signature"]
    run_test("TS-08", "Eksik İmza Verisi (Access Control)", False, json.dumps(packet_dict_08))

    large_message = "A" * 50000
    packet_09 = alice.create_secure_packet(large_message)
    run_test("TS-09", "Büyük Boyutlu Veri (Performans Testi)", True, packet_09)

    broken_packet = packet_01[:15] 
    run_test("TS-10", "Bozuk JSON Formatı (Hata Yakalama)", False, broken_packet)

    # ------------------ TEST SONUÇ RAPORU ------------------
    print(f"{LogColors.INFO}{'-'*50}{LogColors.ENDC}")
    success_rate = (sum(test_results) / len(test_results)) * 100
    print(f"Toplam Test: {len(test_results)} | Başarılı Test: {sum(test_results)}")
    
    if success_rate == 100.0:
        print(f"{LogColors.OK}SİSTEM GÜVENLİK TESTLERİ %100 BAŞARIYLA TAMAMLANDI.{LogColors.ENDC}")
    else:
        print(f"{LogColors.WARNING}SİSTEMDE ZAFİYETLER TESPİT EDİLDİ!{LogColors.ENDC}")

def interactive_mode():
    alice = SecureCommunicator("Siber_Vatan_2026")
    bob = SecureCommunicator("Siber_Vatan_2026")
    
    while True:
        print(f"\n{LogColors.INFO}=== GÜVENLİ HABERLEŞME SİMÜLASYONU ==={LogColors.ENDC}")
        print("1. Kullanıcıdan Mesaj Al ve Gönder (Normal Senaryo)")
        print("2. Araya Gir ve Mesajı Değiştir (MITM Saldırısı Simülasyonu)")
        print("3. Otomatik Güvenlik Testlerini Çalıştır (10 Senaryo)")
        print("4. Çıkış")
        
        secim = input(f"{LogColors.WARNING}Lütfen bir işlem seçin (1-4): {LogColors.ENDC}")
        
        if secim == '1':
            # KULLANICIDAN İNPUT ALMA ŞARTI BURADA SAĞLANIYOR
            kullanici_mesaji = input(f"{LogColors.OK}İletilecek mesajı yazın: {LogColors.ENDC}")
            
            # GÜVENLİK METODUNU UYGULAMA ŞARTI BURADA SAĞLANIYOR
            paket = alice.create_secure_packet(kullanici_mesaji)
            print(f"\n{LogColors.INFO}[Ağ Üzerinden Giden Paket]{LogColors.ENDC}")
            print(paket)
            
            print(f"\n{LogColors.INFO}[Bob Paketi Teslim Aldı ve Doğruluyor]{LogColors.ENDC}")
            is_valid, log = bob.verify_packet(paket)
            if is_valid:
                print(f"{LogColors.OK}[✔] {log}{LogColors.ENDC}")
            else:
                print(f"{LogColors.FAIL}[✘] {log}{LogColors.ENDC}")
                
        elif secim == '2':
            orijinal_mesaj = input(f"{LogColors.OK}Orijinal mesajı yazın: {LogColors.ENDC}")
            paket_json = alice.create_secure_packet(orijinal_mesaj)
            print(f"Orijinal Paket: {paket_json}")
            
            sahte_mesaj = input(f"{LogColors.FAIL}Saldırgan olarak mesajı ne ile değiştirmek istersiniz?: {LogColors.ENDC}")
            
            # Sözlüğe çevirip mesaj kısmını manipüle ediyoruz (HMAC'e dokunmadan)
            paket_dict = json.loads(paket_json)
            paket_dict["message"] = sahte_mesaj
            tahrif_edilmis_paket = json.dumps(paket_dict)
            
            print(f"\n{LogColors.INFO}[Bob Değiştirilmiş Paketi Teslim Aldı ve Doğruluyor]{LogColors.ENDC}")
            is_valid, log = bob.verify_packet(tahrif_edilmis_paket)
            print(f"{LogColors.FAIL}[✘] {log}{LogColors.ENDC}")

        elif secim == '3':
            run_security_tests()
            
        elif secim == '4':
            print("Sistemden çıkılıyor...")
            break
        else:
            print("Geçersiz seçim. Lütfen tekrar deneyin.")

if __name__ == "__main__":
    interactive_mode()
