# SolPWCapture

SolPWCapture, modem veya router cihazlarından PPPoE kullanıcı adı ve şifresini yakalamak için tasarlanmış bir araçtır. Bu araç, kendisini bir PPPoE sunucusu (Fake Server) olarak tanıtarak modemin kimlik doğrulama bilgilerini (PAP protokolü üzerinden) ele geçirir.

## Özellikler

- **PADI/PADO Keşif:** Gelen PADI paketlerine yanıt vererek modemi kandırır.
- **LCP Onayı:** Modem ile LCP (Link Control Protocol) görüşmesini tamamlar.
- **PAP Kimlik Doğrulama:** PAP (Password Authentication Protocol) üzerinden kullanıcı adı ve şifreyi yakalar.
- **VLAN Desteği:** 802.1Q VLAN etiketli paketleri otomatik olarak algılar ve VLAN ID bilgisini gösterir.
- **MAC Adresi Tespiti:** Bağlanan cihazın MAC adresini raporlar.

## Gereksinimler

- Python 3.12+
- `scapy` kütüphanesi
- Ağ kartı (Ethernet/Wi-Fi) üzerinde paket dinleme ve gönderme yetkisi (Genellikle `root` veya `sudo` gerektirir).

## Kurulum

1. Depoyu klonlayın veya dosyaları indirin.
2. Bir sanal ortam oluşturun (isteğe bağlı ama önerilir):
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # macOS/Linux için
   # veya
   .venv\Scripts\activate     # Windows için
   ```
3. Gerekli kütüphaneleri yükleyin:
   ```bash
   pip install -r requirements.txt
   ```

## Kullanım

1. `main.py` dosyasını açın ve `IFACE` değişkenini kendi ağ arayüzünüzün adıyla (örneğin: `en0`, `eth0`, `en7` vb.) güncelleyin:
   ```python
   IFACE = "en7"  # Burayı kendi arayüzünüzle değiştirin
   ```
2. Uygulamayı yönetici yetkileriyle çalıştırın:
   ```bash
   sudo python main.py
   ```
3. Modemin WAN portunu bilgisayarınızın ağ kartına bağlayın (veya uygun bir ağ topolojisi kurun). Modem PPPoE bağlantısı kurmaya çalıştığında bilgiler ekranda görünecektir.

## Uyarı

Bu araç yalnızca eğitim ve ağ testleri amacıyla geliştirilmiştir. Yetkiniz olmayan ağlarda ve cihazlarda kullanılması yasal sonuçlar doğurabilir. Kullanıcı, aracın kullanımından doğacak her türlü sorumluluğu kabul eder.
