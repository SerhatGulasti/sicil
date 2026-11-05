[EN](README.md) | **TR**

# Sicil

CachyOS'ta kurulu paketlerin bilinen güvenlik sorunları olup olmadığını günde bir kez
kontrol eden küçük bir araç. Bulduklarını, paket kullanımını kaydeden ayrı bir araç olan
Yoklama'nın her paketi en son ne zaman kullanılmış gördüğüyle birleştirir ve sonucu neyin
ilginizi hak ettiğine göre sıralar.

Sicil yalnızca okur ve raporlar. Hiçbir paketi kurmaz, güncellemez veya kaldırmaz, root
istemez, Yoklama'ya hiçbir şey yazmaz. Sicil bozulursa Yoklama etkilenmez.

## Gereksinimler

- CachyOS ya da pacman kullanan başka bir sistem; günlük çalışma için systemd
- Python 3.10 veya üstü (yalnız standart kütüphane)
- `arch-audit`, `git`, `pactree` (`pacman-contrib` paketinden), `notify-send`
- Son kullanım tarihleri ve sök önerileri için `yoklama`. Yoksa çalıştırma uyarıyla sürer.
- Çekirdek CVE kayıtları için yaklaşık 300 MB disk

## Kurulum

Sicil kaynak ağacından çalışır, servis de bu ağacı `~/.daemons/sicil` altında bekler.

```sh
systemctl --user link ~/.daemons/sicil/systemd/sicil.service ~/.daemons/sicil/systemd/sicil.timer
systemctl --user enable --now sicil.timer
ln -s ~/.daemons/sicil/bin/sicil ~/.local/bin/sicil    # `sicil` diye çağırmak için
```

Zamanlayıcı her gün 10:00 civarında çalışır; `nm-online` bağlantı olduğunu söyleyince ya da
iki dakika sonra başlar. Bilgisayar kapalıyken kaçan çalıştırma bir sonraki açılışta yapılır.
Kullanıcı zamanlayıcıları yalnız oturum açıkken çalışır; bildirim de zaten o zaman görülebilir.

İlk çalıştırma yaklaşık bir dakika sürer, çünkü çekirdek CVE kayıtlarını klonlar.

## Kullanım

```sh
sicil run                # kaynakları kontrol et, değişeni kaydet
sicil report             # açık bulguları göster; ağa çıkmaz, yalnız okur
sicil report --all       # kapanan bulgular da
sicil report --json      # betikler için JSON, tam listelerle
```

```text
Last run: 2026-11-05 23:40 (repo ok, aur ok, kernel ok, yoklama ok)

Red: none

Yellow: none

Removal suggestions: none

Unverified (no fix recorded, installed version is newer than the record)
  PACKAGE  SEVERITY  CVE             CVSS  EPSS   VERSION  INSTALLED   RECORD    LAST USED   DESCRIPTION
  wget     Medium    CVE-2021-31879  -     0.011  unknown  1.25.0-6.1  1.21.3-1  -           GNU Wget through 1.21.1 does not omit the Authorization header upon...

Looks closed (installed version is outside every CVE's affected range)
  PACKAGE  SEVERITY  CVE            CVSS     EPSS   VERSION  INSTALLED  RECORD   LAST USED   DESCRIPTION
  pam      High      CVE-2025-6020  7.8 CNA  0.005  closed   1.7.3-1.1  1.7.0-2  2026-11-05  A flaw was found in linux-pam. The module pam_namespace may use acc...

Kernels (for information, nothing to do now)
  PACKAGE            SUMMARY
  linux-cachyos-lts  6.18.55 (running); branch latest 6.18.60, 5 behind; repo still has 6.18.55-2; 873 records cover this version; 6.18.60 fixes 737 of them, 136 remain

Not found in AUR: none
```

Başlık, son çalıştırma 36 saatten eskiyse ya da eksik kaldıysa uyarır ve Yoklama'nın kısa
gözlem süresi uyarısını da taşır. Komut çıktısı İngilizcedir.

## Bölümler ne anlama geliyor

| Bölüm | Resmi paketler | AUR paketleri | Çekirdekler |
| --- | --- | --- | --- |
| Red (kırmızı) | Ciddiyet High veya Critical, ya da sürüm aralığının dışarıda bırakmadığı KEV'deki bir CVE | Maintainer el değiştirdi, sahipsiz paket sahiplenildi ya da paket AUR'dan silindi | Bu sürümü kapsayan bir CVE KEV'de |
| Yellow (sarı) | Ciddiyet Low, Medium veya Unknown | Sahipsiz, out-of-date işaretli ya da yeni co-maintainer | Depoda daha yeni sürüm var ya da dal EOL |
| Removal suggestions (sök önerisi) | Aşağıya bakın | Aşağıya bakın | Hiçbir zaman |
| Unverified (doğrulanmamış) | Takip kaydında düzeltme yok ve kurulu sürüm kayıttakinden yeni | | |
| Looks closed (kapanmış görünüyor) | Unverified gibi, ama her CVE'nin etkilenen aralığı kurulu sürümü dışarıda bırakıyor | | |
| Kernels (çekirdekler) | | | Geride olsun olmasın, şu an yapılacak bir şey yok |
| Not found in AUR | | Sicil'in ilk baktığı andan beri AUR'da yok | |

Yeni bir kırmızı bulgu tek masaüstü bildirimi gönderir, birden fazlaysa tek bir özet. Başka
hiçbir şey bildirim üretmez, aynı bulgu ikinci kez bildirilmez.

Tek seferlik AUR olayları 7 gün açık kalır ve sonra kendiliğinden kapanır, böylece raporu
sonradan okuyan da görür. Sahipsizlik gibi süren durumlar sürdükleri kadar açık kalır.

**Doğrulanmamış neden var?** Arch takip kaydında düzeltilmiş sürüm yoksa `arch-audit` daha yeni
bütün sürümleri de raporlar, yani eski bir kayıt hiç kapatılmamış olabilir. Sicil bunları
alarmların dışında tutar ama göstermeye devam eder.

**Kapanmış görünüyor nasıl belirlenir?** Bir CVE ancak kaydında paketin kendisini adlandıran bir
satırda makine okunur sürüm aralığı varsa, o satır listede olmayanların etkilenmediğini
söylüyorsa ve kurulu sürüm aralığın dışındaysa kapalı sayılır. Dağıtımların satırları yok sayılır,
serbest metin hiç ayrıştırılmaz: yanlış "kapandı" demek, hiç dememekten kötüdür.

**Sök önerisi** ancak paketleri kaldırmak açıklı paketi gerçekten sistemden çıkaracaksa verilir.
Sicil bağımlılık zincirini `pactree -ru` ile hiçbir paketin gerektirmediği paketlere
(`pacman -Qqtt`) kadar yürür. Bunların hepsi Yoklama'nın ölçümüyle 60 gündür kullanılmamış
olmalı, hiçbiri korunan ya da ölçülemez olmamalı. Aksi halde rapor yalnız paketi nelerin çektiğini
gösterir. Yoklama 60 gün gözlem yapmadan öneri üretilmez. Doğrulanmamış ve kapanmış görünen
bulgular ile çekirdekler hiç öneri almaz.

**CVSS ve EPSS seviye değiştirmez.** EPSS kurulu sürümü bilmez: gerçek bir raporumuzdaki en yüksek
değer, kurulu sürümden çok önce düzeltilmiş bir CVE'ye aitti.

## Çekirdekler

Çekirdeğin CVE ekibi neredeyse her düzeltmeye kayıt açıyor. Bu yüzden dalının gerisindeki bir
çekirdek, birbirinden ayırması zor yüzlerce kayıtla kapsanır. Sicil bu nedenle liste yerine
çekirdek başına tek satır yazar; tam liste `--json` içindedir. Yalnız `linux-cachyos` ve
`linux-cachyos-lts` kontrol edilir. Paket güncellenmiş ama makine eski çekirdekle çalışıyorsa
satırda yeniden başlatma beklediği yazar.

## Nasıl çalışır

Her çalıştırma önce kaynakları okur, sonra sonucu tek işlemde kaydeder. Başarısız olan kaynak
yalnız kendi şeridini atlatır: o şeridin önceki durumu korunur, hiçbir şeyi kapanmaz ve rapor
çalıştırmanın eksik kaldığını söyler.

| Kaynak | Ne için | Ne zaman |
| --- | --- | --- |
| `arch-audit`, [security.archlinux.org](https://security.archlinux.org/) verisiyle | Resmi paket bulguları | Her çalıştırma |
| [AUR RPC](https://aur.archlinux.org/rpc/) | Maintainer ve out-of-date durumu | Her çalıştırma |
| [cvelistV5](https://github.com/CVEProject/cvelistV5) | Açıklama, CVSS, sürüm aralıkları | Yeni CVE'ler; kapanmamışlar bir hafta sonra yeniden |
| [EPSS](https://www.first.org/epss/) | Raporda gösterilen değer | Her çalıştırma |
| [CISA KEV](https://github.com/cisagov/kev-data) | Sömürüldüğü bilinen CVE'ler | Her çalıştırma |
| [Çekirdek CVE kayıtları](https://git.kernel.org/pub/scm/linux/security/vulns.git) | Her çekirdeği kapsayan kayıtlar | Her çalıştırma, JSON dosyalarının sığ güncellemesi |
| [kernel.org](https://www.kernel.org/releases.json) | Dal başına son sürüm ve EOL | Her çalıştırma |
| `yoklama report` | Son kullanım, boştaki paketler, gözlem süresi | Her çalıştırma |

Durum `~/.local/state/sicil/` altında durur: `sicil.db` ve `kernel-vulns` klasörü.

| Modül | Görevi |
| --- | --- |
| `sicil/sources.py` | Dışarıdan okunan her şey |
| `sicil/rules.py` | Resmi ve AUR paketlerinin seviyeleri, sök kuralı |
| `sicil/cve.py` | CVE kayıtlarını okuma, sürüm kararı |
| `sicil/enrich.py` | CVE önbelleği, KEV ve EPSS |
| `sicil/kernel.py` | Çekirdek şeridi |
| `sicil/store.py` | SQLite depolama ve taşıma |
| `sicil/run.py` | Bir `sicil run` |
| `sicil/report.py` | `report` komutu |

## Sınırlar

Rapor bir ipucudur, hüküm değil.

- **"Kapanmış görünüyor" upstream sürümlerle ilgilidir.** CVE kaydındaki aralıklara güvenir.
- **Birçok kayda karar verilemez.** CVE kayıtlarının birçoğunda kullanılabilir sürüm aralığı yok;
  bunlar Doğrulanmamış kalır. Paket adı kayıttaki ürün adıyla da uyuşmayabilir.
- **Çekirdek sayıları yalnız sürüme bakar.** CachyOS'un kendi yamaları ve çekirdeğin yapılandırması
  hesaba katılmaz, yani kayıt derlenmemiş bir modülle ilgili olabilir. Bu yüzden rapor bir sürümde
  o kadar açık olduğunu değil, kayıtların o sürümü "kapsadığını" söyler. Kaçırılan düzeltme
  sayısı bir alt sınırdır, çünkü CVE'ler çoğu zaman düzeltmeden sonra açılır.
- **"Depoda daha yeni sürüm var" son pacman eşitlemesine bakar.** Sicil root istemediği için
  paket listelerini kendisi yenilemez.
- **Yalnız CachyOS depolarında olan paketler kapsam dışıdır,** iki çekirdek hariç. Arch takip
  listesi onları bilmez.
- **AUR paketlerine CVE kontrolü yapılmaz.** AUR adları upstream projelerle güvenilir biçimde
  eşleşmez, bu yüzden onlar için yalnız güvenilirlik sinyalleri toplanır.

## Geliştirme

```sh
python3 -B -m unittest discover -s tests
```

Testler kaydedilmiş yanıtları ve geçici bir git deposunu kullanır, ağa hiç çıkmaz. Gerçek
durumunuza dokunmadan denemek için `--db` kullanın. Çekirdek klasörü verdiğiniz veritabanının
yanında tutulur.

## Kaldırma

```sh
systemctl --user disable --now sicil.timer
rm ~/.local/bin/sicil
```

Toplanan veri `~/.local/state/sicil` altında kalır; istemiyorsanız onu da silin.
