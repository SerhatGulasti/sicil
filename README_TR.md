[EN](README.md) | **TR**

# Sicil

Sicil, CachyOS'ta kurulu paketlerde bilinen güvenlik sorunu olup olmadığına günde bir kez bakan
küçük bir araç. Bulduklarını, paket kullanımını kaydeden [Yoklama](https://github.com/SerhatGulasti/yoklama)'dan gelen son kullanım
bilgisiyle birleştirip sonucu neye bakmaya değdiğine göre sıralar.

Sicil yalnız okur ve raporlar. Paket kurmaz, güncellemez, kaldırmaz. Root istemez, [Yoklama](https://github.com/SerhatGulasti/yoklama)'ya da
hiçbir şey yazmaz. Sicil bozulursa [Yoklama](https://github.com/SerhatGulasti/yoklama) etkilenmez.

## Gereksinimler

- CachyOS ya da pacman kullanan başka bir sistem, günlük çalıştırma için systemd
- Python 3.10 ya da üstü (yalnız standart kütüphane)
- `arch-audit`, `git`, `pactree` (`pacman-contrib` paketinden), `notify-send`
- İsteğe bağlı: son kullanım tarihleri ve sök önerileri için [Yoklama](https://github.com/SerhatGulasti/yoklama).
  Yoksa Sicil tek satırlık notla aynı şekilde çalışır, yalnız son kullanım sütunu ve sök bölümü çıkmaz,
  `--unused` ile `--used` de çalışmayı reddeder.
- Çekirdek CVE kayıtları için yaklaşık 300 MB disk

## Kurulum

Sicil kaynak ağacından çalışır, servis de bu ağacı `~/.daemons/sicil` altında bekler.

```sh
systemctl --user link ~/.daemons/sicil/systemd/sicil.service ~/.daemons/sicil/systemd/sicil.timer
systemctl --user enable --now sicil.timer
ln -s ~/.daemons/sicil/bin/sicil ~/.local/bin/sicil    # `sicil` diye çağırmak için
```

Zamanlayıcı her gün 10.00 civarında çalışır. Servis `nm-online` bağlantıyı bildirince ya da iki
dakika sonra başlar. Bilgisayar kapalıyken kaçan çalıştırma bir sonraki açılışta yapılır.
Kullanıcı zamanlayıcıları yalnız oturum açıkken çalışır, bildirim de zaten ancak o zaman görülür.

İlk çalıştırma çekirdek CVE kayıtlarını klonladığı için yaklaşık bir dakika sürer.

## Kullanım

```sh
sicil run                # kaynakları kontrol et, değişeni kaydet
sicil report             # açık bulguları göster (ağa çıkmaz, yalnız okur)
sicil report --all       # kapanan bulguları da göster
sicil report --json      # tam listelerle JSON çıktısı
sicil show <id>          # tek kayıt, şu an kurulu sürüme göre
```

`sicil run` yeni sorun olup olmadığını, neyin değiştiğini ve çekirdeklerin durumunu birkaç cümleyle
söyler:

```text
No new problems.
Standing: 15 can't be verified, 6 look closed.
linux-cachyos: 7.3.1; latest in its branch.
linux-cachyos-lts: 6.18.55 (running); branch latest 6.18.60, 5 behind; repo still has 6.18.55-2.
Details: sicil report
```

`sicil report` terminal genişliğine uyar. Sığmayan tablo en az önemli sütunlarını bırakıp hangilerini
bıraktığını yazar, pipe'a giden çıktıda ise hiçbir şey kısalmaz.

```text
Last run: 2026-11-06 09:44 (repo ok, aur ok, kernel ok, yoklama ok)

Red: none

Yellow: none

Removal suggestions: none

Can't verify: record is old, installed version is newer
  ID                   SEVERITY  EPSS   RANGE    INSTALLED   RECORD
  wget:CVE-2021-31879  Medium    0.011  unknown  1.25.0-6.1  1.21.3-1
    GNU Wget through 1.21.1 does not omit the Authorization header upon a redirect to a different...

Looks closed: installed version is outside every CVE's affected range
  ID                 SEVERITY  CVSS     EPSS   RANGE    INSTALLED  RECORD   LAST USED
  pam:CVE-2025-6020  High      7.8 CNA  0.005  outside  1.7.3-1.1  1.7.0-2  2026-11-06
    A flaw was found in linux-pam. The module pam_namespace may use access user-controlled paths...

Kernels: for information, nothing to do now
  linux-cachyos-lts
    6.18.55 (running); branch latest 6.18.60, 5 behind; repo still has 6.18.55-2; 873 records cover
    this version; 6.18.60 fixes 737 of them, 136 remain

Not found in AUR: none
```

Her satır kopyalanabilir bir ID ile başlar, açıklama da satırın altında durur. Bütün satırlarda boş
olan sütun çıkmaz, bütün satırlarda aynı olan değer tablonun üstüne taşınır.

Son çalıştırma 36 saatten eskiyse ya da eksik kaldıysa başlıkta uyarı çıkar. Yoklama'nın gözlem
süresi kısaysa onun uyarısı da buraya gelir. Komut çıktısı İngilizce.

### Filtreler

Filtreler `sicil report` ile çalışır, `--json` verildiğinde de geçerlidir. Farklı filtrelerin hepsi
tutmalıdır, aynı filtre tekrarlanırsa biri tutması yeter: `-p pam -p libxml2 -c 7`, "pam ya da
libxml2, CVSS'i de 7 ve üstü" demektir.

| Ne | Bayrak | Kural |
| --- | --- | --- |
| Paket | `-p`, `--package <ad>` | Joker çalışır: `'lib*'` |
| CVE | `--cve <id>` | Joker çalışır: `'CVE-2021-*'`. Çekirdekte eşleşen ID'leri listeler |
| Ciddiyet | `-s`, `--severity <seviye>` | Bu seviye ve üstü: `-s medium` medium, high ve critical demektir. Unknown yalnız `-s unknown` ile gelir |
| CVSS | `-c`, `--min-cvss <puan>` | Bu puan ve üstü. CNA'nın puanı, o yoksa CISA-ADP'ninki |
| Son kullanım | `--unused <gün>`, `--used <gün>` | Hiç kullanılmamış paket kullanılmayan sayılır. Yoklama'nın ölçemediği paket listelenmez, `no last-used date` diye sayılır. Yoklama yoksa boş liste dönmez, hata verir |
| Kurulu sürüm | `--installed-min`, `--installed-max` | Metin olarak değil, pacman'ın `vercmp` kuralıyla karşılaştırılır |
| Kayıt sürümü | `--record-min`, `--record-max` | Aynı kural |
| Durum | `--status <durum>` | `open`, `unverified`, `looks-closed` |

Filtrelenen alanı boş olduğu için elenen kayıt kaybolmaz, raporun sonunda alan başına sayılır:
`3 records hidden: no CVSS`. Filtreli rapor bunu en üstte de söyler, böylece `Red: none` "her şey
temiz" diye okunmaz. Program çalıştıran tek filtre sürüm filtreleridir, o da `vercmp`'i çalıştırır.

### ID'ler ve `sicil show`

ID `paket:CVE` biçimindedir, örneğin `pam:CVE-2025-6020`. İki makine birbirini görmeden aynı ID'yi
bulur. Sürüm ID'ye girmez, `sicil show` kurulu sürümü sorduğunuz anda okur. AUR bulguları olay
olduğu için ID almaz.

```text
pam:CVE-2025-6020
Installed 1.7.3-1.1 · looks closed

A flaw was found in linux-pam. The module pam_namespace may use access user-controlled paths without
proper protection, allowing local users to elevate their privileges to root via multiple symlink
attacks and race conditions.

Severity   High
CVSS       7.8 (CNA)
EPSS       0.005
KEV        no
Range      outside
Record     1.7.0-2
Last used  2026-11-06
Tracker    https://security.archlinux.org/CVE-2025-6020
Source     https://www.cve.org/CVERecord?id=CVE-2025-6020
```

- `sicil show CVE-2025-6020` bu makinede o CVE'nin geçtiği bütün paketleri listeler.
- `-f`, `--field <alan>` betikler için tek alanı yalın basar: `desc`, `installed`, `status`,
  `severity`, `cvss`, `epss`, `kev`, `range`, `record`, `fixed`, `last-used`, `url`.
- Kurulu olup bulgusu olmayan paket için tam olarak bu yazar, çünkü bulgu olmaması etkilenmediğini
  kanıtlamaz. Kurulu olmayan paket için `Not installed` yazar.
- `show` veritabanını salt okunur açar, sürümü pacman'a sorar, ağa çıkmaz. Çekirdekte kaydı yerel
  kopyadan da okur.

## Bölümlerin anlamı

| Bölüm | Resmi paketler | AUR paketleri | Çekirdekler |
| --- | --- | --- | --- |
| Red (kırmızı) | Ciddiyeti High ya da Critical olan bulgular, sürüm aralığının dışarıda bırakmadığı KEV'deki CVE'ler | Maintainer değişmiş, sahipsiz paket sahiplenilmiş ya da paket AUR'dan çıkmış | Bu sürümü kapsayan bir CVE KEV'de |
| Yellow (sarı) | Ciddiyet Low, Medium ya da Unknown | Sahipsiz, out-of-date işaretli ya da yeni co-maintainer gelmiş | Depoda daha yeni sürüm var ya da dal EOL |
| Removal suggestions (sök önerisi) | Aşağıda | Aşağıda | Verilmez |
| Can't verify (doğrulanamıyor) | Takip kaydında düzeltme yok, kurulu sürüm de kayıttakinden yeni | | |
| Looks closed (kapanmış görünüyor) | Doğrulanamayan gibi ama her CVE'nin etkilenen aralığı kurulu sürümü dışarıda bırakıyor | | |
| Kernels (çekirdekler) | | | Geride olsun olmasın, şu an yapılacak bir şey yok |
| Not found in AUR | | Sicil ilk baktığından beri AUR'da yok | |

Yeni kırmızı bulgu masaüstü bildirimi gönderir, birden fazlaysa hepsi tek özette toplanır. Başka
hiçbir şey bildirim üretmez, aynı bulgu da ikinci kez bildirilmez.

Tek seferlik AUR olayları 7 gün açık kalıp kendiliğinden kapanır, böylece raporu sonradan okuyan da
görür. Sahipsizlik gibi süren durumlar sürdükleri kadar açık kalır.

Arch takip kaydında düzeltilmiş sürüm yoksa `arch-audit` daha yeni bütün sürümleri de raporlar, yani
eski bir kayıt hiç kapatılmamış olabilir. **Doğrulanamıyor** bölümü bu yüzden var. Sicil bu bulguları
alarmların dışında tutar ama göstermeyi sürdürür.

**Kapanmış görünüyor** kararı için üç koşul gerekir: CVE kaydında paketin kendisini adlandıran bir
satırda makine okunur sürüm aralığı olmalı, o satır listede olmayanların etkilenmediğini söylemeli,
kurulu sürüm de aralığın dışında kalmalı. Dağıtımların satırları yok sayılır, serbest metin hiç
ayrıştırılmaz. Yanlış yere "kapandı" demek, hiç dememekten kötü.

**Sök önerisi** ancak paketleri kaldırmak açığı olan paketi gerçekten sistemden çıkaracaksa verilir.
Sicil bağımlılık zincirini `pactree -ru` ile yukarı doğru izleyip hiçbir paketin gerektirmediği
paketleri (`pacman -Qqtt`) bulur. Bunların hepsi Yoklama'nın ölçümüne göre 60 gündür kullanılmamış
olmalı, hiçbiri korunan ya da ölçülemeyen paket olmamalı. Bu koşullar tutmazsa rapor yalnız paketi
nelerin çektiğini gösterir. Yoklama 60 gün gözlem yapmadan öneri üretilmez. Doğrulanamayan ve kapanmış
görünen bulgular ile çekirdekler hiç öneri almaz.

CVSS ve EPSS seviye değiştirmez. EPSS kurulu sürümü bilmez: gerçek bir rapordaki en yüksek değer,
kurulu sürümden çok önce düzeltilmiş bir CVE'ye aitti.

## Çekirdekler

Çekirdeğin CVE ekibi neredeyse her düzeltmeye kayıt açar, bu yüzden dalının gerisinde kalan bir
çekirdeği birbirinden ayırması zor yüzlerce kayıt kapsar. Sicil de liste yerine çekirdek başına tek
satır yazar, tam liste `--json` çıktısında. Yalnız `linux-cachyos` ve `linux-cachyos-lts` kontrol
edilir. Paket güncellendiği hâlde makine eski çekirdekle çalışıyorsa satırda yeniden başlatma
beklediği yazar.

## Nasıl çalışır

Her çalıştırma önce kaynakları okur, sonra sonucu tek transaction'da kaydeder. Başarısız olan kaynak
yalnız kendi şeridini (resmi paketler, AUR ya da çekirdek) atlatır: o şeridin önceki durumu korunur,
hiçbir bulgusu kapanmaz, rapor da çalıştırmanın eksik kaldığını söyler.

| Kaynak | Ne için | Ne zaman |
| --- | --- | --- |
| `arch-audit`, [security.archlinux.org](https://security.archlinux.org/) verisiyle | Resmi paket bulguları | Her çalıştırma |
| [AUR RPC](https://aur.archlinux.org/rpc/) | Maintainer ve out-of-date durumu | Her çalıştırma |
| [cvelistV5](https://github.com/CVEProject/cvelistV5) | Açıklama, CVSS, sürüm aralıkları | Yeni CVE'ler, kapanmamışlar bir hafta sonra yeniden |
| [EPSS](https://www.first.org/epss/) | Raporda gösterilen değer | Her çalıştırma |
| [CISA KEV](https://github.com/cisagov/kev-data) | Sömürüldüğü bilinen CVE'ler | Her çalıştırma |
| [Çekirdek CVE kayıtları](https://git.kernel.org/pub/scm/linux/security/vulns.git) | Her çekirdeği kapsayan kayıtlar | Her çalıştırma, JSON dosyalarının sığ güncellemesi |
| [kernel.org](https://www.kernel.org/releases.json) | Dal başına son sürüm ve EOL | Her çalıştırma |
| `yoklama report` | Son kullanım, boştaki paketler, gözlem süresi | Her çalıştırma |

Durum bilgisi `~/.local/state/sicil/` altında tutulur: `sicil.db` ve `kernel-vulns` klasörü.

| Modül | Görevi |
| --- | --- |
| `sicil/sources.py` | Dışarıdan okunan her şey |
| `sicil/rules.py` | Resmi ve AUR paketlerinin seviyeleri, sök kuralı |
| `sicil/cve.py` | CVE kayıtlarını okuma, sürüm kararı |
| `sicil/enrich.py` | CVE önbelleği, KEV ve EPSS |
| `sicil/kernel.py` | Çekirdek şeridi |
| `sicil/store.py` | SQLite depolama ve migration |
| `sicil/run.py` | Bir `sicil run` çalıştırması |
| `sicil/report.py` | `report` komutu ve düzeni |
| `sicil/filters.py` | `report` filtreleri |
| `sicil/show.py` | `show` komutu |

## Sınırlar

Raporu ipucu olarak okuyun.

- "Kapanmış görünüyor" upstream sürümlerle ilgili, CVE kaydındaki aralıklara güvenir.
- Pek çok CVE kaydında kullanılabilir sürüm aralığı olmadığı için karar verilemez, bunlar
  Doğrulanamıyor bölümünde kalır. Paket adı da kayıttaki ürün adıyla uyuşmayabilir.
- Çekirdek sayıları yalnız sürüme bakar. CachyOS'un kendi yamaları ve çekirdeğin yapılandırması hesaba
  katılmaz, yani kayıt derlenmemiş bir modülle ilgili olabilir. Rapor bu yüzden sürümde o kadar açık
  olduğunu söylemez, kayıtların sürümü "kapsadığını" söyler. CVE'ler çoğu zaman düzeltmeden sonra
  açıldığı için kaçırılan düzeltme sayısı gerçekte daha yüksek olabilir.
- "Depoda daha yeni sürüm var" bilgisi son pacman eşitlemesine dayanır. Sicil root istemediği için
  paket listelerini kendisi yenilemez.
- İki çekirdek dışında, yalnız CachyOS depolarında bulunan paketlere bakılmaz. Arch takip listesi
  onları bilmez.
- AUR paketlerine CVE kontrolü yapılmaz. AUR adları upstream projelerle güvenilir biçimde eşleşmediği
  için bu paketlerden yalnız güvenilirlik sinyalleri toplanır.
- `--unused` ile `--used`, Yoklama'nın ölçemediği paket hakkında bir şey söylemez. Böyle bir paket
  Yoklama görmeden kullanılıyor olabilir, bu yüzden iki filtre de onu listelemez. Raporun sonunda
  `no last-used date` diye sayılır.

## Geliştirme

```sh
python3 -B -m unittest discover -s tests
```

Testler kaydedilmiş yanıtları ve geçici bir git deposunu kullanır, ağa hiç çıkmaz. Gerçek durumunuza
dokunmadan denemek için `--db` kullanın. Çekirdek klasörü verdiğiniz veritabanının yanında tutulur.

## Kaldırma

```sh
systemctl --user disable --now sicil.timer
rm ~/.local/bin/sicil
```

Toplanan veri `~/.local/state/sicil` altında kalır, istemiyorsanız onu da silin.
