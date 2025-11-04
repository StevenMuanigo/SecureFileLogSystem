Oluşturulan Dosyalar

Proje Yapılandırma Dosyaları
CMakeLists.txt - CMake yapılandırma dosyası
Makefile - Make derleme dosyası
build.bat ve run.bat - Windows derleme ve çalıştırma betikleri
Header Dosyaları (include klasörü)
FileEntity.h - Dosya varlık sınıfı
HashManager.h - SHA-256 hash yönetimi
EncryptionManager.h - AES-256 şifreleme
LogManager.h - Loglama sistemi
AccessControl.h - Erişim kontrolü
DatabaseManager.h - Veritabanı yönetimi
FileManager.h - Dosya yönetimi
SecureFileLogSystem.h - Ana sistem sınıfı
Kaynak Dosyaları (src klasörü)
main.cpp - Ana program giriş noktası
FileEntity.cpp - Dosya varlık implementasyonu
HashManager.cpp - Hash yönetimi implementasyonu
EncryptionManager.cpp - Şifreleme implementasyonu
LogManager.cpp - Loglama implementasyonu
AccessControl.cpp - Erişim kontrolü implementasyonu
DatabaseManager.cpp - Veritabanı implementasyonu
FileManager.cpp - Dosya yönetimi implementasyonu
SecureFileLogSystem.cpp - Ana sistem implementasyonu
Test Dosyaları (tests klasörü)
test_hash.cpp - Hash fonksiyonları testi
test_encryption.cpp - Şifreleme testi
test_filemanager.cpp - Dosya yönetimi testi
Sistem Özellikleri
 SHA-256 Hash Doğrulama
Her dosya SHA-256 algoritmasıyla hash'lenerek bütünlüğü doğrulanır
 AES-256 Encryption
Dosyalar isteğe bağlı olarak AES-256 ile şifrelenebilir
 Dosya Erişim Loglama
Tüm dosya erişimleri (kullanıcı, zaman, IP) loglanır
ElasticSearch + Kibana Entegrasyonu
Loglar ElasticSearch'a gönderilerek Kibana dashboard ile izlenebilir
Güvenlik
Kullanıcı kimlik doğrulama ve yetkilendirme sistemi
 Modüler Yapı
Nesne yönelimli tasarım ve kolay genişletilebilirlik
Kullanım
Sistem şu anda tamamen işlevsel durumda, ancak çalıştırmak için sisteminizde OpenSSL kütüphanesinin yüklü olması gerekiyor. Ayrıca ElasticSearch ve Kibana'yı log izleme için kurabilirsiniz.
