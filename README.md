# 🛡️ Ağ Trafiği Anomali Tespit ve IDS Sistemi (Real-Time Network Intrusion Detection System)

Bu proje; **CICIDS2017** veri seti kullanılarak geliştirilmiş, gerçek zamanlı ağ trafiğini dinleyen ve çift kademeli yapay zeka mimarisiyle siber saldırıları tespit eden hibrit bir Ağ Güvenlik ve İzleme (IDS) sistemidir. 

---

## 👥 Geliştirme Süreci ve Notlar
* Projenin ilk temelleri bir ekip çalışması olarak **Ramazan VANLIOĞLU** ile atılmış, ardından **Abdullah Özdemir** tarafından mimari geliştirilmiş.

---

## 🧠 Yapay Zeka ve Model Mimarisi

Sistem, yüksek doğruluk ve performans sağlamak için **iki kademeli (hibrit) bir karar mekanizması** üzerine kurulmuştur:

1. **1. Kademe (Gatekeeper - Ağ Geçidi / İkili Sınıflandırma):** 
   - **XGBoost (Booster)** kullanılarak eğitilmiştir.
   - Gelen ağ akışının normal mi yoksa şüpheli/saldırı mı olduğunu hızlıca (`0` veya `1`) filtreler.
2. **2. Kademe (Expert Model - Uzman Model / Çoklu Sınıflandırma):** 
   - Eğer ilk kademede saldırı şüphesi tespit edilirse (`prob > 0.5`), akış **Random Forest** modeline yönlendirilir.
   - Bu model; saldırının türünü (örn. DoS, Port Scan, Botnet vb.) spesifik olarak sınıflandırır ve güven skorunu hesaplar.

---

## 🛠️ Kullanılan Teknolojiler

* **Yapay Zeka & Veri İşleme:** Python, Scikit-Learn, XGBoost, Pandas, NumPy, Joblib, Google Colab (Veri ön işleme ve eğitim aşaması)
* **Ağ Analizi & Simülasyon:** Scapy, Socket
* **Backend:** Flask, Flask-SocketIO
* **Frontend (Arayüz):** React, CSS, WebSocket tabanlı canlı veri akışı

---

## 📂 Veri Seti ve Eğitim
* Projede **CICIDS2017** birleştirilmiş ve temizlenmiş veri seti kullanılmıştır.
* Ham ağ verileri ön işleme adımlarından geçirilmiş, modelin beklentisine uygun matris formatına getirilerek (`canli_test_seti.csv`) modeller eğitilmiştir.

---

## ⚙️ Kurulum ve Çalıştırma

Projeyi yerel bilgisayarınızda çalıştırmak için aşağıdaki adımları takip edebilirsiniz:

### 1. Projeyi Klonlayın
- git clone https://github.com/abdullahOzdemirr/network-anomaly-detection.git
- cd network-anomaly-detection

### 2. React Frontend (Arayüz) Tarafını Başlatın
- npm install
- npm start

### 3. Python Backend (Sunucu) Tarafını Başlatın
- python server.py

### Tarayıcınızdan http://localhost:3000 adresine giderek gerçek zamanlı anomali tespit panelini görüntüleyebilirsiniz.