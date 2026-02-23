#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <cmath>
#include <cstdint>
#include <netdb.h>
#include <map>
#include <cstdlib>
#include <chrono>
#include <array>
#include <iomanip>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/kdf.h>
#include <openssl/err.h>

using namespace std;

constexpr char SERVER_HOSTNAME[] = "sentinel_gks";
constexpr int PORT = 5000;
constexpr double GPS_SCALE = 10000000.0;
constexpr double EARTH_RADIUS_KM = 6371.0;
constexpr double DEGREE_TO_METER = 111000.0;

enum class PacketMagic : uint8_t {
    HANDSHAKE_REQ = 0xDD,
    HANDSHAKE_RES = 0xEE,
    TELEMETRY = 0xFF,
    FEC_RECOVERY = 0xFE,
    ACKNOWLEDGE = 0xAA
};

enum class PriorityLevel : uint8_t {
    NORMAL = 0,
    CRITICAL = 1,
    FEC_PACKET = 2
};

enum class FlightMode : uint8_t {
    MANUAL = 0,
    AUTONOMOUS = 1,
    RTL = 2 
};

#pragma pack(push, 1)
struct PlaintextTelemetry {
    uint32_t seq_num;
    uint64_t timestamp;
    int32_t latitude;
    int32_t longitude;
    float altitude;
    float speed;
    float battery;
    uint8_t flight_mode;
    uint8_t priority;
};

struct EncryptedPacket {
    uint8_t magic_byte;
    int32_t uav_id;
    uint8_t iv[12];
    uint8_t ciphertext[sizeof(PlaintextTelemetry)];
    uint8_t auth_tag[16];
};

struct HandshakeRequest {
    uint8_t magic_byte = 0xDD;
    int32_t uav_id;
    uint8_t ephemeral_pub_key[65];
    uint8_t sig_len;
    uint8_t signature[72];
};

struct AckPacket {
    uint8_t magic_byte;
    uint32_t seq_num;
    uint64_t timestamp;
};
#pragma pack(pop)

struct UnackedPacket {
    PlaintextTelemetry pkt;
    uint64_t last_send_time;
    uint32_t current_timeout;
    uint8_t retry_count; 
};

double to_rad(double degree) { return degree * M_PI / 180.0; }
uint64_t get_time_ms() {
    return chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now().time_since_epoch()).count();
}

class UavLinkManager {
    private:
        int sockfd;
        struct sockaddr_in server_addr;
        std::map<uint32_t, UnackedPacket> unacked_packets;
        uint32_t send_interval = 1000;
        uint64_t current_ping = 0;
        int my_uav_id;
        
        uint8_t session_key[32]; 
        bool is_handshake_complete = false;

        std::array<PlaintextTelemetry, 3> fec_buffer{}; 
        int fec_counter = 0;

        uint32_t last_fec_seq = 0;

    public:
        UavLinkManager(int uav_id) : sockfd(-1), my_uav_id(uav_id) {} 
        ~UavLinkManager() { if (sockfd >= 0) close(sockfd); }
        uint32_t get_send_interval() const { return send_interval; }
        bool is_secure() const { return is_handshake_complete; }

        void init_socket(int port){
            if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) exit(EXIT_FAILURE);
            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(port);
            
            struct hostent *host = gethostbyname(SERVER_HOSTNAME);
            if(host != nullptr) memcpy(&server_addr.sin_addr, host->h_addr_list[0], host->h_length);
            
            struct timeval timeout{0, 10000};
            setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        }

        bool perform_handshake() {
            cout << "🔄 [HANDSHAKE] GKS ile güvenli el sıkışma başlatılıyor..." << endl;

            FILE* priv_fp = fopen("../keys/uav_private.pem", "r");
            FILE* pub_fp = fopen("../keys/gks_public.pem", "r");
            if (!priv_fp || !pub_fp) {
                cerr << "❌ [KRİTİK] Sertifikalar bulunamadı! '../keys' klasörünü kontrol et." << endl;
                return false;
            }
            EVP_PKEY* uav_priv_key = PEM_read_PrivateKey(priv_fp, NULL, NULL, NULL);
            EVP_PKEY* gks_pub_key = PEM_read_PUBKEY(pub_fp, NULL, NULL, NULL);
            fclose(priv_fp); fclose(pub_fp);

            if (!uav_priv_key || !gks_pub_key) {
                cerr << "❌ [KRİTİK] Anahtarlar okunamadı (PEM Format Hatası)!" << endl;
                return false;
            }

            EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
            EVP_PKEY_keygen_init(pctx);
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
            EVP_PKEY *ephemeral_key = NULL;
            EVP_PKEY_keygen(pctx, &ephemeral_key);
            EVP_PKEY_CTX_free(pctx);

            if (!ephemeral_key) {
                cerr << "❌ [KRİTİK] ECDH Geçici anahtarı üretilemedi!" << endl;
                return false;
            }

            size_t eph_pub_len = 65;
            uint8_t eph_pub_bytes[65];
            EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(ephemeral_key);
            const EC_GROUP *group = EC_KEY_get0_group(ec_key);
            const EC_POINT *point = EC_KEY_get0_public_key(ec_key);
            EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, eph_pub_bytes, eph_pub_len, NULL);
            EC_KEY_free(ec_key);

            HandshakeRequest req;
            req.uav_id = my_uav_id;
            memcpy(req.ephemeral_pub_key, eph_pub_bytes, 65);
            
            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, uav_priv_key);
            EVP_DigestSignUpdate(mdctx, &req.uav_id, sizeof(req.uav_id));
            EVP_DigestSignUpdate(mdctx, req.ephemeral_pub_key, 65);
            
            size_t sig_len;
            EVP_DigestSignFinal(mdctx, NULL, &sig_len);
            EVP_DigestSignFinal(mdctx, req.signature, &sig_len);
            req.sig_len = (uint8_t)sig_len;
            EVP_MD_CTX_free(mdctx);

            sendto(sockfd, &req, 1 + 4 + 65 + 1 + sig_len, 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
            cout << "📤 İHA Kimliği GKS'ye gönderildi. Cevap bekleniyor..." << endl;

            struct timeval tv{0, 500000};
            setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            
            uint8_t resp_buf[512];
            socklen_t addr_len = sizeof(server_addr);
            bool found_ee = false;
            uint64_t start_wait = get_time_ms();
            
            while(get_time_ms() - start_wait < 2500) { 
                int n = recvfrom(sockfd, resp_buf, sizeof(resp_buf), 0, (struct sockaddr*)&server_addr, &addr_len);
                if (n > 0 && resp_buf[0] == static_cast<uint8_t>(PacketMagic::HANDSHAKE_RES)) {
                    found_ee = true;
                    break;
                }
            }
            
            tv = {0, 10000};
            setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            if (!found_ee) {
                cout << "⚠️ GKS'den Handshake onayı alınamadı! Tekrar denenecek." << endl;
                EVP_PKEY_free(uav_priv_key); EVP_PKEY_free(gks_pub_key); EVP_PKEY_free(ephemeral_key);
                return false;
            }

            uint8_t* gks_pub_bytes = resp_buf + 1;
            uint8_t gks_sig_len = resp_buf[66];
            uint8_t* gks_sig = resp_buf + 67;

            EVP_MD_CTX *v_ctx = EVP_MD_CTX_new();
            EVP_DigestVerifyInit(v_ctx, NULL, EVP_sha256(), NULL, gks_pub_key);
            EVP_DigestVerifyUpdate(v_ctx, gks_pub_bytes, 65);
            if (EVP_DigestVerifyFinal(v_ctx, gks_sig, gks_sig_len) != 1) {
                cerr << "🛑 [SİBER SALDIRI] GKS imzası SAHTE! Bağlantı kesildi." << endl;
                EVP_MD_CTX_free(v_ctx);
                EVP_PKEY_free(uav_priv_key); EVP_PKEY_free(gks_pub_key); EVP_PKEY_free(ephemeral_key);
                return false;
            }

            EC_KEY *gks_ephemeral_ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
            EC_POINT *gks_point = EC_POINT_new(group);
            EC_POINT_oct2point(group, gks_point, gks_pub_bytes, 65, NULL);
            EC_KEY_set_public_key(gks_ephemeral_ec, gks_point);
            EVP_PKEY *gks_ephemeral_pkey = EVP_PKEY_new();
            EVP_PKEY_assign_EC_KEY(gks_ephemeral_pkey, gks_ephemeral_ec);

            EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(ephemeral_key, NULL);
            EVP_PKEY_derive_init(ctx);
            EVP_PKEY_derive_set_peer(ctx, gks_ephemeral_pkey);
            
            size_t secret_len;
            EVP_PKEY_derive(ctx, NULL, &secret_len);
            uint8_t* shared_secret = new uint8_t[secret_len];
            EVP_PKEY_derive(ctx, shared_secret, &secret_len);

            EVP_PKEY_CTX *hkdf_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
            EVP_PKEY_derive_init(hkdf_ctx);
            EVP_PKEY_CTX_set_hkdf_md(hkdf_ctx, EVP_sha256());
            EVP_PKEY_CTX_set1_hkdf_key(hkdf_ctx, shared_secret, secret_len);
            EVP_PKEY_CTX_add1_hkdf_info(hkdf_ctx, reinterpret_cast<const unsigned char*>("handshake"), 9);
            size_t key_len = 32;
            EVP_PKEY_derive(hkdf_ctx, session_key, &key_len);

            EVP_PKEY_CTX_free(hkdf_ctx); EVP_PKEY_CTX_free(ctx);
            delete[] shared_secret; EC_POINT_free(gks_point);
            EVP_PKEY_free(uav_priv_key); EVP_PKEY_free(gks_pub_key); 
            EVP_PKEY_free(ephemeral_key); EVP_PKEY_free(gks_ephemeral_pkey);

            cout << "🔐 [BAŞARILI] Zero Trust Doğrulaması Tamamlandı! AES-256 Oturum Anahtarı kilitlendi." << endl;
            is_handshake_complete = true;
            return true;
        }

        bool encrypt_data(const PlaintextTelemetry& plain_data, EncryptedPacket& enc_pkt, uint8_t magic) {
            enc_pkt.magic_byte = magic;
            enc_pkt.uav_id = my_uav_id;
            
            RAND_bytes(enc_pkt.iv, 12);

            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            int len, ciphertext_len;

            EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
            EVP_EncryptInit_ex(ctx, NULL, NULL, session_key, enc_pkt.iv);

            int outlen;
            EVP_EncryptUpdate(ctx, NULL, &outlen, (const unsigned char*)&enc_pkt.uav_id, sizeof(enc_pkt.uav_id));

            EVP_EncryptUpdate(ctx, enc_pkt.ciphertext, &len, (const unsigned char*)&plain_data, sizeof(PlaintextTelemetry));
            ciphertext_len = len;

            EVP_EncryptFinal_ex(ctx, enc_pkt.ciphertext + len, &len);
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, enc_pkt.auth_tag);
            EVP_CIPHER_CTX_free(ctx);
            
            return true;
        }

        void send_telemetry(PlaintextTelemetry& packet){
            if(!is_handshake_complete) return;

            EncryptedPacket secure_pkt{};
            if (!encrypt_data(packet, secure_pkt, static_cast<uint8_t>(PacketMagic::TELEMETRY))) return;

            sendto(sockfd, &secure_pkt, sizeof(secure_pkt), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));

            string prio_str = (packet.priority == 1) ? "[🔴 KRİTİK]" : "[🟢 AKAN]";
            cout << "📤 " << prio_str << " Pkt #" << packet.seq_num << " (Zero Trust) Gönderildi..." << endl;
            unacked_packets[packet.seq_num] = {packet, get_time_ms(), 500, 0};

            if(packet.priority == 1 && packet.seq_num > last_fec_seq){
                fec_buffer[fec_counter] = packet;
                fec_counter++;
                last_fec_seq = packet.seq_num;
                if(fec_counter == 3){
                    generate_and_send_fec();
                    fec_counter = 0;
                }
            }
        }

        void generate_and_send_fec(){
            PlaintextTelemetry plain_fec{};
            uint8_t* p1 = reinterpret_cast<uint8_t*>(&fec_buffer[0]);
            uint8_t* p2 = reinterpret_cast<uint8_t*>(&fec_buffer[1]);
            uint8_t* p3 = reinterpret_cast<uint8_t*>(&fec_buffer[2]);
            uint8_t* pf = reinterpret_cast<uint8_t*>(&plain_fec);

            for(size_t i = 0; i < sizeof(PlaintextTelemetry); i++){
                pf[i] = p1[i] ^ p2[i] ^ p3[i];
            }
            
            EncryptedPacket secure_fec{};
            if(encrypt_data(plain_fec, secure_fec, static_cast<uint8_t>(PacketMagic::FEC_RECOVERY))) {
                sendto(sockfd, &secure_fec, sizeof(secure_fec), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
                cout << "🚀 [FEC] ŞİFRELİ Kurtarma Paketi Gönderildi!" << endl;
            }
        }

        void listen_for_acks(){
            if(!is_handshake_complete) return;

            uint8_t buffer[32];
            socklen_t addr_len = sizeof(server_addr);
            int n = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&server_addr, &addr_len);

            if(n > 0){
                if(buffer[0] == 0xBB){
                    cout << "🔄 [KAOS KURTARMA] GKS bağlantıyı unutmuş! Yeniden el sıkışılacak..." << endl;
                    is_handshake_complete = false;
                    return;
                }
                if(buffer[0] == static_cast<uint8_t>(PacketMagic::ACKNOWLEDGE)){
                    AckPacket* ack = reinterpret_cast<AckPacket*>(buffer);
                    uint64_t now = get_time_ms();
                    current_ping = now - ack->timestamp;
                    cout << "   ✅ [GKS ONAYI] Pkt #" << ack->seq_num << " | Ping: " << current_ping << " ms" << endl;
                    unacked_packets.erase(ack->seq_num);
                }
            }
        }
};

int main(){
    srand(time(nullptr) ^ clock());
    int my_uav_id = 100 + (rand() % 900);
    if(getenv("UAV_ID")) my_uav_id = atoi(getenv("UAV_ID"));

    UavLinkManager link(my_uav_id);
    link.init_socket(PORT);

    cout << "🚁 İHA-" << my_uav_id << " (Otonom Zero-Trust Modu) Başlatıldı..." << endl;

    while(!link.is_secure()){
        link.perform_handshake();
        if(!link.is_secure()) sleep(2);
    }

    PlaintextTelemetry packet{};
    packet.battery = 100.0f;
    packet.flight_mode = static_cast<uint8_t>(FlightMode::AUTONOMOUS);
    packet.speed = 25.0f;
    double current_lat = 37.8000, current_lon = 32.4000;
    const double target_lat = 39.9208, target_lon = 32.8541;
    uint32_t current_seq = 1;
    uint64_t last_send_time = 0;

    while(true){
        if(!link.is_secure()){
            link.perform_handshake();
            if(!link.is_secure()) {
                sleep(1);
                continue;
            }
        }

        uint64_t current_time = get_time_ms();
        link.listen_for_acks();

        if(current_time - last_send_time >= link.get_send_interval()){
            double dLat = target_lat - current_lat;
            double dLon = target_lon - current_lon;
            double dist = sqrt(dLat*dLat + dLon*dLon);

            if(dist > 0.0001){
                double move_deg = (packet.speed * (link.get_send_interval() / 1000.0)) / DEGREE_TO_METER;
                if(move_deg > dist) move_deg = dist;
                current_lat += (dLat / dist) * move_deg;
                current_lon += (dLon / dist) * move_deg;
            }

            packet.latitude = static_cast<int32_t>(current_lat * GPS_SCALE);
            packet.longitude = static_cast<int32_t>(current_lon * GPS_SCALE);
            packet.altitude = 500.0f;
            packet.battery -= 25.0f;
            if(packet.battery < 0.0f) packet.battery = 0.0f;
            packet.seq_num = current_seq++;
            packet.timestamp = current_time;
            packet.priority = (packet.battery <= 20.0f) ? 1 : 0;

            link.send_telemetry(packet);
            last_send_time = current_time;
        }
        usleep(1000);
    }
    return 0;
}