#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <dvbcsa/dvbcsa.h>
#include "functions.c"

/*------------------------------------------------*/
/*  Copyright by Vitali Tumasheuski @unidiag      */
/* https://tvcas.com    Email: admin@tvcas.com    */
/*------------------------------------------------*/

#define VERSION "1.01"
#define DEBUG false // show encrypt packets to console

#define SM_SERIAL 2100001234
#define SM_ECM_KEY "6F5F943163CD395E223DC4DEDDA2A96A7BE382C19848A957F787C74AD1BF2A42"
#define SM_EMM_KEY "2cc5a20f67ff3ccec108e207626fb31f"
#define SM_START 0x65922AB0 // unix=1704078000 (01 january 2024)
#define SM_FINISH 0x6D184A30 // unixtime=1830308400 (01 january 2028)
#define SM_ACCESS 0x00000001 // access criteria

#define UDP_RX_ADDR "239.1.100.1" // input encrypted stream
#define UDP_RX_PORT 1234
#define UDP_TX_ADDR "239.10.100.1" // output decrypted stream
#define UDP_TX_PORT 1234

#define TS_PACKET_SIZE 188
#define UDP_BUFFER_SIZE 188 * 7
#define SYNC_BYTE 0x47
#define PAT_PID 0x00
#define CAT_PID 0x01 
#define NIT_PID 0x10
#define SDT_PID 0x11
#define EIT_PID 0x12
#define DATAGRAM_LENGTH 48
#define START_ECM 12
#define START_EMM 19






int main (int argc, char *argv[]) {
// ███████╗████████╗ █████╗ ██████╗ ████████╗                                                                                                                                                                            
// ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗╚══██╔══╝                                                                                                                                                                            
// ███████╗   ██║   ███████║██████╔╝   ██║                                                                                                                                                                               
// ╚════██║   ██║   ██╔══██║██╔══██╗   ██║                                                                                                                                                                               
// ███████║   ██║   ██║  ██║██║  ██║   ██║                                                                                                                                                                               
// ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝                                                                                                                                                                               

    
    echo("[INFO] TVCAS4CAM v.%s. Copyright 2024 TVCAS.COM\n", VERSION);
    echo("[INPUT] udp://@%s:%d\n", UDP_RX_ADDR, UDP_RX_PORT);
    echo("[OUTPUT] udp://@%s:%d\n", UDP_TX_ADDR, UDP_TX_PORT);

    struct Config config;

    // start subscription for smartcard
    struct Subscription subs = {
      .serial_no = SM_SERIAL,
      .start = SM_START,
      .finish = SM_FINISH,
      .access_criteria = SM_ACCESS,
    };
    struct dvbcsa_key * csa_key;
    struct sockaddr_in rx_addr, tx_addr;

    int reuse = 1;
    int start = 0;
    int last_parity = -1;
    int rx_len, sock_rx, sock_tx, parity;
    unsigned int addrlen;
    unsigned char buf_rx[UDP_BUFFER_SIZE], buf_tx[UDP_BUFFER_SIZE];
    unsigned char key[24];
    unsigned char decrypt_ecm[DATAGRAM_LENGTH], decrypt_emm[DATAGRAM_LENGTH];
    
    echo("[SERIAL] %lu (%02X %02X %02X %02X)\n", subs.serial_no, (subs.serial_no >> 24)&0xFF, (subs.serial_no >> 16)&0xFF, (subs.serial_no >> 8)&0xFF, subs.serial_no&0xFF);
    csa_key = dvbcsa_key_alloc(); // init libdvbcsa











// ██████╗ ██╗  ██╗    ██╗   ██╗██████╗ ██████╗     ███████╗ ██████╗  ██████╗██╗  ██╗███████╗████████╗
// ██╔══██╗╚██╗██╔╝    ██║   ██║██╔══██╗██╔══██╗    ██╔════╝██╔═══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝
// ██████╔╝ ╚███╔╝     ██║   ██║██║  ██║██████╔╝    ███████╗██║   ██║██║     █████╔╝ █████╗     ██║   
// ██╔══██╗ ██╔██╗     ██║   ██║██║  ██║██╔═══╝     ╚════██║██║   ██║██║     ██╔═██╗ ██╔══╝     ██║   
// ██║  ██║██╔╝ ██╗    ╚██████╔╝██████╔╝██║         ███████║╚██████╔╝╚██████╗██║  ██╗███████╗   ██║   
// ╚═╝  ╚═╝╚═╝  ╚═╝     ╚═════╝ ╚═════╝ ╚═╝         ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   
                                                                                                      
    memset((char *) &rx_addr, 0, sizeof(rx_addr));
    rx_addr.sin_family = AF_INET;
    rx_addr.sin_port = htons(UDP_RX_PORT);
    rx_addr.sin_addr.s_addr = inet_addr(UDP_RX_ADDR);
    addrlen = sizeof(rx_addr);
    if ((sock_rx = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
			perror("rx_socket(): error ");
			exit(EXIT_FAILURE);
    }
    if (setsockopt(sock_rx, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0) {
			perror("setsockopt() SO_REUSEADDR: error ");
    }
    if (bind(sock_rx, (struct sockaddr*)&rx_addr, sizeof(rx_addr)) < 0) {
			perror("bind(): error");
			exit(EXIT_FAILURE);
    }
















// ████████╗██╗  ██╗    ██╗   ██╗██████╗ ██████╗     ███████╗ ██████╗  ██████╗██╗  ██╗███████╗████████╗
// ╚══██╔══╝╚██╗██╔╝    ██║   ██║██╔══██╗██╔══██╗    ██╔════╝██╔═══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝
//    ██║    ╚███╔╝     ██║   ██║██║  ██║██████╔╝    ███████╗██║   ██║██║     █████╔╝ █████╗     ██║   
//    ██║    ██╔██╗     ██║   ██║██║  ██║██╔═══╝     ╚════██║██║   ██║██║     ██╔═██╗ ██╔══╝     ██║   
//    ██║   ██╔╝ ██╗    ╚██████╔╝██████╔╝██║         ███████║╚██████╔╝╚██████╗██║  ██╗███████╗   ██║   
//    ╚═╝   ╚═╝  ╚═╝     ╚═════╝ ╚═════╝ ╚═╝         ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   
                                                                                                    


        // Создаем сокет для отправки данных (UDP)
    if ((sock_tx = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
			perror("tx_socket(): error ");
			return 0;
    }
    memset(&tx_addr, 0, sizeof(tx_addr));
    tx_addr.sin_family = AF_INET;
    tx_addr.sin_addr.s_addr = inet_addr(UDP_TX_ADDR);
    tx_addr.sin_port = htons(UDP_TX_PORT);









// ██████╗ ██████╗ ███████╗██████╗  █████╗ ██████╗ ███████╗    ███████╗ ██████╗███╗   ███╗    ██╗  ██╗███████╗██╗   ██╗
// ██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝    ██╔════╝██╔════╝████╗ ████║    ██║ ██╔╝██╔════╝╚██╗ ██╔╝
// ██████╔╝██████╔╝█████╗  ██████╔╝███████║██████╔╝█████╗      █████╗  ██║     ██╔████╔██║    █████╔╝ █████╗   ╚████╔╝ 
// ██╔═══╝ ██╔══██╗██╔══╝  ██╔═══╝ ██╔══██║██╔══██╗██╔══╝      ██╔══╝  ██║     ██║╚██╔╝██║    ██╔═██╗ ██╔══╝    ╚██╔╝  
// ██║     ██║  ██║███████╗██║     ██║  ██║██║  ██║███████╗    ███████╗╚██████╗██║ ╚═╝ ██║    ██║  ██╗███████╗   ██║   
// ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝    ╚══════╝ ╚═════╝╚═╝     ╚═╝    ╚═╝  ╚═╝╚══════╝   ╚═╝   
                                                                                                                    

    unsigned char *ecm_key = malloc(32);
    hex_string_to_bytes(SM_ECM_KEY, ecm_key);
    // was: 6F5F943163CD395E223DC4DEDDA2A96A7BE382C19848A957F787C74AD1BF2A42
    SessionKeyDecrypt(&ecm_key[0]);
    SessionKeyDecrypt(&ecm_key[8]);
    SessionKeyDecrypt(&ecm_key[16]);
    SessionKeyDecrypt(&ecm_key[24]);
    // became: A903001610EA18020E7F554CC2180B00079D010B0033CE98D91714300B140D03


 






// ██████╗ ██████╗ ███████╗██████╗  █████╗ ██████╗ ███████╗    ███████╗███╗   ███╗███╗   ███╗    ██╗  ██╗███████╗██╗   ██╗
// ██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝    ██╔════╝████╗ ████║████╗ ████║    ██║ ██╔╝██╔════╝╚██╗ ██╔╝
// ██████╔╝██████╔╝█████╗  ██████╔╝███████║██████╔╝█████╗      █████╗  ██╔████╔██║██╔████╔██║    █████╔╝ █████╗   ╚████╔╝ 
// ██╔═══╝ ██╔══██╗██╔══╝  ██╔═══╝ ██╔══██║██╔══██╗██╔══╝      ██╔══╝  ██║╚██╔╝██║██║╚██╔╝██║    ██╔═██╗ ██╔══╝    ╚██╔╝  
// ██║     ██║  ██║███████╗██║     ██║  ██║██║  ██║███████╗    ███████╗██║ ╚═╝ ██║██║ ╚═╝ ██║    ██║  ██╗███████╗   ██║   
// ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝    ╚══════╝╚═╝     ╚═╝╚═╝     ╚═╝    ╚═╝  ╚═╝╚══════╝   ╚═╝   
                                                                                                                       
    unsigned char *emm_key = malloc(16);
    hex_string_to_bytes(SM_EMM_KEY, emm_key);
    // was: 2cc5a20f67ff3ccec108e207626fb31f
    SessionKeyDecrypt(&emm_key[0]);
    SessionKeyDecrypt(&emm_key[8]);
    // became: DAD1390609403F6C4342D0F1C111A0DD








    while(true) {

			rx_len = recvfrom(sock_rx, buf_rx, sizeof(buf_rx), 0, (struct sockaddr *) &rx_addr, &addrlen);

      for (int i = 0; i < rx_len; i += TS_PACKET_SIZE) {
        uint8_t *packet = &buf_rx[i];
        if (packet[0] != SYNC_BYTE) {
          printf("Sync byte not found\n");
          continue;
        }






        uint16_t pid = get_pid(packet);
        switch(pid){








// ██████╗  █████╗ ████████╗
// ██╔══██╗██╔══██╗╚══██╔══╝
// ██████╔╝███████║   ██║   
// ██╔═══╝ ██╔══██║   ██║   
// ██║     ██║  ██║   ██║   
// ╚═╝     ╚═╝  ╚═╝   ╚═╝   
                         

          case PAT_PID: // 0x00
            config.pmt_pid = b2int(&packet[15], true);
            config.pnr = b2int(&packet[13], false);
            config.tsid = b2int(&packet[8], false);
            break;







//  ██████╗ █████╗ ████████╗
// ██╔════╝██╔══██╗╚══██╔══╝
// ██║     ███████║   ██║   
// ██║     ██╔══██║   ██║   
// ╚██████╗██║  ██║   ██║   
//  ╚═════╝╚═╝  ╚═╝   ╚═╝   
                         
          case CAT_PID: // 0x01
            config.cas = b2int(&packet[15], false);
            config.emm_pid = b2int(&packet[17], true);
            break;






          case NIT_PID:
          case EIT_PID:
            break;




// ███████╗██████╗ ████████╗
// ██╔════╝██╔══██╗╚══██╔══╝
// ███████╗██║  ██║   ██║   
// ╚════██║██║  ██║   ██║   
// ███████║██████╔╝   ██║   
// ╚══════╝╚═════╝    ╚═╝   
                         
          case SDT_PID:
            if(start==0){
              echo("[SDT] ");
              for(int j=12; j<TS_PACKET_SIZE; j++){
                uint8_t c = packet[j];
                if(c != 255){
                  if(c < 30) c = '.';
                  printf("%c", c);
                }
              }
              printf("\n");
              start=1;
            }
            break;

          default:








// ██████╗ ███╗   ███╗████████╗
// ██╔══██╗████╗ ████║╚══██╔══╝
// ██████╔╝██╔████╔██║   ██║   
// ██╔═══╝ ██║╚██╔╝██║   ██║   
// ██║     ██║ ╚═╝ ██║   ██║   
// ╚═╝     ╚═╝     ╚═╝   ╚═╝   
                            
            if(pid == config.pmt_pid){

              if (config.cas == b2int(&packet[19], false)){ // 0B00
                config.ecm_pid = b2int(&packet[21], true); // 94
                config.pcr_pid = b2int(&packet[13], true); // 1601
                if(start==1){
                  dump(&config);
                  start = 2;
                }
              }








        // ██████╗ ██╗  ██╗    ███████╗ ██████╗███╗   ███╗    ██████╗ ██╗██████╗ 
        // ██╔══██╗╚██╗██╔╝    ██╔════╝██╔════╝████╗ ████║    ██╔══██╗██║██╔══██╗
        // ██████╔╝ ╚███╔╝     █████╗  ██║     ██╔████╔██║    ██████╔╝██║██║  ██║
        // ██╔══██╗ ██╔██╗     ██╔══╝  ██║     ██║╚██╔╝██║    ██╔═══╝ ██║██║  ██║
        // ██║  ██║██╔╝ ██╗    ███████╗╚██████╗██║ ╚═╝ ██║    ██║     ██║██████╔╝
        // ╚═╝  ╚═╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝╚═╝     ╚═╝    ╚═╝     ╚═╝╚═════╝ 
                                                                                                                                        

            }else if (pid == config.ecm_pid){

              unsigned char step = 0;

              if (parity != packet[5]){
                echo("\033[32m[ECM 0x%02X]\033[0m ", packet[5]);

                if (!DEBUG){
                  for(int i = START_ECM; i < START_ECM + DATAGRAM_LENGTH; i++){
                    printf("%02X", packet[i]);
                  }
                }
                





                // ███████╗ ██████╗███╗   ███╗     ██████╗ ██████╗ ███████╗███╗   ██╗
                // ██╔════╝██╔════╝████╗ ████║    ██╔═══██╗██╔══██╗██╔════╝████╗  ██║
                // █████╗  ██║     ██╔████╔██║    ██║   ██║██████╔╝█████╗  ██╔██╗ ██║
                // ██╔══╝  ██║     ██║╚██╔╝██║    ██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║
                // ███████╗╚██████╗██║ ╚═╝ ██║    ╚██████╔╝██║     ███████╗██║ ╚████║
                // ╚══════╝ ╚═════╝╚═╝     ╚═╝     ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝
                                                                                                                                                                 

                if (packet[5] == 0x81) step = 16;
                memcpy(key, &ecm_key[step], 16);
                memcpy(key + 16, &ecm_key[step], 8);

                dec2gost(&packet[START_ECM], DATAGRAM_LENGTH, key, decrypt_ecm);

                if (DEBUG){
                    for(int ii=0; ii<DATAGRAM_LENGTH; ii++){
                        printf("%02X", decrypt_ecm[ii]);
                    }
                }

                // ecm-gift..
                if(subs.serial_no == b2long(&decrypt_ecm[24])){
                    subs.start = b2long(&decrypt_ecm[32]);
                    subs.finish = b2long(&decrypt_ecm[36]);
                    subs.access_criteria = b2long(&decrypt_ecm[28]);
                    printf(" !"); // marker for ECM-gift
                }
                
                if(decrypt_ecm[DATAGRAM_LENGTH-1] != csum(decrypt_ecm)){
                  printf(" ?"); // marker for control summ not correct
                }
                printf("\n");
                parity = packet[5];
              }







        // ██████╗ ██╗  ██╗    ███████╗███╗   ███╗███╗   ███╗    ██████╗ ██╗██████╗ 
        // ██╔══██╗╚██╗██╔╝    ██╔════╝████╗ ████║████╗ ████║    ██╔══██╗██║██╔══██╗
        // ██████╔╝ ╚███╔╝     █████╗  ██╔████╔██║██╔████╔██║    ██████╔╝██║██║  ██║
        // ██╔══██╗ ██╔██╗     ██╔══╝  ██║╚██╔╝██║██║╚██╔╝██║    ██╔═══╝ ██║██║  ██║
        // ██║  ██║██╔╝ ██╗    ███████╗██║ ╚═╝ ██║██║ ╚═╝ ██║    ██║     ██║██████╔╝
        // ╚═╝  ╚═╝╚═╝  ╚═╝    ╚══════╝╚═╝     ╚═╝╚═╝     ╚═╝    ╚═╝     ╚═╝╚═════╝ 
                                                                                 
            }else if (pid == config.emm_pid){

              if (subs.serial_no == b2long(&packet[11])){
                
                echo("\033[33m[EMM 0x82]\033[0m ");




                // ███████╗███╗   ███╗███╗   ███╗     ██████╗ ██████╗ ███████╗███╗   ██╗
                // ██╔════╝████╗ ████║████╗ ████║    ██╔═══██╗██╔══██╗██╔════╝████╗  ██║
                // █████╗  ██╔████╔██║██╔████╔██║    ██║   ██║██████╔╝█████╗  ██╔██╗ ██║
                // ██╔══╝  ██║╚██╔╝██║██║╚██╔╝██║    ██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║
                // ███████╗██║ ╚═╝ ██║██║ ╚═╝ ██║    ╚██████╔╝██║     ███████╗██║ ╚████║
                // ╚══════╝╚═╝     ╚═╝╚═╝     ╚═╝     ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝

                
                memcpy(key, emm_key, 16);
                memcpy(key + 16, emm_key, 8); 
                dec2gost(&packet[START_EMM], DATAGRAM_LENGTH, key, decrypt_emm);
                
                // serial number from EMM
                uint32_t emm_sn = b2long(decrypt_emm);

                if(emm_sn < 2100000000 || emm_sn > 2110000000){ 
                  // for receive SMS
                  for(int ii=0; ii<DATAGRAM_LENGTH-1; ii++){
                      printf("%c", decrypt_emm[ii]);
                  }
                }else if(DEBUG){
                  for(int ii=0; ii<DATAGRAM_LENGTH; ii++){
                      printf("%02X", decrypt_emm[ii]);
                  }
                }else{
                  for(int i = START_EMM; i < START_EMM + DATAGRAM_LENGTH; i++){
                    printf("%02X", packet[i]);
                  }
                }
                
                if(decrypt_emm[DATAGRAM_LENGTH-1] == csum(decrypt_emm)){
                  // if not SMS - update subscribes..
                  if(emm_sn >= 2100000000 && emm_sn < 2110000000){
                    subs.start = b2long(&decrypt_emm[8]);
                    subs.finish = b2long(&decrypt_emm[12]);
                    subs.access_criteria = b2long(&decrypt_emm[4]);
                  }
                }else{
                  printf(" ?"); // marker for control summ not correct
                }
                printf("\n");
              }












        // ██████╗ ███████╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗
        // ██╔══██╗██╔════╝██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝
        // ██║  ██║█████╗  ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   
        // ██║  ██║██╔══╝  ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   
        // ██████╔╝███████╗╚██████╗██║  ██║   ██║   ██║        ██║   
        // ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   
                                                                  

          }else if (get_bit(packet[3], 7) && parity > 0){

            uint32_t ecm_time = b2long(decrypt_ecm);
            uint32_t ecm_ac = b2long(&decrypt_ecm[20]);

            // decrypt if time and access_criteria is success
            if(ecm_time > subs.start && ecm_time < subs.finish && (ecm_ac & subs.access_criteria)){

              uint8_t s = get_bit(packet[3], 5) ? packet[4]+5 : 4;
              dvbcsa_key_set(&decrypt_ecm[get_bit(packet[3], 6) ? 4 : 12], csa_key);
              dvbcsa_decrypt(csa_key, packet+s, TS_PACKET_SIZE-s);
              set_bit(&packet[3], 6, false);
              set_bit(&packet[3], 7, false);

            }

          }



        }

        
        
        // copy the packet to a new buffer for transmission...
        memcpy(buf_tx+i, packet, TS_PACKET_SIZE);

      }














        // ███████╗███████╗███╗   ██╗██████╗     ██╗   ██╗██████╗ ██████╗ 
        // ██╔════╝██╔════╝████╗  ██║██╔══██╗    ██║   ██║██╔══██╗██╔══██╗
        // ███████╗█████╗  ██╔██╗ ██║██║  ██║    ██║   ██║██║  ██║██████╔╝
        // ╚════██║██╔══╝  ██║╚██╗██║██║  ██║    ██║   ██║██║  ██║██╔═══╝ 
        // ███████║███████╗██║ ╚████║██████╔╝    ╚██████╔╝██████╔╝██║     
        // ╚══════╝╚══════╝╚═╝  ╚═══╝╚═════╝      ╚═════╝ ╚═════╝ ╚═╝     
                                                                       
      if (sendto(sock_tx, buf_tx, sizeof(buf_tx), 0, (struct sockaddr *)&tx_addr, sizeof(tx_addr)) < 0) {
        perror("Failed to send data");
        exit(EXIT_FAILURE);
      }
    }
}
