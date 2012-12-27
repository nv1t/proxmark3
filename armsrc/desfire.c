/*-----------------------------------------------------------------------------
// Hagen Fritsch - June 2010
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to support Mifare DESFire Cards
//-----------------------------------------------------------------------------
*/
#include <stdarg.h>

#include "proxmark3.h"
#include "apps.h"
#include "util.h"
#include "string.h"
#include "des.h"
#include "printf.h"

#include "iso14443a.h"
#include "iso14443crc.h"

#include "desfire.h"



struct desfire_data * desfire = (void *) (BigBuf + 1024); // BigBuf+4096 Bytes

void print_result(char * name, uint8_t * buf, size_t len) {
   uint8_t * p = buf;
   for(; p-buf < len; p += 8)
       Dbprintf("[%s:%02x/%02x] %x %x %x %x %x %x %x %x", name, p-buf, len, p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
}

/* execute a desfire command
 * by sending it in an APDU on the established iso14443a channel
 * put return result into *data
 * return number of bytes received */
int _desfire_command(uint8_t * cmd, size_t cmd_len, void * data) {
   uint8_t* resp = desfire->iso_resp_buf;  // was 3560 - tied to other size changes
   int len;

   /* construct APDU and append CRC */
   uint8_t real_cmd[cmd_len+4];
   real_cmd[0] = 0x0a;
   real_cmd[1] = 0x00;
   memcpy(real_cmd+2, cmd, cmd_len);
   AppendCrc14443a(real_cmd,cmd_len+2);

   ReaderTransmit(real_cmd, cmd_len+4);

   len = ReaderReceive(resp);
   if(!len)
       return -1; //DATA LINK ERROR

   char name[6];
   sprintf(name, "rx:%02x", cmd[0]);
   print_result(name, resp, len);
   
   // cid = resp[1];
   enum DESFIRE_STATUS status = resp[2];
   resp += 3; len -= 5; //2 bytes iso, 1 byte status, in the end: 2 bytes crc

   /* HACK: during authentication (0x0a) the status is set to AF instead of SUCCESS */
   if(cmd[0] == AUTHENTICATE_A && status == ADDITIONAL_FRAME) status = OPERATION_OK;

   switch(status) { // status code
   case OPERATION_OK:
       memcpy(data, resp, len);
       return len;
   case ADDITIONAL_FRAME: // Additional Frame
       memcpy(data, resp, len);
       uint8_t cmd_more_data[] = {0xaf};
       int res = _desfire_command(cmd_more_data, sizeof(cmd_more_data), (uint8_t *) data+len);
       if(res < 0) return res;
       return res + len;
   default:
       Dbprintf("unexpected desfire response: %X (to %X)", status, cmd[0]);
       return -status;
   }
}

int desfire_command(void * resp, enum DESFIRE_CMD cmd, size_t arg_count, ...) {
   va_list argptr;
   uint8_t command[arg_count+1];
   uint8_t *p = command;

   va_start(argptr, arg_count);
   while(p++ - command < arg_count)
       *p = va_arg(argptr, int);

   va_end( argptr );

   command[0] = cmd;
   int res = _desfire_command(command, arg_count+1, resp);
   if(res >= 0) return res;
   Dbprintf("desfire command %X failed: %X", cmd, -res);
   print_result("cmd", command, arg_count+1);
   return res;
}

void memxor(uint8_t * dst, uint8_t * src, size_t len) {
   for( ; len > 0; len--,dst++,src++)
       *dst ^= *src;
}

void desfire_encrypt_cbc(DES3_KS k, void * data, int len) {
   uint8_t *d  = data;
   uint8_t iv[8] = {0,0,0,0,0,0,0,0};
   if(((uint32_t) d & 0x3) != 0) Dbprintf("warn: DES not 32bit aligned");

   for(;len>0;len-=8,d+=8) {
       memxor(d, iv, 8);
       des3(k, (void *)d);
       memcpy(iv, d, 8);
   }
}

int desfire_encrypt_packet(uint8_t * p, size_t length, DES3_KS session_key) {
   int p_len = (length+7+2) & ~7;
   AppendCrc14443a(p, length);
   memset(p+length+2, 0, p_len - length);
   desfire_encrypt_cbc(session_key, p, p_len);
   return p_len;
}

void setup_3des_ks(uint32_t *key, DES3_KS knd) {
   uint32_t des_key[6] = {key[0], key[1], key[2], key[3], key[0], key[1]};
   des3key(knd,(void *)des_key,1);
}

int request_authentication(uint8_t key_slot, uint8_t * resp) {
   iso14a_set_trigger(1);
   if(desfire_command(resp, AUTHENTICATE_A, 1, key_slot) < 0) return 0;
   iso14a_set_trigger(0);
   return 1;
}

/* perform the desfire authentication procedure */
int desfire_auth(uint8_t key_slot, uint32_t * key, DES3_KS session_key) {

   DES3_KS knd;
   int res;
   uint8_t* resp = desfire->resp_buf;
   uint8_t nonce_command[17];

   uint32_t sess_key[4];

   setup_3des_ks(key, knd);

   if(desfire_command(resp, AUTHENTICATE_A, 1, key_slot) < 0) return 0;

   des3(knd, resp);            //decrypt the nonce

   sess_key[1] = *(uint32_t *)  resp;  //generate the session key
   sess_key[3] = *(uint32_t *) (resp+4);
   sess_key[0] = *(uint32_t *) (nonce_command+1);
   sess_key[2] = *(uint32_t *) (nonce_command+5);
   if(key[0] == key[2] && key[1] == key[3])
       sess_key[2] = sess_key[0],
       sess_key[3] = sess_key[1];
   Dbprintf("0x%x,0x%x,0x%x,0x%x", sess_key[0], sess_key[1], sess_key[2], sess_key[3]);
   setup_3des_ks(sess_key, session_key);

   memcpy(nonce_command+9, resp+1, 7); //shift the nonce
   nonce_command[16] = resp[0];

   desfire_encrypt_cbc(knd, nonce_command+1, 16);
   nonce_command[0] = AUTHENTICATION_FRAME;
   res = _desfire_command(nonce_command, 17, resp);
   if(res < 0) { Dbprintf("authentication failed: %X", -res); return 0; }
   desfire->authenticated_key = key_slot;

   return 1;
}

int desfire_key_settings(
   int allow_master_key_change,
   int restrict_file_list,
   int restrict_delete,
   int allow_config_change,
   int restrict_key_change_to_master_key,
   int key_change_key, /* 0x1 to 0xd, 0xe == same key required */
   int freeze_keys) {
   uint8_t res = 0;
   if(freeze_keys) res = 0xf0;
   if(key_change_key) res = key_change_key;
   if(restrict_key_change_to_master_key) res = 0;
   
   return res << 4 | !!allow_config_change << 3 | !restrict_delete << 2 | !restrict_file_list << 1 | !!allow_master_key_change;
}


int desfire_create_app(uint32_t aid, uint8_t key_settings, uint8_t num_keys) {
   return desfire_command(desfire->resp_buf, CREATE_APPLICATION, 5, aid, aid >> 8, aid >> 16, key_settings, num_keys);
}
int desfire_delete_app(uint32_t aid) {
   return desfire_command(desfire->resp_buf, DELETE_APPLICATION, 3, aid, aid >> 8, aid >> 16);
}
int desfire_select_app(uint32_t aid) {
   return desfire_command(desfire->resp_buf, SELECT_APPLICATION, 3, aid, aid >> 8, aid >> 16);
}

int desfire_create_file(int file_id, int security_level, int size) {
   return desfire_command(desfire->resp_buf, CREATE_STD_DATA_FILE, 7, file_id, security_level, 0xee, 0xee, size, size >> 8, size >> 16);
}

int desfire_change_file_settings(int file_id, int security_level, int read_key, int write_key, int rw_key) {
   return desfire_command(desfire->resp_buf, CHANGE_FILE_SETTINGS, 4, file_id, security_level, rw_key << 4 | 0xe, read_key << 4 | write_key);
}

int desfire_read_data(int file_id, int offset, int length, void * buf) {
   return desfire_command(buf, READ_DATA, 7, file_id, offset, offset >> 8, offset >> 16, length, length >> 8, length >> 16);
}

int desfire_write_data(int file_id, int offset, int length, void * buf, DES3_KS session_key) {
   uint8_t cmd[length+8+10];
   cmd[0] = WRITE_DATA;
   cmd[1] = file_id;
   cmd[2] = offset, cmd[3] = offset >> 8, cmd[4] = offset >> 16;
   cmd[5] = length, cmd[6] = length >> 8, cmd[7] = length >> 16;

   memcpy(cmd+8, buf, length);
   if(session_key)
       length = desfire_encrypt_packet(cmd+8, length, session_key);

   return _desfire_command(cmd, length+8, desfire->resp_buf);
}

int desfire_change_key(uint8_t key_slot, void * old_key, void * new_key, DES3_KS session_key) {
   uint8_t * cmd = desfire->resp_buf + 2; // +another 2 needs to be on a 32bit boundary
   uint8_t * data = cmd+2;
   uint32_t * old = old_key,
            * new = new_key;
   uint32_t * key = (uint32_t *) data;

   cmd[0] = CHANGE_KEY;
   cmd[1] = key_slot;

   int i, res;
   int len = 18;
   uint8_t key_settings[2];
           
   if((res = desfire_command(key_settings, GET_KEY_SETTINGS, 0)) < 0) return res;

   uint8_t change_key = key_settings[0] >> 4;
       
   if(desfire->authenticated_key != key_slot && change_key != 0xe) {
       for(i=0;i<4;i++)
           key[i] = old[i] ^ new[i];
       AppendCrc14443a(data, 16);
       ComputeCrc14443(CRC_14443_A, new_key, 16, data+16, data+17);
       len += 2;
   } else {
       memcpy(key, new_key, 16);
       AppendCrc14443a(data, 16);
   }

   memset(data+len, 0, 24-len); // zero-padding
   desfire_encrypt_cbc(session_key, data, 24);
   
   return _desfire_command(cmd, 26, desfire->resp_buf);
}



//void ReaderIsoDESFire(uint32_t parameter) {
/*enum desfire_param {
   CONNECT,
   NO_DISCONNECT,
   EXCHANGE_DATA,
};*/
void ReaderMifare(uint32_t param, uint32_t param2, uint8_t * cmd, UsbCommand * ack) {
   uint8_t* resp = desfire->resp_buf;
   uint32_t default_key[] = {0,0,0,0};
   int res;

   if(param & CONNECT)
   {
       iso14443a_setup();
       res = iso14443a_select_card(resp,NULL,&param);
       if(!res) {
           DbpString("iso14443a card select failed");
           goto err;
       }
       if(res == 2) {
           DbpString("not a mifare desfire card");
           goto err;
       }

   }
   if(param & EXECUTE_NATIVE_COMMAND)
   {
       // param2 is cmd_len
       if(param2 >> 8 & 0xff) { // stuff to encrypt?
           uint8_t offset = param2 >> 8;
           desfire_encrypt_packet(cmd + offset, (param2 & 0xff) - offset, desfire->session_key);
       }
       ack->arg[0] = _desfire_command(cmd, param2 & 0xff, ack->d.asBytes);
       /*if(param2 >> 16 & 0xff) { // stuff to decrypt?
           uint8_t offset = param2 >> 16;
           desfire_decrypt_packet(ack->d.asBytes + offset...
       }*/
       UsbSendPacket((void *)ack, sizeof(UsbCommand));
    }
   
   if(param & EXECUTE_SPECIAL_COMMAND)
   {
       ack->arg[0] = request_authentication(param2 & 0xf, ack->d.asBytes);
       UsbSendPacket((void *)ack, sizeof(UsbCommand));
   }   


   /*if(param & EXECUTE_SPECIAL_COMMAND)
   {   // special functionality to access in card
       // param2 is cmd
       switch(param2) {
       case AUTH:
           ack->arg[0] = desfire_auth(*cmd, cmd+4, desfire->session_key);
           break;
       case CH_KEY:
           ack->arg[0] = desfire_change_key(*cmd, cmd+4, cmd+20, desfire->session_key);
           break;
       default:
           Dbprintf("desfire command %x unimplemented", param2);
       }
       UsbSendPacket((void *)ack, sizeof(UsbCommand));
   }*/

   /*res = desfire_command(resp, GET_VERSION, 0);
   print_result("ver", resp, res);

   res = desfire_command(resp, GET_APPLICATION_IDS, 0);
   print_result("apps", resp, res);

        if(desfire_select_app(0) < 0) goto err;

   if(!desfire_auth(0, default_key, desfire->session_key)) goto err; */

   /*if(param & 4)
       if(desfire_delete_app(0xabcdef) < 0) goto err;

   if(param & 1) {
       if(desfire_create_app(0xabcdef, desfire_key_settings(1, 0, 0, 1, 1, 0, 0), 4) < 0) goto err;
   
           res = desfire_command(resp, GET_APPLICATION_IDS, 0);
       print_result("apps", resp, res);
   }*/
   // keynum, filesettings, crc_params, [new_key/ch_file, 
   if(param & 0x10) {
       if(desfire_select_app(0xabcdef) < 0) goto err;

       if(!desfire_auth(0, default_key, desfire->session_key)) goto err;

       res = desfire_command(resp, GET_FILE_IDS, 0);
       if(res < 0) goto err;
       print_result("files", resp, res);

       /*if(param & 8) {
           if(desfire_create_file(1, param >> 8 & 0xf, 32) < 0) goto err;
       } else 
       if(param & 8)
           if(desfire_change_file_settings(1, param >> 8 & 0xf, 0, 0, 0) < 0) goto err;*/

       if(param & 0x100) {
           if((res = desfire_read_data(1, 0, 8, resp)) < 0) goto err;
           print_result("file", resp, res);

           uint8_t data[] = {0,2,4,6,8,9};
           if((res = desfire_write_data(1, 0, 6, data, desfire->session_key)) < 0) goto err;

           if((res = desfire_read_data(1, 0, 8, resp)) < 0) goto err;
           print_result("file", resp, res);
       }

       if(desfire_command(resp, GET_KEY_VERSION, 1, 2) < 0) goto err;
       Dbprintf("key version: %x", resp[0]);
       uint8_t changekey = param >> 12 & 0xf;
   
       if(param & 2) {
           uint32_t old[] = {0,0,0,0};
           uint32_t new[] = {2,4,6,8};

           res = desfire_change_key(changekey, old, new, desfire->session_key);
           if(res < 0) Dbprintf("change key error: %x", -res);

           if(!desfire_auth(changekey, new, desfire->session_key)) {
               if(desfire_auth(changekey, old, desfire->session_key) < 0) goto err;
               DbpString("still using the old key");
           }
       }
   }
err:   
   if(param & NO_DISCONNECT) return;
   FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
}
