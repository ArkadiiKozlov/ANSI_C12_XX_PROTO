/***************************************************************************
                          uart_udo24_umv64.cpp  -  description
                             -------------------
    begin                : Fri Dec 28 2001
    copyright            : (C) 2001 by 
    email                : 
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/
/* includes */
#include "./alpha1800.h"

#define		printf_log(args...)	{ printf (args); printf ("\n"); sprintf (prot_str, args); msg_obj->log (prot_str); }
// without carrier return
#define		printf_log2(args...)	{ printf (args); sprintf (prot_str, args); msg_obj->log (prot_str); }

///////////////////////////////////////////////////////////////////////////////
alpha1800::alpha1800 ()  
 {		
    protocol_state = START; //start state of protocol connection
    size_in = 0;
    data_trying = 0;
    alpha1800number = 0;    
 
 };
/////////////////////////////////////////////////////////////////////////////// 
void alpha1800::set_params (const char * _serial_dev, speed_t _speed, const char * _sport_param, int _alpha1800number)
{
    strcpy (serial_dev, _serial_dev);
    speed = _speed;
    strcpy (sport_param, _sport_param);
    alpha1800number = _alpha1800number;    
};
///////////////////////////////////////////////////////////////////////////////
STATUS alpha1800::open_serial ()
{
  if (us.open (serial_dev, speed, sport_param) <= 0) {
       printf ("can't open %s\n", serial_dev);
       return ERROR;
     } 
  return OK;
}
///////////////////////////////////////////////////////////////////////////////
STATUS alpha1800::logon_alpha ()
{
   log_out ();
   usleep (1000000);
   unsigned char identification[9] = { 0xEE, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x00, 0x00 };            
   unsigned char negotiation [12]  = { 0xEE, 0x00, 0x20, 0x00, 0x00, 0x04, 0x60, 0x04, 0x00, 0xff, 0x00, 0x00 };
   unsigned char logon [21]        = { 0xee, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x50, 0x00, 0x02, 0x41, 0x64, 0x6d,
                                       0x69, 0x6e, 0x69, 0x73, 0x74, 0x72, 0x61, 0x00, 0x00 };
   unsigned char auth [19]         = { 0xEE, 0x00, 0x20, 0x00, 0x00, 0x0b, 0x53, 0x09, 0x00, //key id
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // auth info
                                       0x00, 0x00 };
   //1. identification                 
   if (perform_tranzaction (identification, 9, 25) == ERROR) {
        printf_log  ("Identification error");
        return ERROR;
      }
   printf_log  ("Identification OK");      
   unsigned char ticket[8];
   memcpy (ticket, buff_in+14, 8);   
   printf_log ("ticket: %02x %02x %02x %02x %02x %02x %02x %02x", buff_in[14], buff_in[15], buff_in[16], buff_in[17], 
                                                                  buff_in[18], buff_in[19], buff_in[20], buff_in[21] );
   //2. negotiation
   if (perform_tranzaction (negotiation, 12, 13) == ERROR) {
        printf_log  ("negotiation error");
        return ERROR;
      }
   printf_log  ("negotiation OK");           
   //3. logon
   printf_log  ("logon:");   
   if (perform_tranzaction (logon, 21, 9) == ERROR) {
        printf_log  ("logon error");
        return ERROR;
      }
   //4. auth
   des_ctx dc;
   unsigned char *cp,key[8] = { 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30 };
   cp = ticket;
   des_key(&dc,(unsigned char *)key);
   des_enc(&dc,(unsigned char *)cp,1);
   memcpy (auth+9, ticket, 8);
   if (perform_tranzaction (auth, 19, 19) == ERROR) {
        printf_log  ("authentification error");
        return ERROR;      
      }
   printf_log  ("authentification OK");         
   //5. turning 27 table
   unsigned char w_table_27[48] = { 
                                 0xEE, 0x00, 0x00, 0x00, 0x00, 40,
                              //full write   table id   length of data
                                 0x40,       0x0,  27,  0x00, 34,    
                              // data
                              // demand1   demand2
                                 0x00,       0x01,
                              // values 32
                              //freq  voltA ......
                              // 0x32  0x36
                                 0x32, 0x36, 0x33, 0xab, 0x38, 0x35, 0xad, 0x41, 0x37, 0x34,
                                 0xac, 0x40, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0xaf,
                                 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9,
                                 0xaa, 0xb5,
                                 0x00,      //crc - sum of data and ~
                                 0x00, 0x00 // crc32                                                 
                             };
   unsigned char crc8 = 0x00;                             
   memcpy (w_table_27+13, quant_ids, 32);
   for (int i = 0; i < 34; i++)                             
         crc8 = w_table_27[i+11] + crc8;
   crc8 = ~crc8;         
   if (crc8&0x01)
       crc8 = crc8 + 1;
//   printf ("--crc8--: %02x\n", (unsigned char)crc8);
   w_table_27[45] = crc8;
   if (perform_tranzaction (w_table_27, 48, 9) == ERROR) {
        printf_log  ("write table 27  error");
        return ERROR;      
      }
   printf_log ("turning 27 table OK");   
   protocol_state = ESTABLISHED;
   return OK;
};
///////////////////////////////////////////////////////////////////////////////         
STATUS alpha1800::log_out ()
{
  unsigned char logout    [9] = { 0xEE, 0x00, 0x00, 0x00, 0x00, 0x01, 0x52, 0x00, 0x00 };
  unsigned char terminate [9] = { 0xEE, 0x00, 0x20, 0x00, 0x00, 0x01, 0x21, 0x00, 0x00 };
  // logout                 
  if (perform_tranzaction (logout, 9, 9) == ERROR) {
       printf_log  ("logout error");
       return ERROR;
     }     
  printf_log  ("logout OK");     
  // terminate
  if (perform_tranzaction (terminate, 9, 9) == ERROR) {
       printf_log  ("terminate error");
       return ERROR;
     }
  printf_log  ("terminate OK");     
  return OK;
}
///////////////////////////////////////////////////////////////////////////////         
STATUS alpha1800::get_data (vector <float> & _data_f)
{
  int connect_tryings = 0;
  while (protocol_state != ESTABLISHED) {   
          if (connect_tryings++ == 2)
              return ERROR;              
          logon_alpha ();
          usleep (1000000); // 1 sec.                     
        }

    unsigned char read_req [11] = { 0xEE, 0x00, 0x00, 0x00, 0x00, 0x03, 0x30, 0x00, 0x00, 0x00, 0x00 };
    
    //get table number 27 
    unsigned short table_id = 27; // quantities id-s table
    read_req[7] = table_id>>8;
    read_req[8] = table_id;
//    printf_log  ("retrieving table 27: ");   
    printf  ("retrieving table 27:\n");   
    if (perform_tranzaction (read_req, 11, 46) == ERROR) {
         if (++data_trying >= 3)
             protocol_state = START;
         printf_log  ("retrieving table 27 error, trying %d", data_trying);                    
         return ERROR;
       }

    //get table number 28 
    table_id = 28;    
    read_req[7] = table_id>>8;
    read_req[8] = table_id;    
//    printf_log  ("retrieving table 28: ");   
    printf ("retrieving table 28:\n");   
    if (perform_tranzaction (read_req, 11, 220) == ERROR) {
         if (++data_trying > 3)         
             protocol_state = START;
         printf_log  ("retrieving table 28 error, trying %d", data_trying);       
         return ERROR;
       }
    
    data_trying = 0;   
    
    unsigned int i1;
    for (int i = 0; i < 32; i++) {
          memcpy (&i1, buff_in+25 + i*6, 4);
          _data_f[i] = (float)i1/10000;
//    printf ("value1: %f\n", (float)i1/10000);
//    memcpy (&i1, buff_in+31, 4);
//    printf ("value2: %f\n", (float)i1/10000);
        }
         
  return OK;
}
///////////////////////////////////////////////////////////////////////////////         
STATUS alpha1800::perform_tranzaction2 (unsigned char *_buff_out, int _size, int _read_size)
{
  unsigned short crc16_local;
  unsigned char ACK[1] = { 0x06 };
  crc16_local = crc16 ((char *)_buff_out, _size-2);
  _buff_out[_size-2] = crc16_local>>8;
  _buff_out[_size-1] = crc16_local;

  us.set_read_timeout (4000000, 500000);            
  get_garbage ();
  int size_out = 0;
  size_in = 0;
  printf ("->");
  print_bytes (_buff_out, _size);
  usleep (250);
  if ((size_out = us.write ((char *)_buff_out, _size)) <= 0) {
        printf_log  ("can't send");
        return ERROR;  // driver error
     }
  //read ACK 
  if ((size_in = us.read ((char *)buff_in, 1)) <= 0) {
       printf_log  ("no ACK");
       return ERROR;
     }
  printf ("<-");
  print_bytes (buff_in, size_in);
  // read usefull data
  size_out = 0;
  size_in = 0;
  if ((size_in = us.read ((char *)buff_in, _read_size)) <= 0) {
       printf_log  ("no usefull data");
       return ERROR;
     }
  printf ("<-");
  print_bytes (buff_in, size_in);
  // send ACK     
  printf ("->");
  print_bytes (ACK, 1);
  usleep (250);   
  if ((size_out = us.write ((char *)ACK, 1)) <= 0) {
       printf_log  ("can't send ACK...");
       return ERROR;  // driver error
      }
      
  if (size_in == _read_size && check_crc (buff_in, size_in) == OK)
      return OK;     
  else {
          printf_log ("length or crc error");
          return ERROR;      
       }          
};
///////////////////////////////////////////////////////////////////////////////         
STATUS alpha1800::perform_tranzaction (unsigned char *_buff_out, int _size, int _read_size)
{
  unsigned short crc16_local;
  unsigned char ACK[1] = { 0x06 };
  crc16_local = crc16 ((char *)_buff_out, _size-2);
  _buff_out[_size-2] = crc16_local>>8;
  _buff_out[_size-1] = crc16_local;

  us.set_read_timeout (4000000, 500000);            
  get_garbage ();
  int retrying = 0;
  int size_out = 0;
  size_in = 0;
  while (retrying++ < 3) {  
          printf("->");
          print_bytes (_buff_out, _size);
          usleep (250);
          if ((size_out = us.write ((char *)_buff_out, _size)) <= 0) {
                printf_log  ("can't send, trying: %d", retrying);
                return ERROR;  // driver error
             }
          //read ACK 
          if ((size_in = us.read ((char *)buff_in, 1)) <= 0) {
                printf_log  ("no ACK, trying %d", retrying);
                continue;
             }
          printf("<-");
          print_bytes (buff_in, size_in);
          if (buff_in[0] == 0x06) {
               break;
             }
          if (buff_in[0] == 0x15) {
               continue;
             }             
        }
  if (retrying >= 3) {
       printf_log ("no ACK, trying: %d", retrying-1);
       return ERROR;
     }       
     
  // read usefull data
  retrying = 0;
  size_out = 0;
  size_in = 0;
  unsigned char NAK [1] = { 0x15 };
  while (retrying++ < 3) {    
          if ((size_in = us.read ((char *)buff_in, _read_size)) <= 0) {
                printf_log  ("no usefull data, trying %d", retrying);
                printf_log2 ("->");
                log_bytes (NAK, 1);
                usleep (250);
                if ((size_out = us.write ((char *)NAK, 1)) <= 0) {
                       printf_log  ("can't send NAK");
                       return ERROR;  // driver error
                   }
                continue;
             }
//   printf ("size_in: %d\n", size_in);     
          printf("<-");
          print_bytes (buff_in, size_in);
          // send ACK     
          printf ("->");
          print_bytes (ACK, 1);
          usleep (250);   
          if ((size_out = us.write ((char *)ACK, 1)) <= 0) {
                printf_log  ("can't send ACK...");
                return ERROR;  // driver error
             }
          if (size_in == _read_size && check_crc (buff_in, size_in) == OK)
               return OK;     
          else {
                     printf_log ("length (%d < %d) or crc error", size_in, _read_size);
                     continue;      
          }                                   
       }
  if (retrying >= 3) {
       printf_log ("no usefull data, trying: %d", retrying-1);
       return ERROR;
     }                                 
   return OK;     
};
///////////////////////////////////////////////////////////////////////////////	    
void alpha1800::get_garbage ()
{
  // get garbage
  us.set_read_timeout (0, 0);   
  size_in = 0;
  while ((size_in = us.read ((char *)buff_in, 1024)) > 0) {
          printf_log2 ("garbage: ");
          log_bytes (buff_in, size_in);
        }       
  us.set_read_timeout (4000000, 500000);        
}
///////////////////////////////////////////////////////////////////////////////	    
void alpha1800::log_bytes (unsigned char *buffer, int _size) 
{
  char str_log [1024];
  int j = 0;
  if (_size > 330) {
      printf_log ("truncated to 330 bytes...")
      _size = 330;
     }
  for (int i = 0; i < _size; i++ ) {
        sprintf (str_log+j, " %02x", buffer[i]);
	j = j + 3;
      }      
  str_log[j] = '\0';
  printf_log ("%s", str_log);  
};
///////////////////////////////////////////////
void alpha1800::print_bytes (unsigned char *buffer, int _size) 
{
  
  for (int i = 0, j = 0; i < _size; i++ ) {
        printf (" %02x", buffer[i]);
	j = j + 3;
      }      
  printf ("\n");  
  
};
///////////////////////////////////////////////
STATUS alpha1800::check_crc (unsigned char * _buff_in, int _size)
{
  unsigned short crc16_local = crc16 ((char *)_buff_in, (unsigned short)_size-2);
  if ((_buff_in[_size-2] == (unsigned char)(crc16_local>>8)) && (_buff_in[_size-1] == (unsigned char)crc16_local)) {
//       printf ("checksum is OK\n");
       return OK;
     }
  else {
         printf_log ("checksum error %04x has %02x %02x", crc16_local, _buff_in[_size-1], _buff_in[_size-2]);
         return ERROR;
  }
  return OK;
};       
///////////////////////////////////////////////
unsigned short alpha1800::crc16(char * _data_p, unsigned short _length)
{
  // crc x16 + x12 + x5 + 1
  unsigned char i;
  unsigned int data;
  unsigned int crc;
  crc = 0xffff;
  if (_length == 0)
      return (~crc);
      
  do {
      data = (unsigned int)0xff & *_data_p++;
      for (i = 0; i < 8; i++ ) {
           if ((crc & 0x0001) ^ (data & 0x0001))
                crc = (crc >> 1) ^ 0x8408;
           else
                 crc >>= 1;
           data >>= 1;
          }
  } while (--_length);
  crc = ~crc;
  data = crc;
  crc = (crc << 8) | (data >> 8 & 0xFF);
  return (crc);
};
///////////////////////////////////////////////////////////////////////////////	    
alpha1800::~alpha1800 ()
 {
 // nothing to delete while
 };
///////////////////////////////////////////////////////////////////////////////
