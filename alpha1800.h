/***************************************************************************
                          uart_udo24_umv64.h  -  description
                             -------------------
    begin                : Fri Dec 28 2001
    copyright            : (C) 2001 by Arkadi A. Kozlov
    email                :arkashamain@mail.ru
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/
/* this is uart.h file */
#ifndef  _alpha1800
#define  _alpha1800


/*
--------------------------
Author:    Arkady K.
--------------------------
e-mail:    arkashamain@mail.ru
--------------------------
copyright: arkady&CRTC
--------------------------
*/
/* includes */
#include "messages.h"
#include "station.h"
#include "common.h"
#include "msg.h"

#include "./des.h"
//#include "./quant_ids.h"
#include "../../uart_simple.h"



enum PROT_STATE { START = 0, ESTABLISHED };


class alpha1800 {
 private:  
	    MsgN * msg_obj;
            uart_simple  us;
            char serial_dev [100];
            speed_t      speed;                      	     
            char sport_param [30];	                   	                    
	    int  error_485_counter;		        
            unsigned char  buff_in[4096];
            unsigned char  buff_out[4096];                                                           
            char prot_str[1024];           
            unsigned char protocol_state;
            int size_in; 
            int data_trying;
            int alpha1800number;
//            unsigned char quant_ids [32];                        
            static unsigned char quant_ids [32];            
 protected:
             unsigned short crc16(char * _data_p, unsigned short _length);
 public:
         alpha1800 ();
         void set_params (const char * _serial_dev, speed_t _speed, const char * _sport_param, int _alpha1800number);
         STATUS open_serial ();
         void fill_sturctures ();
         void log_bytes (unsigned char *buffer, int _size);
         void print_bytes (unsigned char *buffer, int _size);
         virtual void Set_Msg_Obj (MsgN *_obj) { msg_obj = _obj; };                
         STATUS logon_alpha ();
         STATUS perform_tranzaction (unsigned char *_buf_out, int _size, int _read_size);
         STATUS perform_tranzaction2 (unsigned char *_buf_out, int _size, int _read_size);         
         STATUS log_out ();
         STATUS get_data (vector <float> & _data_f);
         void get_garbage ();
         STATUS check_crc (unsigned char * _buff_in, int _size);
         virtual ~alpha1800 ();
	
 };

#endif /* !_alpha1800_ */
