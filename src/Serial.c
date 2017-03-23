/*
 ============================================================================
 Name        : Mifare
 Author      : IHM
 Version     : 0.1
 Copyright   :
 Description :
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>   /* Serial Port IO Controls */

#include "myserial.h"
#include "slmodule.h"

struct response {
	int error;
	unsigned char status;
	unsigned char request;
	int	len;
	unsigned char buffer[4096];
};

struct response readResponse(cport_nr){

	int n=0,t=9999;

	int mode = 0;

	struct response resp;

	unsigned char cbuf[8];
	int count = 0;
	int idx = 0;
	unsigned char csum = 0;

	while (mode != 99) {
		while (RS232_PollComport(cport_nr, cbuf, 1) == 0)
		   usleep (100);

		// we have a character

		switch (mode){
			case 0:
				if (cbuf[0] == 0xBD ){
					csum = 0xBD;
					mode = 1;
					}
				break;
			case 1:
				count = cbuf[0];
				csum ^= cbuf[0];
				mode = 2;
				break;
			case 2:
				resp.request = cbuf[0];
				csum ^= cbuf[0];
				mode = 3;
				break;
			case 3:
				resp.status = cbuf[0];
				csum ^= cbuf[0];
				mode = 4;
				count -= 3;
				if ( count <= 0 )
					mode = 5;
				break;
			case 4:
				resp.buffer[idx++] = cbuf[0];
				csum ^= cbuf[0];
				if (count-- <= 1){
					mode = 5;
					resp.len = idx;   // We are storing the length of the data. The checksum is in there but not really required!
					}
				break;
			case 5:
				if (csum != cbuf[0]){
					resp.error = -1;
				}
				else
					resp.error = 0;
				mode = 99;
				break;
			}
		}

	return resp;
}


int main(void) {

	  int reader_type = 0;

	  int n,
	      cport_nr=16,         // Identifies the serial port
	      bdrate=115200;       //  baud

	  int p;

	  unsigned char buf[4096];
	  unsigned char rsp[4096];

	  struct response r;

	  char mode[]={'8','N','1',0};

	  if(RS232_OpenComport(cport_nr, bdrate, mode))
	  {
	    printf("Can not open com port\n");
	    return(0);
	  }

//	  Mifare_cputbuff(cport_nr, SL032CMD_SelectCard, sizeof(SL032CMD_SelectCard)) ;

//	  while (1)
	  {
		  Mifare_cputbuff(cport_nr, SL032CMD_LightOn, sizeof(SL032CMD_LightOn)) ;
		  usleep(1000000);  /* sleep for 1000 milliSeconds */
		  Mifare_cputbuff(cport_nr, SL032CMD_LightOff, sizeof(SL032CMD_LightOff)) ;
		  usleep(1000000);  /* sleep for 1000 milliSeconds */
	  }

	  // flush the input buffer ( responses from LED commands )
	  do {
	    usleep(50);
	  } while (RS232_PollComport(cport_nr, buf, 4095));

	  Mifare_cputbuff(cport_nr, SL032CMD_GetFirmware, sizeof(SL032CMD_GetFirmware)) ;

	  usleep(5000);

	  //We can automatically decide if it's an 031 or an 032 from the response!

//	  while(SPort_Getsize(cport_nr) == 0){
//		 usleep(10000);
//	  }

//	  printf("Bytes available = %d",SPort_Getsize(cport_nr));

	  r = readResponse(cport_nr);

	  // if it gets a checksum error we crash out.
	  if (r.error != 0){
		  printf( "Transport error %02X reading Mifare device - probably csum!",r.error);
//	      printf("Received %i bytes: ", n);
	      return EXIT_FAILURE;
	  	  }

	   if(r.status == 0) {
		   printf("Command %02x succeeded\n",r.request);

		   if (r.len > 8){
			   for (p=0;p<5;p++){
				   if (r.buffer[p] != SL031_ID[p]){
					   break;
				   }
			   }
			   if (p < 5){
				   for (p=0;p<5;p++){
					   if (r.buffer[p] != SL032_ID[p]){
						   break;
					   }
				   }
				   if (p<5){
					   printf("Can't ID MifFare Reader \n");
					   return EXIT_FAILURE;
				   }
				   else {
				  		reader_type = 1;
				  		printf ("SL032 reader detected\n");
				   }
			   }
			   else {
				   reader_type = 0;
				   printf ("SL031 reader detected\n");
			   }
		   }
	   }

	  int toggle = 0;

	  while(1)
	  {
		  Mifare_cputbuff(cport_nr, SL032CMD_SelectCard, sizeof(SL032CMD_SelectCard)) ;

		  usleep(300000);

/*		  n = RS232_PollComport(cport_nr, buf, 100);
		  if ( n>0){
			  printf( "Read: ");
			  for (p=0;p<n;p++){
				 printf("%02X ",buf[p]) ;
			  }
			  printf("\n");
		  }

		  printf("Read done\n");  */


		  r = readResponse(cport_nr);

		  // if it gets a checksum error we crash out.
		  if (r.error != 0){
			  printf( "Transport error %02X reading Mifare device - probably csum!",r.error);
	//	      printf("Received %i bytes: ", n);
		      return EXIT_FAILURE;
		  	  }

		   if(r.status == 0) {
			   	// printf("Command %02x succeeded\n",r.request);

				printf("Card present \n");

				// Depending on the length of data we either have a 4 byte ID or a 7 Byte ID
				// Alternatively we can look at last data byte see the card type!
				// Get the byte at the pointer.
				switch (r.buffer[r.len-1]){
					case 1:
						printf ("Mifare 1k, 4 byte UID\n");
						break;
					case 2:
						printf ("Mifare Pro\n");
						break;
					case 3:
						printf ("Mifare UltraLight or NATG203[1], 7 byte UID\n");
						break;
					case 4:
						printf ("Mifare 4k, 4 byte UID\n");
						break;
					case 5:
						printf ("Mifare ProX\n");
						break;
					case 6:
						printf ("Mifare DesFire\n");
						break;
					case 7:
						printf ("Mifare 1k, 7 byte UID [2]\n");
						break;
					case 8:
						printf ("Mifare 4k, 7 byte UID [2]\n");
						break;
					default:
						printf ("Card type unknown\n");
						break;

					}

				printf("Card ID: ");
				if (r.len == 5){	// we have a 4 byte ID
					for (p=0;p<4;p++){
						printf("%02X ",r.buffer[p]);
					}

				}
				else if (r.len == 8){
					for (p=0;p<7;p++){
						printf("%02X ",r.buffer[p]);
					}
				}
				else {				// Some odd length we don't know how to handle!
					printf ("Unknown length of card ID!\n");
					return EXIT_FAILURE;
				}
				printf("\n");
		  }

/*
	    if ( toggle == 0){
			  toggle = 1;
			  Mifare_cputbuff(cport_nr, SL032CMD_LightOn, sizeof(SL032CMD_LightOn)) ;
		  }
		else {
			  toggle = 0;
			  Mifare_cputbuff(cport_nr, SL032CMD_LightOff, sizeof(SL032CMD_LightOn)) ;
		  }
		  // flush the input buffer ( responses from LED commands )
		  do {
		    usleep(50);
		  } while (RS232_PollComport(cport_nr, buf, 4095));

*/
	//    usleep(10000);  /* sleep for 100 milliSeconds */

	  }


	return EXIT_SUCCESS;
}
