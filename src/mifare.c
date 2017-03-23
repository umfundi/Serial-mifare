/*
 * mifare.c


 *
 *  Created on: 22 Mar 2017
 *      Author: ian
 */

//#include "CLAVIER.h"

#include <stdint.h>
#include "mifare.h"
#include "materiel.h"
#include "screen.h"
#include "EEPROMADRESSES.h"

uint8_t MifResTypeDeCarte();
//**************************************************
// Constantes
//**************************************************
#define int8_t    short
#define uint8_t   unsigned short
#define uint16_t  unsigned int
#define uint32_t  unsigned long
#define byte      uint8_t
//-----------------------------------------------------------------------------
static uint8_t mifI2CErr ;
static unsigned char g_cRxBuf[22];
static uint8_t g_cTxBuf[22];
static uint8_t g_cCardType;
//-----------------------------------------------------------------------------
#define SNDLEN        g_cTxBuf[0]
#define SNDCOMMAND    g_cTxBuf[1]
#define SNDDATASTART  g_cTxBuf[2]
//-----------------------------------------------------------------------------
#define RCVCMD_SL030 g_cRxBuf[1]
#define RCVSTA_SL030 g_cRxBuf[2]
#define RCVDAT_SL030 g_cRxBuf[3]

//-----------------------------------------------------------------------------
// ----> 16 blocs de 3 * 16 octets pour la carte complete
// ==> Bloc 0
// 0            -> UID de la care
// 1 et 2       -> les index de stands ( 8 possibles )
// ==> Bloc 1 et 2
// 4 - 5 - 6    -> Texte 3 * 16 caractéres          COMMUN A TOUS LES STANDS
// 8 - 9 - 10   -> Texte suite soit 84 caractéres
// ==> Bloc 3
// 12 - 13 - 14 -> Les trois compteurs du stand N° 1
// ==> Bloc 4
// 16 - 17 - 18 -> Les trois compteurs du stand N° 2   (st * 4)+(12-4) = 16
// ==> Bloc 5
//    etc...
// ==> Bloc 11
// 40 - 41 - 42 -> Les trois compteurs du stand N° 8  (8 * 4)+(12-4) = 40
//----
// ==> Bloc 12 a 15 libres soit 4 * 3 * 16 = 192 octets

//-----------------------------------------------------
//--- La clé de base peut être 0xAA ou 0xBB ou 0xFF ---
#define TYPECLEBASE    0xAA
uint8_t CleTravailType ;
//-----------------------------------------------------
//-----------------------------------------------------
// Compiler directive, set struct alignment to 1 uint8_t for compatibility
#  pragma pack(1)

// Promatic
typedef struct {                // 16 octets de la ligne 0x04
   uint8_t ecuid[0x06] ;         // 6  octets = Only 4 on left used
   uint8_t Libre_Free ;          // Free to use
   uint8_t codesand[0x04]  ;     // 4  octets = Shooting ground number
   uint8_t CC2 ;                 // 1  Options to run
   uint16_t UpliftHiLo ;         // 2  Code complementaire
   uint8_t GCN ;                 // 1  = sales / ground card number in ascii
   uint8_t EA ;                  // 1  = Extended access A
} pr_04;

typedef struct {         // 16 octets de la ligne 0x05
   uint8_t cid ;          // 1  octets = Starts from $00, Controller ID is sucked, inc'd & written back
   uint8_t ccid  ;        // 1
   uint8_t cc2in ;        // 1
   uint8_t flags ;        // 1  => 0 = CardFreeplayEnable as written to Master Card
   uint8_t SerLoMi[0x03]; // 3  => Num Serie
   uint8_t CMD ;          // 1  Type of card M = master / 0=normal / 1 to 8=Ground card
   uint8_t CT ;           // 1  =>>>> card type (cost code card) only R/W by programmer (Choix du tarif)
   uint8_t free[0x03] ;   // 3
   uint8_t EB ;           // 1  ==> Extended access B
   uint8_t CustCnt[0x03]; // 3  ==> Incremente tous les plateauc ici (totalisateur)
} pr_05;

typedef struct {            // 16 octets de la ligne 0x06
   uint16_t   count ;        // 2  Count goes DOWN or UP depending on CC2,3
   uint16_t   limit  ;       // 2  Up limit or DOWN Max limit. (not specific)
   uint8_t    coast[0x08] ;  // 8  Either 0 for Target based or a value in pennies cost based
   uint16_t   CashCnt;       // 2
   uint16_t   RipCashLim ;   // 2
} pr_06;

typedef struct {
   uint8_t free[10];             //
   uint8_t CC[3];                //Compteur global ??
   uint8_t Lock[3];              //Compteur ??
} pr_57;

typedef struct {
   uint8_t UUIDbase[4];          // UUID Real
   uint8_t UUIDcrypted[6];       // UUID for validity test of card
   uint8_t keyA[6];              // Key for Xtreme card
} pr_init;

typedef struct {
  pr_04   L4;
  pr_05   L5;
  pr_06   L6;
//pr_57   L57;
  pr_init init;
} str_Promatic_Infos ;

// Promatic_Infos.init.UUIDbase

// Reset struct alignment to default
#pragma pack()
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
#define  TestSpare        Promatic_Infos.L4.CC2 & 0x01
#define  TestManager      Promatic_Infos.L4.CC2 & 0x02
#define  TestMoneyUse     Promatic_Infos.L4.CC2 & 0x04
#define  TestCountUP      Promatic_Infos.L4.CC2 & 0x08
#define  TestSerialBase   Promatic_Infos.L4.CC2 & 0x10
#define  TestStafCard     Promatic_Infos.L4.CC2 & 0x20
#define  TestSubMaster    Promatic_Infos.L4.CC2 & 0x40
#define  TestMasterGround Promatic_Infos.L4.CC2 & 0x80
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------
//-----------------------------------------------------
typedef struct ca_unstand {    // 4 octets * 8 = 32
   uint16_t   numero ;         //Structure * 8 contenue dans la carte
   uint8_t    codesand ;       //dans le champ 1 et 2 soit 32 octets.
   uint8_t    type ;
} ca_unstand ;

typedef struct st_mifcarte {
   uint32_t    num;            //Le Numéro de la carte dans le bloc 0
   uint32_t    compteur[3];    //Suivant son N° d'enregistrement
   ca_unstand  stands[8];      //Le bloc 1 et 2 complets (Les 8 stands) = 32
   uint8_t     texte[0x60];    //Les blocs  4 , 5 , 6  , 8 , 9 , 10
} st_mifcarte;

//Infos du stand en mode global
static str_InfoStand  InfoStand ;
static st_mifcarte    mifcarte  ;

//Infos de la carte promatic
static str_Promatic_Infos Promatic_Infos;

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
void MifInfosStandCharge( str_InfoStand * sta )
{
   memcpy( &InfoStand , sta , sizeof(str_InfoStand) );
}
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//---- Attention, adresse identique a une mémoire ------
#define SLVADD      0xA0
#define DDRmifSCL   TRISD.F10
#define mifSCL      PORTD.F10
#define DDRmifSDA   TRISD.F9
#define mifSDA      PORTD.F9
//-----------------------------------------------------------------------------
void mifPause() { Delay_Cyc( 0 , 90 ); }  // 50 = 400Khz a 20 Mhz
//-----------------------------------------------------------------------------
void mifGuardTime()
{
    uint16_t a , tim ;
    tim=0;
    for( a=0; a < 50 ; a++ )   // origine = 50 tours sans pause (Trop court)
    {
       tim++; mifPause();
       if( !mifSCL || !mifSDA ){ a=0 ; }
       //if( !I2C1_Is_Idle ){ a=0 ; }
       if( tim > 50000 ) { break; }
    }
}
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
void mifSCLHigh(){
    DDRmifSCL = 1 ;
    mifPause();
    while( !mifSCL ){ DDRmifSCL = 1 ; mifPause(); }
}
void mifSCLLOW(){
    mifSCL    = 0  ;
    DDRmifSCL = 0  ;
    mifPause();
}
void mifSDAHigh(){
    DDRmifSDA = 1  ;
    mifPause();
}
void mifSDALow(){
    mifSDA    = 0  ;
    DDRmifSDA = 0  ;
    mifPause();
}
void mifI2CSendStart(){     //SCL: 1   mifSDA : 1->0
    mifI2CErr = 0 ;
    mifSCLLOW()   ;
    mifSDAHigh()  ;
    mifSCLHigh()  ;
    mifSDALow()   ;
    Delay_80us     ;        //delai supplémentaire pour entrer dans la fonction
    mifSCLHigh()  ;
}
void mifI2CSendStop(){      //SCL: 1   mifSDA : 0->1
    mifSCLLOW()    ;
    mifSDALow()    ;
    mifSCLHigh()   ;
    mifSDAHigh()   ;
}
void mifI2CSendAck(){
    mifSCLLOW()    ;
    mifSDALow()    ;
    mifSCLHigh()   ;
    mifSCLLOW()    ;
}
void mifI2CSendNotAck(){
    mifSCLLOW()    ;
    mifSDAHigh()   ;
    mifSCLHigh()   ;
    mifSCLLOW()    ;
}
void mifI2CReadAck(){
    mifSCLLOW()    ;
    mifSDAHigh()   ;
    mifSCLHigh()   ;     // 9éme coup d'orloge
    Delay_80us()   ;     //delai supplémentaire pour detecter
    if( mifSDA == 1 ){
        mifI2CErr=1;
    }else{
        mifSCLLOW();
    }
}
//---------------------------------------------
void mifI2COutByte( uint8_t I2CByteo )
{
    uint8_t I2CCountO = 8 ;
    mifSCLLOW()      ;
    while( I2CCountO > 0 ){
      if( I2CByteo & 0x80 ) mifSDAHigh(); else mifSDALow();
      mifSCLHigh()   ;
      mifSCLLOW()    ;
      I2CCountO -- ;
      I2CByteo = I2CByteo << 1 ;
    }
    mifI2CReadAck();
}
//---------------------------------------------
uint8_t mifI2CInByte()
{
    uint8_t mifI2CCountR = 8 ;
    uint8_t mifI2CByteR  = 0 ;
    mifSCLLOW()  ;
    mifSDAHigh() ;
    while( mifI2CCountR > 0 ){
      mifI2CByteR = mifI2CByteR << 1 ;
      mifI2CCountR--   ;
      mifSCLHigh()    ;
      if( mifSDA == 1 ) mifI2CByteR++ ;
      mifSCLLOW()     ;
    };
     return(mifI2CByteR);
}
//-----------------------------------------------------------------------------
void SendBuf_I2C( uint8_t *dat, uint8_t len )
{
    uint8_t counter;
    Delay_ms( 5 );           // 5 = ok
    mifGuardTime()         ; //attend que le port soit libre
    mifI2CSendStart()      ;
    mifI2COutByte(SLVADD)  ; //0xA0 = adresse de mifare
    if( !mifI2CErr ){
       for(counter=0;counter<len;counter++){
           mifI2COutByte( *(dat + counter) );
           if( mifI2CErr ){ break; }
       }
    }
    mifI2CSendStop() ;
}
//-----------------------------------------------------------------------------
void ReadBuf_I2C(uint8_t *dst, uint8_t BufSize)
{
    uint8_t counter  ;
    Delay_ms( 50 );      // >= 50 et 50=ok Attend la préparation de la réponse
    memset( dst , 0x00 , BufSize ); //Purge le buffer
    RCVSTA_SL030 = 0xFF ;           //Statut en erreur par defaut
    mifGuardTime()          ;       //attend que le port soit libre
    mifI2CSendStart()       ;
    mifI2COutByte(SLVADD|1) ;       //0xA1 = adresse de mifare en lecture
   if( !mifI2CErr ){
      *dst = mifI2CInByte() ;       //lecture de LEN
      mifI2CSendAck()  ;
      if( *dst >= BufSize-1 ) *dst = BufSize-2;
      for(counter=1 ; counter < *dst ;counter++)
      {
        *(dst + counter) = mifI2CInByte() ;
        mifI2CSendAck() ;
      }
      *(dst + counter) = mifI2CInByte() ;
      mifI2CSendNotAck() ;
      mifI2CSendStop() ;
      mifI2CErr = *(dst + 2);
   }
}
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
/*
void SendBuf_I2C( uint8_t *dat, uint8_t len )
{
    uint8_t counter;
    Delay_ms( 5 );            // 5 = ok
    mifGuardTime();           //attend que le port soit libre
    I2C1_Start();             // issue I2C1 start signal
    mifI2CErr = I2C1_Write(SLVADD); // send byte via I2C1  (command to 24cO2)
    for(counter=0;counter<len;counter++){
       mifGuardTime();
       mifI2CErr = I2C1_Write( *(dat + counter) );
    }
    I2C1_Stop();
}
//-----------------------------------------------------------------------------
void ReadBuf_I2C(uint8_t *dst, uint8_t BufSize)
{
    uint8_t counter  ;
    Delay_ms( 60 );      // >= 50 et 50=ok Attend la préparation de la réponse
    memset( dst , 0x00 , BufSize ); //Purge le buffer
    RCVSTA_SL030 = 0xFF ;           //Statut en erreur par defaut
    mifGuardTime();                 //attend que le port soit libre
    I2C1_Start();                   // issue I2C1 start signal
    I2C1_Write(SLVADD|1);           // send byte via I2C1  (device address + W)
    mifGuardTime();
    *dst = I2C1_Read(1u);           // read data LEN (acknowledge)
    if( *dst >= BufSize-1 ) *dst = BufSize-2;
    for(counter=1 ; counter < *dst ;counter++)
    {
      mifGuardTime();
      *(dst + counter) = I2C1_Read(1u);  // read data (acknowledge)
    }
    mifGuardTime();
    *(dst + counter) = I2C1_Read(0u);    // last data is read (no acknowledge)
    I2C1_Stop();
    mifI2CErr = *(dst + 2);
 }
*/
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//Code de securité: 0x7F,0x07,0x88,0x69, ne peut être modifié que par la clé B
//---------------------  445123445123  ----------------------------------------
//-----------------------------------------------------------------------------
volatile uint8_t KeyAA[6], KeyAAoptBB[16];
uint8_t UUID[16], PromaticS[6], PromaticS2[6], UUID2[16];

//Utiliser la clé A  (Clé B identique a la A mais non utilisable)
const uint8_t PromaticSecurity[]={0xFF,0x07,0x80,0x69};
//GOLD  : Lire la valeur en ligne 5 =  0x11a20390124e0000
//SILVER: Lire la valeur en ligne 5 =  0x01311379d0460000
const uint8_t PromaticA[]={0xF0,0x0D,0xFE,0xED,0xD0,0xD0 ,  \
                                 0x0B,0xB3,0x1D,0xC1,0x23,0xE5 ,  \
                                 0x75,0x78,0xBF,0x2C,0x66,0xA9 ,  \
                                 0xCD,0x21,0x28,0x89,0xC3,0xED ,  \
                                 0x69,0x36,0xC0,0x35,0xAE,0x1B ,  \
                                 0xC6,0xC8,0x66,0xAA,0x42,0x1E ,  \
                                 0x59,0x0B,0xD6,0x59,0xCD,0xD2 ,  \
                                 0xAA,0x73,0x4D,0x2F,0x40,0xE0 ,  \
                                 0x09,0x80,0x0F,0xF9,0x4A,0xAF ,  \
                                 0x5A,0x12,0xF8,0x33,0x26,0xE7 ,  \
                                 0xC5,0x54,0xEF,0x6A,0x60,0x15 ,  \
                                 0x0D,0x8C,0xA5,0x61,0xBD,0xF3 ,  \
                                 0xB8,0x93,0x71,0x30,0xB6,0xBA ,  \
                                 0xD7,0x74,0x4A,0x1A,0x0C,0x44 ,  \
                                 0x82,0x90,0x8B,0x57,0xEF,0x4F ,  \
                                 0xFE,0x04,0xEC,0xFE,0x55,0x77 };

const uint8_t ConstKeyDD[]={0x44,0x51,0xff,0x07,0x80,0x69};

const uint8_t ConstKeyAA[]={0x0F,0x44,0x51,0x23,0xAA,0xF0};   //client
const uint8_t ConstKeyBB[]={0x44,0x51,0x23,0x44,0x51,0x23};   //secrete
const uint8_t ConstKeyFF[]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
const uint8_t ConstSECURITE[]={0x0F,0x44,0x51,0x23,0xAA,0xF0  ,0x7F,0x07,0x88,0x69,  0x44,0x51,0x23,0x44,0x51,0x23};
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
const uint8_t ComSelectCard[] = {1,1};
const uint8_t ComHalt[]       = {1,0x50};
const uint8_t ComVersion[]    = {1,0xF0};
const uint8_t ComLoginSector0[]={9,2,0+0,0xBB,0x44,0x51,0x23,0x44,0x51,0x23};
// MifCmdConst( &ComLoginSector0[0] , sizeof(ComLoginSector0));
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
// codesand[0x04]  ;     // 4  octets = Shooting ground number
//Les nombres sont gérés sur 3 octets pour promatic
void MifProm_StrToLong( uint8_t *lplgc , uint32_t *Lval , uint8_t len )
{
  ((uint8_t*)Lval)[0] = *lplgc ; lplgc++ ;    // Lo
  ((uint8_t*)Lval)[1] = *lplgc ; lplgc++ ;    // Med
  ((uint8_t*)Lval)[2] = *lplgc ; lplgc++ ;    // Hi
  ((uint8_t*)Lval)[3] = 0x00;                 // Higher
  if( len > 3 )
    ((uint8_t*)&Lval)[3] = *lplgc;
}
//-----------------------------------------------------------------------------
void MifProm_LongToStr( uint32_t Lval , uint8_t *lplgc , uint8_t len )
{
  *lplgc = ((uint8_t*)&Lval)[0]; lplgc++ ;     // Lo
  *lplgc = ((uint8_t*)&Lval)[1]; lplgc++ ;     // Med
  *lplgc = ((uint8_t*)&Lval)[2]; lplgc++ ;     // Hi
  if( len > 3 )
     *lplgc = ((uint8_t*)&Lval)[3];            // Higher
}
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
/*    On doit convertir les 4 octets du noméro de stand en 2 octets
      N°1 dans le numStand
      N°2 dans le code
      On lit les infos de la carte et les convertit dans mon format
      uint8_t codesand
*/
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
void swapf( uint8_t *x )
{
  static uint8_t a, b ;
  a  = (*x & 0x0F) << 4 ;
  b  = (*x & 0xF0) >> 4 ;
  *x = a | b ;
}
//-----------------------------------------------------------------------------
void swapOctet( uint8_t *x ,uint8_t *y  )
{
  uint8_t a ;
  a  = *x ;
  *x = *y ;
  *y =  a ;
}
//-----------------------------------------------------------------------------
void rlcf(  uint8_t *x )
{
  static  uint8_t CARRY , z ;
  z = ((*x) & 0x80) ;          //Test CARRY
  (*x) <<= 1;                  //Rotate left
  if( CARRY ){ *x |= 0X01 ; }  //Set old CARRY
         else{ *x &= 0XFE ; }  //or not
  CARRY = z ;                  //Memory CARRY for the next byte
}
//-----------------------------------------------------------------------------
/*
uint8_t data1[7] ;
void Pro_EncodeData6( uint8_t *data2 )
{
     uint8_t x ;
     memcpy( &data1[0] , data2 , 0x06 );
     //---- Calcul de la cle reelle ----
     //Swap octets
     swapOctet( &data1[0] , &data1[4]);
     swapOctet( &data1[2] , &data1[5]);
     x = data1[0] ;           //Ne pas changer le 1 maintenant
     rlcf( &x );              //Init CARRY pour la suite
     rlcf( &data1[5] );
     rlcf( &data1[4] );
     rlcf( &data1[3] );
     rlcf( &data1[2] );
     rlcf( &data1[1] );
     rlcf( &data1[0] );         //Change le 1
     //Swap 1/2 octet
     swapf( &data1[0] );
     swapf( &data1[1] );
     swapf( &data1[2] );
     swapf( &data1[3] );
     swapf( &data1[4] );
     swapf( &data1[5] );
     //Increments
     data1[0] += 1;    // 0A 0B   1   A0  0A  0B
     data1[1] += 2;    // B1 B3   2   1B  B1  B3
     data1[2] += 3;    // 1A 1D   3   A1  1A  1D
     data1[3] += 4;    // AD B1   4   DB  BD  C1   - 0X10
     data1[4] += 5;    // 49 4E   5   E1  1E  23
     data1[5] += 6;    // 99 9F   6   FD  DF  E5
     memcpy( data2 , &data1[0] , 0x06 );
}
*/
//-----------------------------------------------------------------------------
void Pro_EncodeData6( uint8_t *data1 )
{
     uint8_t x ;
     //---- Calcul de la cle reelle ----
     //printf("UUID = %02X %02X %02X %02X %02X %02X \n",*data1 ,*(data1 + 1),*(data1 + 2),*(data1 + 3),*(data1 + 4),*(data1 + 5));
     //Swap octets
     swapOctet( data1 + 0 , data1 + 4 );
     swapOctet( data1 + 2 , data1 + 5 );
     //printf("KEY1 = %02X %02X %02X %02X %02X %02X \n",*data1 ,*(data1 + 1),*(data1 + 2),*(data1 + 3),*(data1 + 4),*(data1 + 5));
     //Rotations   => rlcf   with carry
     x = (*(data1 + 0)) ;   // Ne pas changer le 1 maintenant
     rlcf( &x );            // Init CARRY pour la suite
     rlcf( data1 + 5 );
     rlcf( data1 + 4 );
     rlcf( data1 + 3 );
     rlcf( data1 + 2 );
     rlcf( data1 + 1 );
     rlcf( data1 + 0 );  //Change le 1
     //printf("KEY2 = %02X %02X %02X %02X %02X %02X \n",*data1 ,*(data1 + 1),*(data1 + 2),*(data1 + 3),*(data1 + 4),*(data1 + 5));
     //Swap 1/2 octet
     swapf( data1 + 0 );
     swapf( data1 + 1 );
     swapf( data1 + 2 );
     swapf( data1 + 3 );
     swapf( data1 + 4 );
     swapf( data1 + 5 );
     //printf("KEY3 = %02X %02X %02X %02X %02X %02X \n",*data1 ,*(data1 + 1),*(data1 + 2),*(data1 + 3),*(data1 + 4),*(data1 + 5));
     //Increments
     (*(data1 + 0)) ++;
     (*(data1 + 1)) += 2;
     (*(data1 + 2)) += 3;
     (*(data1 + 3)) += 4;
     (*(data1 + 4)) += 5;
     (*(data1 + 5)) += 6;
     //printf("KEY  = %02X %02X %02X %02X %02X %02X \n",*data1 ,*(data1 + 1),*(data1 + 2),*(data1 + 3),*(data1 + 4),*(data1 + 5));
}
//-----------------------------------------------------------------------------
uint8_t Pro_Compare( uint8_t *strA , uint8_t *strB , uint8_t len )
{
   uint8_t x;
   for( x=0 ; x<len ; x++ ){
      if( (*strA) != (*strB) ){ return( 0x00 ); }
      strA++; strB++;
   }
   return( 0x01 );
}
//-----------------------------------------------------------------------------
const uint8_t Seed[6]={0xF0,0x0D,0xFE,0xED,0xD0,0xD0};
//-----------------------------------------------------------------------------
void Pro_Genoldkey( uint8_t *key , uint8_t index )
{
    uint8_t x;
    memcpy( key , &Seed[0] , 0x06 );
    for( x=0 ; x<index ; x++ ){ Pro_EncodeData6( key ); }
}
//-----------------------------------------------------------------------------
void Pro_StoreEncodedUID( str_Promatic_Infos *carte , uint8_t *lpUUID )
{
     uint8_t x ;
     //---- Clean all structure
     memset( &mifcarte.texte , 0 , sizeof(mifcarte.texte) );
     memset( carte , 0x00 , sizeof( str_Promatic_Infos ));
     memcpy( carte->init.UUIDbase    , lpUUID , 0x04 );
     memcpy( carte->init.UUIDcrypted , lpUUID , 0x04 );
     //---- Basic encode one time and StoreEncodedUID ----
     Pro_EncodeData6( carte->init.UUIDcrypted );
     //---- EncryptUIDagain ---- Gen key for Xtreme ----
     x = (*(carte->init.UUIDcrypted + 5));
     (*(carte->init.keyA + 5)) = (*(carte->init.UUIDcrypted + 5)) + (*(carte->init.UUIDcrypted + 4)) ;
     (*(carte->init.keyA + 4)) = (*(carte->init.UUIDcrypted + 4)) + (*(carte->init.UUIDcrypted + 3)) ;
     (*(carte->init.keyA + 3)) = (*(carte->init.UUIDcrypted + 3)) + (*(carte->init.UUIDcrypted + 2)) ;
     (*(carte->init.keyA + 2)) = (*(carte->init.UUIDcrypted + 2)) + (*(carte->init.UUIDcrypted + 1)) ;
     (*(carte->init.keyA + 1)) = (*(carte->init.UUIDcrypted + 1)) + (*(carte->init.UUIDcrypted + 0)) ;
     (*(carte->init.keyA + 0)) = (*(carte->init.UUIDcrypted + 0)) + x ;
}
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
void AuthCalculCleA()
{
  uint32_t lpc ;
  //Mémorise la clé active
  memcpy( &KeyAA      , &ConstKeyAA    , 6  );  //Clé de base initiale
  memcpy( &KeyAAoptBB , &ConstSECURITE , 16 );  //Bloc de formatage 16 octets
  memcpy( &lpc , &KeyAA[1] , 4 );               //Transforme en long
  lpc += mifcarte.num ;                         //encode par débordement
  memcpy( &KeyAA[1]   , &lpc   , 4 );           //Mémorise la clé active
  memcpy( &KeyAAoptBB , &KeyAA , 6 );           //La meme dans la complete
}
//-----------------------------------------------------------------------------
// Retourne 1 si c'est un bloc systéme et 0 pour un bloc data
uint8_t CheckKeyBlock( uint8_t nBlock )
{
  uint8_t i;
  for( i = 3 ; i < 64 ; i+=4 ){ if( nBlock == i ){ return( 1 ); } }
  return( 0 );
}
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
void MifCmdConst( const uint8_t *cmd , uint8_t len )
{
    memcpy( &g_cTxBuf[0] , cmd , len );
    SendBuf_I2C( &g_cTxBuf[0]  , len );
}
//-----------------------------------------------------------------------------
//--- Retourne 0 si erreur
uint8_t MifCmdAuth( uint8_t UseKeyA , uint8_t Nligne )
{
    uint8_t x ;
    if( CARD_INSERT ) return( 0x00 );
    SNDLEN = 9 ; SNDCOMMAND = 0x02 ; SNDDATASTART = Nligne / 4 ; //N° de bloc
    if( UseKeyA == 0xAA ){
        g_cTxBuf[3] = 0xAA ;
        memcpy( &g_cTxBuf[4] , &KeyAA , 0x06 );//Dynamique  TYPELECTEUR_MIFARE
        //memcpy( &g_cTxBuf[4] , &ConstKeyAA , 0x06 );    //Statique

    }else if( UseKeyA == 0xBB ){
        g_cTxBuf[3] = 0xBB ;
        memcpy( &g_cTxBuf[4] , &ConstKeyBB , 0x06 );

    }else if( UseKeyA == 0xDD ){       //Promatic OLD       TYPELECTEUR_PROM
        g_cTxBuf[3] = 0xAA ;
        Pro_Genoldkey( &KeyAA , SNDDATASTART );
        memcpy( &g_cTxBuf[4] , &KeyAA , 0x06 );

    }else if( UseKeyA == 0xEE ){       //Promatic Secure     TYPELECTEUR_PROM_X
        g_cTxBuf[3] = 0xAA ;
        memcpy( &g_cTxBuf[4] , &Promatic_Infos.init.keyA[0] , 0x06 );
        //
        //L2(); PrintHexa( &g_cTxBuf[4] , 6 );
        //Pause( 5000 );
    }else{
        g_cTxBuf[3] = 0xAA ;
        memcpy( &g_cTxBuf[4] , &ConstKeyFF , 0x06 );
    }
    SendBuf_I2C( &g_cTxBuf[0] , SNDLEN + 1 );
    ReadBuf_I2C( &g_cRxBuf[0] , sizeof(g_cRxBuf) );
    if((RCVCMD_SL030!=0x02)||(RCVSTA_SL030!=0x02)) {     //erreur
       mifI2CErr = ERRAUTHENTIFICATION ;
       return( 0 );
    }
    return( 1 );
}
//-----------------------------------------------------------------------------
uint8_t MifCmdAuthAuto( uint8_t Nligne )
{
      if( CleTravailType == 0xFF ){
        if( !MifCmdAuth( 0xFF , Nligne ) ){ return( 0x00 ); }
      }else if( CleTravailType == 0xAA ){
        if( !MifCmdAuth( 0xAA , Nligne ) ){ return( 0x00 ); }
      }else if( CleTravailType == 0xDD ){
        if( !MifCmdAuth( 0xDD , Nligne ) ){ return( 0x00 ); }
      }else if( CleTravailType == 0xEE ){
        if( !MifCmdAuth( 0xEE , Nligne ) ){ return( 0x00 ); }
      }else{
        if( !MifCmdAuth( 0xBB , Nligne ) ){ return( 0x00 ); }
      }
      return( 0x01 );
}
//-----------------------------------------------------------------------------
//--- Retourne les 16 octets de la ligne selectionnée ---
uint8_t MifCmdReadTexte( uint8_t nblock , void * out )
{
    SNDLEN = 2 ;  SNDCOMMAND = 0x03 ;  SNDDATASTART = nblock ; //N° de bloc
    SendBuf_I2C( &g_cTxBuf[0] , SNDLEN + 1 );
    ReadBuf_I2C( &g_cRxBuf[0] , sizeof(g_cRxBuf) );
    if((RCVCMD_SL030!=0x03)||(RCVSTA_SL030!=0x00)) {    //erreur
       mifI2CErr = ERRLECTURE ;
       return( 0x00 );
    }
    memcpy( out , &g_cRxBuf[3] , 16 );
    return( 0x01 );
}
//-----------------------------------------------------------------------------
uint8_t MifCmdWriteData( uint8_t nblock , uint8_t *datas )
{
//  if( cle != 0xFF ){
       if( CheckKeyBlock( nblock ) ){  //Pas de clé de protection
         mifI2CErr = ERRPROTECTIONCLES ;
         return( 0 );
       }
//  }
    memcpy( &g_cTxBuf + 0x03 , datas , 16 );
    SNDLEN = 18 ;  SNDCOMMAND = 0x04 ;  SNDDATASTART = nblock ;
    SendBuf_I2C( &g_cTxBuf[0] , SNDLEN + 1 );
    ReadBuf_I2C( &g_cRxBuf[0] , sizeof(g_cRxBuf) );
    if((RCVCMD_SL030!=0x04)||(RCVSTA_SL030!=0x00)) {   //erreur
         mifI2CErr = ERRECRITURE ;
         if( nblock > 0 ) return( 0 );
    }
    return( 1 );
}
//-----------------------------------------------------------------------------
uint8_t MifCmdWriteSecure( uint8_t nblock, uint8_t promat )
{
  uint8_t pos , *p ;
  if( CheckKeyBlock( nblock ) ){      //Uniquement de clé de protection
    if( MifCmdAuthAuto( nblock )){
    //----------
    if( promat == 1 ){
        pos = nblock / 4 ;
        if( pos > 15 ) return( 1 );  //7 = cle FFFFFF...
        p   = &PromaticA[ pos * 6 ] ;
        memcpy( &g_cTxBuf + 0x03 , p , 6 );
        memcpy( &g_cTxBuf + 0x09 , &PromaticSecurity[0] , 4 ); //Formt Promatic
        memcpy( &g_cTxBuf + 0x0D , p , 6 );
    }else if( promat == 2 ){
        memcpy( &g_cTxBuf + 0x03 , &ConstKeyFF[0] , 6 );
        memcpy( &g_cTxBuf + 0x09 , &PromaticSecurity[0] , 4 ); //Mise a blanc
        memcpy( &g_cTxBuf + 0x0D , &ConstKeyFF[0] , 6 );
    }else{
        memcpy( &g_cTxBuf + 0x03 , &KeyAAoptBB[0] , 16 );      //Formatage jpb
    }
    //----------
    SNDLEN = 18 ;  SNDCOMMAND = 0x04 ;  SNDDATASTART = nblock ;
    SendBuf_I2C( &g_cTxBuf[0] , SNDLEN + 1 );
    ReadBuf_I2C( &g_cRxBuf[0] , sizeof(g_cRxBuf) );
    if((RCVCMD_SL030!=0x04)||(RCVSTA_SL030!=0x00)) { return( 0 ); } //erreur
    return( 1 );
    }
  }
  return( 0 );
}
//-----------------------------------------------------------------------------
uint8_t MifCmdNumInit( uint8_t nblock , uint32_t value  )
{
  uint8_t res ;
  res = 1 ;
  if(CheckKeyBlock(nblock)||(CleTravailType ==0xDD )||(CleTravailType ==0xEE)){
      res = 0 ;
  }else{
    //Pas de clé de protection sur bloc 0 ou promatic
    memcpy( &SNDDATASTART + 1 , &value , 4 );
    SNDLEN = 6 ;  SNDCOMMAND = 0x06 ;  SNDDATASTART = nblock ;
    SendBuf_I2C( &g_cTxBuf[0] , SNDLEN + 1 );
    ReadBuf_I2C( &g_cRxBuf[0] , sizeof(g_cRxBuf) );
    if((RCVCMD_SL030!=0x06)||(RCVSTA_SL030!=0x00)) { res = 0 ; } //erreur
  }
  return( res );
}
//-----------------------------------------------------------------------------
uint8_t MifCmdNumAdd( uint8_t nblock , uint32_t value )
{
  uint8_t res ;
  uint32_t total ;
  if( (CleTravailType == 0xDD)||(CleTravailType == 0xEE) ){     //Promatic
    res = 1 ;
  }else{
    res = 1 ;
    memcpy( &SNDDATASTART + 1 , &value , 4 );
    SNDLEN = 6 ;  SNDCOMMAND = 0x08 ;  SNDDATASTART = nblock ;
    SendBuf_I2C( &g_cTxBuf[0] , SNDLEN + 1 );
    ReadBuf_I2C( &g_cRxBuf[0] , sizeof(g_cRxBuf) );
    if((RCVCMD_SL030!=0x08)||(RCVSTA_SL030 > 0x05)) { res = 0 ; } //erreur
  }
  return( res );
}
//-----------------------------------------------------------------------------
uint8_t MifCmdNumDecrease( uint8_t nblock , uint32_t value )
{
  uint8_t res ; uint32_t total , tires , solde ;
  if( (CleTravailType == 0xDD)||(CleTravailType == 0xEE) ){     //Promatic
    res = 1 ;
  }else{
    res = 1 ;
    memcpy( &SNDDATASTART + 1 , &value , 4 );
    SNDLEN = 6 ;  SNDCOMMAND = 0x09 ;  SNDDATASTART = nblock ;
    SendBuf_I2C( &g_cTxBuf[0] , SNDLEN + 1 );
    ReadBuf_I2C( &g_cRxBuf[0] , sizeof(g_cRxBuf) );
    if((RCVCMD_SL030!=0x09)||( RCVSTA_SL030 > 0x05 )) {
      //L1(); Print("res: "); PrintNum8( RCVSTA_SL030 ); Pause( 2000 );
      res = 0 ;      //erreur
    }
  }
  return( res );
}
//-----------------------------------------------------------------------------
uint8_t MifCmdNumRead( uint8_t nblock , uint32_t * valret )
{
    SNDLEN = 2 ;  SNDCOMMAND = 0x05 ;  SNDDATASTART = nblock ;
    SendBuf_I2C( &g_cTxBuf[0] , SNDLEN + 1 );
    ReadBuf_I2C( &g_cRxBuf[0] , sizeof(g_cRxBuf) );
    if((RCVCMD_SL030!=0x05)||(RCVSTA_SL030!=0x00)) { return( 0 ); } //erreur
    memcpy( valret , &RCVDAT_SL030 , 4 );
    return( 1 );
}
//-----------------------------------------------------------------------------
uint8_t MifCmdIndexWrite()
{
  void * adr;
  if( mifcarte.stands[0].type >= TYPECARTE_PROMATIC ){ return( 0 ); }
  //-----------------------------------------
  if( MifCmdAuth( CleTravailType , 0x01 ) )  {
      adr = &mifcarte.stands[0] ;
      if( !MifCmdWriteData( 0x01 , adr )  )      { return( 0 ); }
      if( !MifCmdWriteData( 0x02 , adr + 16 )  ) { return( 0 ); }
      return( 1 );
   }
   return(0);
}
//-----------------------------------------------------------------------------
// IndexStand va de 0 a 7 suivant l'entete de la carte
// Le 1er compteur se trouve a l'adresse 12 sur le bloc 3
uint8_t MifFormatCompteurs( uint8_t IndexStand )
{
  uint8_t posCpt1;
  if( IndexStand < 8 ){
    posCpt1 = ( IndexStand * 4 ) + 12 ;
     if( MifCmdAuth( CleTravailType , posCpt1 ) )  {
       if(  MifCmdNumInit( posCpt1     , 0 ) ) {
         if( MifCmdNumInit( posCpt1 + 1 , 0 ) ){
           if( MifCmdNumInit( posCpt1 + 2 , 0 ) ){
              return( 1 );
           }
         }
       }
     }
  }
  return( 0 );
}
//-----------------------------------------------------------------------------
// IndexStand va de 0 a 7 suivant l'entete de la carte
// Le 1er compteur se trouve a l'adresse 12 sur le bloc 3
uint8_t MifStandCompteursRead( uint8_t IndexStand )
{
  uint8_t posCpt1;
  if( IndexStand < 8 ){
    posCpt1 = ( IndexStand * 4 ) + 12 ;
    if( MifCmdAuth( CleTravailType , posCpt1 ) )  {
      if(  MifCmdNumRead( posCpt1     , &mifcarte.compteur[0] ) ) {
           MifCmdNumRead( posCpt1 + 1 , &mifcarte.compteur[1] );
           MifCmdNumRead( posCpt1 + 2 , &mifcarte.compteur[2] );
           return( 1 );
      }
    }
  }
  return( 0 );
}
//-----------------------------------------------------------------------------
//Utilise le buffer de texte en mode temporaire
uint8_t MifReadBlocComplet( uint8_t LigneBlocDepart )
{
   uint8_t pos;
   if( LigneBlocDepart > 15 ) return(0);
   pos = LigneBlocDepart * 4 ;
   memset( &mifcarte.texte , 0 , sizeof(mifcarte.texte) );
   if( MifCmdAuthAuto( pos ) ){
         MifCmdReadTexte( pos      , &mifcarte.texte[0x00] ) ;
         MifCmdReadTexte( pos + 1  , &mifcarte.texte[0x10] );
         MifCmdReadTexte( pos + 2  , &mifcarte.texte[0x20] );
         return( 1 );
   }
   return(0);
}
//-----------------------------------------------------------------------------
//Utilise le buffer de texte ou autre en mode temporaire
uint8_t MifWriteBlocComplet( uint8_t LigneBlocDepart , uint8_t * str)
{
   uint8_t pos , res ;
   res = 0;
   if( LigneBlocDepart > 15 ){
       mifI2CErr = ERRDEBORDEMENT ;
   }else{
     pos = LigneBlocDepart * 4 ;
     if( MifCmdAuthAuto( pos ) ){
        MifCmdWriteData( pos      , str );
        str += 16 ;
        MifCmdWriteData( pos + 1  , str );
        str += 16 ;
        MifCmdWriteData( pos + 2  , str );
        res = 1 ;
     }else{
        mifI2CErr = ERRAUTHENTIFICATION ;
     }
   }
   return( res );
}
//-----------------------------------------------------------------------------
uint8_t MifFormatTexte()
{
   memset( &mifcarte.texte , 0x00 , sizeof(mifcarte.texte) );
   if( !MifCmdAuthAuto(  4 ) ) return( 8 );
   if( !MifCmdWriteData( 4  , &mifcarte.texte[0x00] ) )return( 7 );
   if( !MifCmdWriteData( 5  , &mifcarte.texte[0x10] ) )return( 6 );
   if( !MifCmdWriteData( 6  , &mifcarte.texte[0x20] ) )return( 5 );
        MifCmdAuthAuto(  8 );
   if( !MifCmdWriteData( 8  , &mifcarte.texte[0x30] ) )return( 4 );
   if( !MifCmdWriteData( 9  , &mifcarte.texte[0x40] ) )return( 3 );
   if( !MifCmdWriteData( 10 , &mifcarte.texte[0x50] ) )return( 2 );
        return( 1 );
}
//-----------------------------------------------------------------------------
void Pro_AddRemouveGlobal( uint16_t dval , uint8_t sens  )
{
   uint32_t lv ;
   MifProm_StrToLong( &Promatic_Infos.L5.CustCnt[0] , &lv , 0x03 );
   if( sens ){ lv += dval ; }else{ lv -= dval ; }
   MifProm_LongToStr( lv , &Promatic_Infos.L5.CustCnt[0] ,0x03 );
   if( MifCmdAuthAuto( 0x05 ) ){
       MifCmdWriteData( 0x05 ,(uint8_t *)&Promatic_Infos.L5 );
   }
}
//-----------------------------------------------------------------------------
uint8_t MifCmdProTestFirstTimeUse()  // Erase all memory if this card is used
{
 const uint8_t FirstTimeRunMap[0x10]={0x46,0x6F,0x72,0x63,0x65,0x20,0x46,0x69,0x72,0x73,0x74,0x020,0x54,0x69,0x6D,0x65};
 uint8_t tmp[0x10];
  if( MifCmdAuthAuto( 58 ) ){
      MifCmdReadTexte( 58 , &tmp ) ;
      if( Pro_Compare(&tmp , &FirstTimeRunMap , 0x0F )){
           return( 1 );                                     // FFT Card
      }
      else if( MifCmdAuthAuto( 62 ) ){
           MifCmdReadTexte( 62 , &tmp ) ;
           if( Pro_Compare(&tmp , &FirstTimeRunMap , 0x0F )){
               return( 1 );                                 // FFT Card
           }
      }
  }
  return( 0 );    //Normal card
}
//-----------------------------------------------------------------------------
uint8_t MifCmdPromaticReadType()  // Lit les 3 lignes utiles
{
   uint16_t v16v , x16x , Uplift ;
   uint8_t  x , y , res ;
   // Test si carte d'effacement: FIRST TIME USE
   MifCmdAuthAuto( 0x04 );
   res = 0 ;

   if( MifCmdProTestFirstTimeUse() > 0 ){
       L2(); Print(" FIRST TIME USE");
/*
       //ResetAllMEMORY( 0x02 );
       MemSaved.ADRPROMCLEWORD = 0x0000 ;
       MemSaved.NUMSTAND       = 0x0000 ;
       MemSaved.Securecode     = 0x00 ;
       MemSaved.ADRPROMBOITE   = 0x00 ;
       MemSaved.PASSWORD       = 0xEEEE ;
       EEpromSave();
       ResetProcesseur();
*/
   }

   //------
   if( MifCmdAuthAuto( 0x04 ) ){
       res = 1 ;
       MifCmdReadTexte( 0x04 , &Promatic_Infos.L4 ) ;
       //------
       // Test la validité de la carte
       if( !Pro_Compare(&Promatic_Infos.init.UUIDcrypted[0] ,
                        &Promatic_Infos.L4.ecuid[0] , 0x06 ) )
       {
           L1(); Print("ERROR CARD !");
           Pause( 2000 );
           memset( &Promatic_Infos , 0x00 , sizeof(Promatic_Infos));
           return( 0 );
       }
       // On continue la lecture
       MifCmdReadTexte( 0x05 , &Promatic_Infos.L5 ) ;
       MifCmdReadTexte( 0x06 , &Promatic_Infos.L6 ) ;
       if( MifCmdAuthAuto( 0x00 ) ){
            MifCmdReadTexte( 0x01 , &mifcarte.texte[0x00] ) ;
            MifCmdReadTexte( 0x02 , &mifcarte.texte[0x10] ) ;
       }
       // Chargement du compteur ==> On utilise seulement le 1er compteur
       if( TestMoneyUse ){
         if( TestCountUP  ){
           v16v = Promatic_Infos.L6.CashCnt - Promatic_Infos.L6.RipCashLim ;
         }else{
           v16v = Promatic_Infos.L6.CashCnt ;
         }
         if( !Promatic_Infos.L6.coast[0] ) Promatic_Infos.L6.coast[0] = 24u;
         if( !Promatic_Infos.L6.coast[1] ) Promatic_Infos.L6.coast[1] = 32u;
         if( !Promatic_Infos.L6.coast[2] ) Promatic_Infos.L6.coast[2] = 40u;
         mifcarte.compteur[0] = v16v / Promatic_Infos.L6.coast[0] ;
         mifcarte.compteur[1] = v16v / Promatic_Infos.L6.coast[1] ;
         mifcarte.compteur[2] = v16v / Promatic_Infos.L6.coast[2] ;

       }else{
         if( TestCountUP  ){
           v16v = Promatic_Infos.L6.limit - Promatic_Infos.L6.count ;
         }else{
           v16v = Promatic_Infos.L6.count ;
         }
         mifcarte.compteur[0] = v16v ;
         mifcarte.compteur[1] = v16v ;
         mifcarte.compteur[2] = v16v ;
       }
       // Le type de carte
       mifcarte.stands[0x07].type = TYPECARTE_CLIENT ;

       // Only for unlock card loader
       if( TestStafCard  ) mifcarte.stands[0x07].type = TYPECARTE_STAF ;
       if( TestManager   ) mifcarte.stands[0x07].type = TYPECARTE_MASTER ;

       // Le Numéro 16 est compilé en codesand 8 + numéro 8
       mifcarte.stands[0x07].codesand = Promatic_Infos.L4.codesand[1] ^ Promatic_Infos.L4.codesand[3] ;
       mifcarte.stands[0x07].numero   = Promatic_Infos.L4.codesand[0] ^ Promatic_Infos.L4.codesand[2] ;

       // ==> Met un numéro de série a ce boitier
       if( TestSerialBase )
       {
           mifcarte.stands[0x07].type = TYPECARTE_SERIAL ;
           //Incrementer le numéro sur la carte



           // Mettre le numéro de série ici pour enregistrement
           mifcarte.compteur[0]           = v16v ;
           mifcarte.compteur[1]           = v16v + 1;
           mifcarte.compteur[2]           = v16v + 2 ;
           mifcarte.stands[0x07].codesand = 0x00 ;
       }

       // ==> Met le numéro de stand et code dans cette boite  ==>ok
       // ==> On doit incrémenter le numéro de materiel si changement de stand
       //     pour les stastistiques. 0=caisse ....
       Uplift = MemSaved.Uplift ;   //Code de securité interne

       if( TestMasterGround )
       {
         x = Lo( MemSaved.NUMSTAND );
         y = MemSaved.Securecode;
         if(((mifcarte.stands[0x07].numero==x)&&(mifcarte.stands[0x07].codesand==y))||((x == 0)&&(y == 0)))
         {
           mifcarte.stands[0x07].type = TYPECARTE_MASTER ;

           if( Promatic_Infos.L5.flags == 0x01 )    //Autorise le mode free
           {
               mifcarte.stands[0x07].type = TYPECARTE_MASTER_X ;
             //Mémorise le code de securité
             //if( Uplift != Promatic_Infos.L4.UpliftHiLo ){
                 MemSaved.ADRPROMCLEWORD = Promatic_Infos.L4.UpliftHiLo ;
                 Uplift = Promatic_Infos.L4.UpliftHiLo ;
             //}
           }

           //---- NEW ----
           if((x==0)&&(y==0))
           {
             //Num stand
             MemSaved.NUMSTAND = mifcarte.stands[0x07].numero ;
             //Code => Suite du N° de stand
             MemSaved.Securecode = mifcarte.stands[0x07].codesand ;
             MemSaved.EPRPOSGRATUIT = 0;   //Gratuits

             //Incremente le N° de machine du stand sur la carte(Adresse reseau)
             Promatic_Infos.L5.cid ++ ;
             MemSaved.ADRPROMBOITE = Promatic_Infos.L5.cid ;
             //Enregistrement sur la carte
             MifCmdAuthAuto( 0x05 );
             if( !MifCmdWriteData( 0x05 ,(uint8_t *)&Promatic_Infos.L5 ) ) {
               res = 0;
             }else{
               EEpromSave();
             }
           }
         }else{
           res = 0 ;
         }
       }

       // On dit que c'est promatic Ancien ou Nouveau
       if( CleTravailType == 0xDD ){
            mifcarte.stands[0x07].type |= TYPECARTE_PROMATIC ; //Ancienne cle
       }else{
            mifcarte.stands[0x07].type |= TYPECARTE_PROM_ATI ; //Cle Xtreme
       }

       // Active la securité ou pas
       /*
       if( Promatic_Infos.L4.UpliftHiLo != Uplift ){
           res = 0 ;
       }
       */
   }
   return( res );
}
//-----------------------------------------------------------------------------
//retourne l'index du stand ou 0xFF avec création si nécessaire.
uint8_t MifStandCherche()
{
   uint8_t x ;
   if( mifcarte.stands[0].type == TYPECARTE_SCORES   ) { return( 0x00 ); }
   if( mifcarte.stands[0].type >= TYPECARTE_PROMATIC ) { return( 0x07 ); }
   //----------------------------
   if( InfoStand.numero == 0 ){ return( 0xFF ); }
   for( x = 0 ; x < 8 ; x++ ){
        if( mifcarte.stands[x].numero == 0 ) break;
        if( mifcarte.stands[x].numero == InfoStand.numero ) { return( x ); }
        if( mifcarte.stands[x].type == TYPECARTE_FORMATAG ){ return( x );}
        if( mifcarte.stands[x].type == TYPECARTE_JPB ){ return( x ); }
   }
   //Vérifie s'il reste de la place
   if( (x > 7)||( mifcarte.stands[7].numero > 0 ) ){ return( 0xFF ); }
   //Création si possible
   mifcarte.stands[x].numero   = InfoStand.numero ;
   mifcarte.stands[x].codesand = InfoStand.codesand ;
   mifcarte.stands[x].type     = 0x00 ;           //Client par defaut
   if( !MifCmdIndexWrite() ){ return( 0xFF ); }   //Enregistrement
   MifFormatCompteurs( x );                       //Purge des compteurs
   return( x );
}
//-----------------------------------------------------------------------------
//---- Réveil du module ----
void mifWAKEUP()
{
//    if( (clavier() & 0b0000000011111111) > 0 ){ return; }  // 1 a 8
    //---------------------
    CARD_MCLR   = 1 ;
    Delay_ms( 80 ) ;       // Origine 80
    //---------------------
//    if( (clavier() & 0b0000000011111111) > 0 ){ return; }  // 1 a 8
    //---------------------
    CARD_MCLR  = 0 ;
    Delay_ms( 80 ) ;       // 30 = non ==> 80 oui
}
//-----------------------------------------------------------------------------
uint8_t MifCartePresente()    // en tout 0.5 seconde
{
    uint8_t x ;
    if( CARD_INSERT == 1 ) { mifWAKEUP(); }    //Active si absente
    for( x=0 ; x < 50 ; x++ ){
        Delay_ms( 8 );
        if( !CARD_INSERT ) return( 1 );        //On attend pas car deja la
//        if( (clavier() & 0b0000000011111111) > 0 ){ break; }  // 1 a 8
    }
    mifHALT();
    return( 0 );
}
//-----------------------------------------------------------------------------
uint32_t bytes_to_num( uint8_t * src )
{
        uint32_t num = 0;
        uint8_t len = 4 ;
        while (len--){
                num = (num << 8) | (*src);
                src++;
        }
        return num;
}
//-----------------------------------------------------------------------------
uint16_t LongToIntXor( uint32_t in )
{
  return( (LoWord( in ) ^ HiWord( in )) );
}
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//--- Retourne 0 ou le numéro de la carte  (1 = carte vierge )
uint16_t MifStandGetATR()
{
   uint8_t x ;
   //CleTravailType = 0xBB ;
   CleTravailType = TYPECLEBASE ;
   memset( &mifcarte , 0x00 , sizeof(mifcarte));     //Purge la structure
   //--------------------
   if( CARD_INSERT ){
       if( MifCartePresente() == 0 ) { return( 0x0000 ); }
   }
   //--------------------
   for( x=0 ; x < 20 ; x++ ){
      Delay_ms( 50 );
      MifCmdConst(ComSelectCard,sizeof(ComSelectCard));
      ReadBuf_I2C( &g_cRxBuf[0], sizeof(g_cRxBuf) );
      if( RCVSTA_SL030 == 0x00 ) break;
   }
   //--------------------
   if( !RCVSTA_SL030 == 0x00 ){
        mifHALT();
        mifI2CErr=ERRTYPECARTE;
        L1(); Print("No response");
        return( 0 );
   }
   //Type Mifare
   switch( g_cRxBuf[0x07] ){
   case 1 :
   case 2 :
   case 4 :
   case 5 :  break;
   default :
        mifHALT();
        mifI2CErr=ERRTYPECARTE;
        return( 0 );
   }
   //--------------------
   memcpy( &UUID , &RCVDAT_SL030 , 0x0F );           //Copie le N° de serie
   memcpy( &UUID2, &RCVDAT_SL030 , 0x0F );           //Copie le N° de serie
   memcpy( &mifcarte.num , &RCVDAT_SL030 , 0x04 );   //Copie le N° de carte
   AuthCalculCleA();
   Pro_StoreEncodedUID( &Promatic_Infos , (uint8_t *)&mifcarte.num );
   mifcarte.num = bytes_to_num( &RCVDAT_SL030 );
   //--------------------
   /*
   MifCmdConst( &ComLoginSector0[0] , sizeof(ComLoginSector0));
   ReadBuf_I2C( &g_cRxBuf[0] , sizeof(g_cRxBuf) );
   if((RCVCMD_SL030!=0x02)||(RCVSTA_SL030!=0x02)) {
   */
   if( !MifCmdAuth( CleTravailType , 0x00 ) ) {    //Auth Normale

      if( MifCmdAuth( 0xFF , 0x00 ) ){             //Carte vierge !!
           CleTravailType = 0xFF ;                 //Mémorise la clé de travail
           mifI2CErr |=  ERRNEUVE ;
           return( 1 );
      }else if( MifCmdAuth( 0xBB , 0x00 ) ){       //Carte a modifier !!
           CleTravailType = 0xBB ;                 //Mémorise la clé de travail
           //for( x = 3 ; x < 64 ; x+=4 ){ MifCmdWriteSecure( x ); }
           /*
           memset( &mifcarte.texte , 0x00 , 16 );
           memcpy( &mifcarte.texte , &KeyAA[0]      , 6 );
           memcpy( &mifcarte.texte[0x07] , &KeyAAoptBB[0] , 6 );
           MifCmdWriteData( 62  , &mifcarte.texte );
           */
           //mifI2CErr +=  ERRNEUVE ;
          // MifCmdAuth( 0xBB , 0x00 );
           return( 1 );
      }else if( MifCmdAuth( 0xDD , 0x00 ) ){       //Carte promatic Ancienne
           CleTravailType = 0xDD ;
           mifI2CErr = ERRpromaticCARD ;
           mifcarte.stands[0].type     = TYPECARTE_PROMATIC ;

      }else if( MifCmdAuth( 0xEE , 0x00 ) ){       //Carte promatic Nouvelle
           CleTravailType = 0xEE ;
           mifI2CErr = ERRpromaticCARD ;
           mifcarte.stands[0].type     = TYPECARTE_PROM_ATI ;

      }else{
        mifI2CErr |= ERRAUTHENTIFICATION ;
        mifHALT();
        return( 0 );                               //erreur
      }
   }
    //--------------------------------
    if( mifI2CErr == ERRpromaticCARD ){
        if( MifCmdPromaticReadType()==0x00 ){
           L1(); Print("CARD Type 0");
           Pause( 2000);
           return(0x00);//Analyse de la carte
        }
        /*
        L1();
              PrintHexa( &Promatic_Infos.L4.codesand[0] , 4 ); Print(" ");
              if( TestCountUP  ){Print("CU ");}else{Print("CD ");}
              if( TestMoneyUse ){Print("Money ");}else{Print("Clay ");}
              PrintHexa( &CleTravailType , 1 );
        L2();
              PrintHexa( &mifcarte.stands[0x07].type , 1 ); Print(" ");
              if( TestSubMaster )   {Print("SM ");}
              if( TestStafCard  )   {Print("MA ");}
              if( TestMasterGround ){Print("MG ");}  // OK

        L1(); PrintHexaLong( Promatic_Infos.L4.codesand );
              PrintHexa( &Promatic_Infos.L5.CMD , 1 ); Print(" ");
              if( Promatic_Infos.L4.FlCountUpDown ){Print("U");}else{Print("D");}
        L2();
              Print("M:");
              if( Promatic_Infos.L4.FlClaysMoney ){Print("1");}else{Print("0");}
              Print(" 7:");
              if( Promatic_Infos.L4.FlMasterCardPgm ){Print("1");}else{Print("0");}
              Print(" 6:");
              if( Promatic_Infos.L4.FlSubMaster ){Print("1");}else{Print("0");}
              Print(" 5:");
              if( Promatic_Infos.L4.FlStafCard ){Print("1");}else{Print("0");}
        */
        //Pause( 1000 );

        Delay_ms( 50 );
        return( LongToIntXor( mifcarte.num ) );
    }
    //--- On peux lire les données du bloc 1 des 8 stands possibles ---
    if( !MifCmdReadTexte( 1 , &mifcarte.stands[0] ) ) { mifI2CErr |= ERRLECTURE ; return( 0 ); }
    Delay_ms( 50 );
    //if( !MifCmdReadTexte( 2 , &mifcarte.stands[4] ) ) { mifI2CErr |= ERRLECTURE ; return( 0 ); }
    //--------------------------------
    //--- On charge les 3 compteurs en mémoire
    MifStandCompteursRead( MifStandCherche() );
    //memcpy( &mifcarte.texte , &KeyAA , 6 );
    //--------------------------------
    return( LongToIntXor( mifcarte.num ) ); //OK
}
//-----------------------------------------------------------------------------
void mifI2CInit()
{
    mifI2CErr = 0  ;       //Gestion de l'erreur interne I2C
    CARD_MCLR = 0 ;        //Envoie du 0v = Module en fonction
    mifWAKEUP();
    memset( &mifcarte , 0x00 , sizeof(mifcarte));     //Purge la structure
}
//-----------------------------------------------------------------------------
void mifHALT()
{
    MifCmdConst(ComHalt,sizeof(ComHalt)); //Commande de stop
    Delay_ms( 80 ) ;
    CARD_MCLR  = 1 ;      //Envoie du 3v = Module stop
}
//-----------------------------------------------------------------------------
// doit retourner 9 si pas d'erreur
uint8_t MifStandFormatageComplet()
{
   uint8_t x , res;
   res = 0;         //Toutes les Promatic
   if( MifResTypeDeCarte() >= TYPELECTEUR_PROM ) {return( 0xFF );}
   //Purge les stands inscrits
  if( !MifCmdAuthAuto( 0x00 ) ) { return( 0xFF ); }
   //-------------------------------
   memset( &mifcarte.stands , 0x00 , 32 );
   if( !MifCmdIndexWrite() ){ return( 0xFE ); }
   //-------------------------------
   res = MifFormatTexte();
   if( res != 1 ) return( res );          //Nettoie le texte
   //-------------------------------      //Nettoie tous les compteurs
   for( x = 0 ; x < 8 ; x++ ){ MifFormatCompteurs( x ); }
   res += 8 ;
   //-------------------------------
   if( CleTravailType == 0xFF){           //Modifie la sécurité
      for( x = 3 ; x < 65 ; x+=4 ){ MifCmdWriteSecure( x , 0 ); }
   }
   return( res );
}
//-----------------------------------------------------------------------------
// doit retourner > 0 si pas d'erreur
uint8_t MifStandFormatageBlanc()
{
   uint8_t x , res;    //Toutes les Promatic
   if( MifResTypeDeCarte() >= TYPELECTEUR_PROM ) {return( 0 );}
   res = 0; memset( &mifcarte.texte , 0xFF , 0x30 );
   //-------------------------------
   for( x = 3 ; x < 65 ; x+=4 ){
     if( MifCmdWriteSecure( x , 2 ) ){
        res++;
        MifCmdWriteData( x - 1  , &mifcarte.texte[0x20] );
        MifCmdWriteData( x - 2  , &mifcarte.texte[0x10] );
        if( (x - 3) > 0 )
        MifCmdWriteData( x - 3  , &mifcarte.texte[0x00] );
     }
   }
   return( res );
}
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
uint8_t MifStandPurge()
{
  uint8_t x ;
  x = MifStandCherche() ;
  //Toutes les Promatic
  if( ( x == 0xFF )||(MifResTypeDeCarte() >= TYPELECTEUR_PROM) ) {return( 0 );}
  return( MifFormatCompteurs( x ) );
}
//-----------------------------------------------------------------------------
uint8_t MifStandModifieCode()
{
  uint8_t x ;
  x = MifStandCherche() ;
  //Toutes les Promatic
  if( ( x == 0xFF )||(MifResTypeDeCarte() >= TYPELECTEUR_PROM) ) {return( 0 );}
  mifcarte.stands[x].codesand = InfoStand.codesand ;
  return( MifCmdIndexWrite() );                         //Enregistrement
}
//-----------------------------------------------------------------------------
uint8_t MifStandModifieType( uint8_t type )
{
  uint8_t x ;
  x = MifStandCherche() ;
  //Toutes les Promatic
  if( ( x == 0xFF )||(MifResTypeDeCarte() >= TYPELECTEUR_PROM) ) {return( 0 );}
  mifcarte.stands[x].type = type ;                  //Modifie le type de carte
  mifcarte.stands[x].codesand = InfoStand.codesand ;//Ajuste le code
  return( MifCmdIndexWrite() );                     //Enregistrement
}
//-----------------------------------------------------------------------------
uint8_t MifStandRetraitNbre( uint16_t Nbre )
{
  uint8_t posCpt1 , x , y , res ;
  uint16_t z , zz ,mmocpt ;
  uint32_t plat ;
  res = 0 ;
  //----
  if( Nbre > 0 ){
     if( (CleTravailType == 0xDD)||(CleTravailType == 0xEE) ){
      //---- Pour Promatic
      if( MifCmdAuthAuto( 0x04 ) ){
        if( TestMoneyUse ){
            // Mode money en decompte
            mmocpt = Promatic_Infos.L6.CashCnt ;  //Backup
            x = Promatic_Infos.L6.coast[InfoStand.NumCompteur]; //Multiplicateur
            z = Nbre * x ;                        //Applique le coef
            if( TestCountUP  ){
                zz = Promatic_Infos.L6.CashCnt + z ;
                if( zz > Promatic_Infos.L6.RipCashLim ) return( 0x00 );
            }else{
                zz = Promatic_Infos.L6.CashCnt - z ;
                if( Promatic_Infos.L6.CashCnt < z ) return( 0x00 );
            }
            Promatic_Infos.L6.CashCnt = zz ;
            // Enregistrement
            if( MifCmdWriteData( 0x06 ,(uint8_t *)&Promatic_Infos.L6 ) ) {
               res = 1;
               mifcarte.compteur[ InfoStand.NumCompteur ] -= Nbre ;
               Pro_AddRemouveGlobal( Nbre , 0x01 );
            }else{
               res = 0;
               Promatic_Infos.L6.CashCnt = mmocpt ;
            }
        }else{
            // Mode plateaux en decompte
            mmocpt = Promatic_Infos.L6.count ;    //Backup
            if( TestCountUP  ){
               z = Promatic_Infos.L6.count + Nbre ;
               //Print(" UP: "); PrintNum16( z ); Pause( 1000 );
               if( z > Promatic_Infos.L6.limit ) return( 0x00 );
            }else{
               z = Promatic_Infos.L6.count - Nbre ;
               //Print(" DOWN: "); PrintNum16( z ); Pause( 1000 );
               if( Promatic_Infos.L6.count < Nbre ) return( 0x00 );   // ok
            }
            //Pause( 1000 );

            Promatic_Infos.L6.count = z ;
            // Enregistrement
            if( MifCmdWriteData( 0x06 ,(uint8_t *)&Promatic_Infos.L6 ) ) {
               res = 1;
               //mifcarte.compteur[ InfoStand.NumCompteur ] -= Nbre ;
               mifcarte.compteur[0] -= Nbre ;
               mifcarte.compteur[1] = mifcarte.compteur[0];
               mifcarte.compteur[2] = mifcarte.compteur[0];
               Pro_AddRemouveGlobal( Nbre , 0x01 );
            }else{
               res = 0;
               Promatic_Infos.L6.count = mmocpt ;
            }
        }
      }
    }else{
      //---- pour mes cartes
      x = MifStandCherche() ;
      if( x < 8 ){
        ((uint16_t *)&plat)[0] = Nbre ;    //Conversion en long  Lo
        ((uint16_t *)&plat)[1] = 0    ;    //Conversion en long  Hi
        //Calcul de la position du bloc mémoire des compteurs sur la carte
        posCpt1 = ( x * 4 ) + 12 ;
        if( InfoStand.NumCompteur < 3 ){
          posCpt1 += InfoStand.NumCompteur ;       //de 0 a 2
          //Si le compteur est vide
          if( mifcarte.compteur[InfoStand.NumCompteur] == 0 ){ return( res ); }
          //Interdit de descendre en dessous de 0
          if( mifcarte.compteur[InfoStand.NumCompteur] < plat ){
             if( InfoStand.caisse > 0 ){         //autorise la caisse a vider
               plat = mifcarte.compteur[InfoStand.NumCompteur] ;
             }else{ return( res ); }
          }
          //On enléve ce qui est possible
          if( MifCmdAuth( CleTravailType , posCpt1 ) == 0x01 ) {
             if( MifCmdNumDecrease( posCpt1 , plat ) == 0x01 ){
               mifcarte.compteur[InfoStand.NumCompteur] -= plat ;
               res = 1;
             }
          }
        }
      }
    }
  }
  return( res );
}
//-----------------------------------------------------------------------------
uint8_t MifStandRetrait()
{
  uint16_t dec;
  ((uint8_t *)&dec)[0] = InfoStand.increment ;//Conversion du uint8_ten int
  ((uint8_t *)&dec)[1] = 0 ;
  return( MifStandRetraitNbre( dec ) );
}
//-----------------------------------------------------------------------------
uint8_t MifStandAjoutNbre( uint16_t Nbre )
{
  uint8_t posCpt1 , x , resA ;
  uint16_t z , zz ,mmocpt ;
  uint32_t NbreL;
  NbreL = 0 ;
  NbreL += Nbre ;
  resA = 0 ;
  //----
  if( (CleTravailType == 0xDD)||(CleTravailType == 0xEE) ){
    //---- Pour Promatic
    if( MifCmdAuthAuto( 0x04 ) ){
      if( TestMoneyUse ){
        mmocpt = Promatic_Infos.L6.CashCnt ;  //Backup
            x = Promatic_Infos.L6.coast[InfoStand.NumCompteur]; //Multiplicateur
            z = Nbre * x ;                        //Applique le coef
        if( TestCountUP  ){
            if( Promatic_Infos.L6.CashCnt < z ) return( 0x00 );
            zz = Promatic_Infos.L6.CashCnt - z ;
        }else{
            zz = Promatic_Infos.L6.CashCnt + z ;
            if( zz > Promatic_Infos.L6.RipCashLim ) return( 0x00 );
        }
        Promatic_Infos.L6.CashCnt = zz ;
        // Enregistrement
        if( MifCmdWriteData( 0x06 ,(uint8_t *)&Promatic_Infos.L6 ) ) {
           resA = 1;
           mifcarte.compteur[ InfoStand.NumCompteur ] += Nbre ;
           Pro_AddRemouveGlobal( Nbre , 0x00 );
        }else{
           resA = 0;
           Promatic_Infos.L6.CashCnt = mmocpt ;
        }
      }else{
        mmocpt = Promatic_Infos.L6.count ;    //Backup
        if( TestCountUP  ){
           if( Promatic_Infos.L6.count < Nbre ) return( 0x00 );
           z = Promatic_Infos.L6.count - Nbre ;
        }else{
           z = Promatic_Infos.L6.count + Nbre ;
           if( z > Promatic_Infos.L6.limit ) return( 0x00 );
        }
        Promatic_Infos.L6.count = z ;
        // Enregistrement
        if( MifCmdWriteData( 0x06 ,(uint8_t *)&Promatic_Infos.L6 ) ) {
           resA = 1;
           //mifcarte.compteur[ InfoStand.NumCompteur ] += Nbre ;
           mifcarte.compteur[0] += Nbre ;
           mifcarte.compteur[1] = mifcarte.compteur[0];
           mifcarte.compteur[2] = mifcarte.compteur[0];
           Pro_AddRemouveGlobal( Nbre , 0x00 );
        }else{
           resA = 0;
           Promatic_Infos.L6.count = mmocpt ;
        }
      }
    }
  }else{
    //---- pour mes cartes
    x = MifStandCherche() ;                    //retourne de 0 à 7  pour 8 stands
    if( x < 8 ){
      //Calcul de la position du bloc mémoire des compteurs sur la carte
      posCpt1 = ( x * 4 ) + 12 ;
      if( InfoStand.NumCompteur < 3 ){
        posCpt1 += InfoStand.NumCompteur ;     //de 0 a 2
        if( MifCmdAuthAuto( posCpt1 ) ) {
          if( MifCmdNumAdd( posCpt1 , NbreL ) ){
              mifcarte.compteur[InfoStand.NumCompteur] += NbreL ;
              resA = 1;
          }
        }
      }
    }
  }
  return( resA );
}
//-----------------------------------------------------------------------------
uint8_t MifStandAjout()
{
  uint16_t inc;
  inc = 0 ;
  inc += InfoStand.increment ;
  return( MifStandAjoutNbre( inc ) );
}
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
uint16_t MifResCompteurActif(){
  return( mifcarte.compteur[ InfoStand.NumCompteur ] );
}
//-----------------------------------------------------------------------------
uint16_t MifResCompteur( uint8_t cpt ){
  if( cpt > 2 ) return( 0 );
  return( mifcarte.compteur[ cpt ] );
}
//-----------------------------------------------------------------------------
uint8_t MifResType()
{
  uint8_t x ;
  x = MifStandCherche() ;
  if( x == 0xFF ){ return( 0xFF ); }
  if( mifcarte.stands[x].type > 0x5F ){
      return( mifcarte.stands[x].type & 0x0F );
  }
  return( mifcarte.stands[x].type );
}
//-----------------------------------------------------------------------------
// if( MifResTypeDeCarte() >= TYPELECTEUR_PROM )  //Toutes les Promatic
uint8_t MifResTypeDeCarte()
{
  uint8_t x , y ;
  x = MifStandCherche();                             //Lit les infos de la carte
  y = mifcarte.stands[x].type & 0xF0 ;               //Extrait le type de carte
  x = TYPELECTEUR_MIFARE ;                           //Par defaut la mienne
  switch( y ){
  case TYPECARTE_PROMATIC : x = TYPELECTEUR_PROM ;   //Anciennement promatic
  case TYPECARTE_PROM_ATI : x = TYPELECTEUR_PROM_X ; //Xtreme promatic
  }
  return( x );
}
//-----------------------------------------------------------------------------
uint8_t MifResTypeDeCarteLue()
{
   if( CleTravailType == 0xDD )return( TYPELECTEUR_PROM );
   if( CleTravailType == 0xEE )return( TYPELECTEUR_PROM_X );
   return( TYPELECTEUR_MIFARE );
}
//-----------------------------------------------------------------------------
uint8_t MifResCode()
{
  uint8_t x ;
  x = MifStandCherche() ;
  if( x == 0xFF ){ return( 0 ); }
  return( mifcarte.stands[x].codesand );
}
//-----------------------------------------------------------------------------
uint8_t MifResNumCtand()
{
  if( (CleTravailType == 0xDD)||(CleTravailType == 0xEE) ){  //Promatic
       return( mifcarte.stands[0x07].numero );
  }
  return( InfoStand.numero );
}
//-----------------------------------------------------------------------------
uint16_t   MifResNumCarte()  { return( LongToIntXor( mifcarte.num ) ); }
uint8_t *  MifResTexte()     { return( &mifcarte.texte[0] ); }
uint8_t    MifGetLastError() { return( mifI2CErr ); }
uint8_t *  MifResBuffer()    { return( &g_cRxBuf[0] ); }
//-----------------------------------------------------------------------------
uint8_t *MifTEST()
{
  uint16_t x;
  uint8_t * cret ;
  cret = &g_cRxBuf[0];
  memset( cret , 0x00 , 16 );   //Nettoie le buffer
  for( x=0 ; x < 5 ; x++ ){
      mifI2CInit();             //Initialise le circuit avant tout
      MifCmdConst( ComVersion , sizeof( ComVersion ) );
      if( !mifI2CErr ){
          ReadBuf_I2C( cret , sizeof( g_cRxBuf ) );
          if( RCVSTA_SL030 == 0x00 ) break;
      }
  }
  mifHALT();
  g_cRxBuf[19] = 0x00;
  L2(); Print("VER: "); PrintHexa( cret , 4 );
  return( cret + 3  );
}

//-----------------------------------------------------------------------------
uint8_t MifTEST_Presence()
{
  uint16_t x;
  uint8_t * cret ;
  cret = &g_cRxBuf[0];
  memset( cret , 0x00 , 16 );   //Nettoie le buffer
  for( x=0 ; x < 5 ; x++ ){
      mifI2CInit();             //Initialise le circuit avant tout
      MifCmdConst( ComVersion , sizeof( ComVersion ) );
      if( !mifI2CErr ){
          ReadBuf_I2C( cret , sizeof( g_cRxBuf ) );
          if( RCVSTA_SL030 == 0x00 ) break;
      }
  }
  mifHALT();
  return( x );   //Retourne < 0x05 si ok
}
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
/************************************************************************
* Overview:  Helper to generate address of result
* Input:     Number of layout              1 up to max
* Output:    ligne and colonne to access
************************************************************************/
static void ScoresRendPosition( uint16_t pos, uint8_t *ligne, uint8_t *colonne)
{
   uint16_t lig , col , x ;
   lig = pos / 0x10 ;    //Ligne a lire => 16 octets par ligne
   col = lig * 0x10 ;
   col = pos - col ;     //Reste de la division
   Lig += 9 ;            //Start position 9 ==> 8 pour BIB number et infos
   if( col == 0 ){
       lig--;
   }else{
       col--;
   }
   *colonne = Lo(col);
   //--- on doit sauter toutes les lignes systeme
   for( x = 9 ; x <= lig ; x++ ){
      if( CheckKeyBlock(x) ) { lig++; }
   }
   //---
   *ligne = Lo(lig);
}
//-----------------------------------------------------------------------
uint8_t ScoresCounterResetAllScores()
{
    uint16_t pos ;
    uint8_t buf[0x10], ligne , colonne , res ;
    memset(&buf[0x00],0x00,sizeof(buf));
    res = 0x01; pos=1u;
    while( pos < MAX_LAYOUTS || res == 0x01 ){
        ScoresRendPosition( pos , &ligne , &colonne );
        if( !MifCmdAuthAuto( ligne ) ){ return(0x00); }
        res = MifCmdWriteData( ligne , &buf[0x00] );
        Pos += 16 ;
    }
    return( res ); // 1 if ok and 0 for error
}
/************************************************************************
* ScoresCounterGetValue
* -----------------------------------------------------------------------
* Overview:
* Input: Number of layout (1 up to maximum admissible by card) find on mail exchanges
* Output: Score stored (0 up to 255)
************************************************************************/
uint8_t ScoresCounterGetValue( uint16_t position  )
{
   uint8_t buf[0x10], score, ligne , colonne;
   if( position > MAX_LAYOUTS || position < 1 ) return(0);
   memset( &buf[0x00] , 0x00 , sizeof(buf) );
   //-- Chaque ligne contiens 16 positions
   ScoresRendPosition( position , &ligne , &colonne );
   if( MifCmdAuthAuto( ligne ) ){
         MifCmdReadTexte( ligne , &buf[0x00] ) ;
         score = buf[colonne];
   }else{
         score = 0;
   }
   return( score );
}
//-----------------------------------------------------------------------------
//---- Write the score for a layout -----
uint8_t ScoresCounterSetValue( uint16_t position , uint8_t val )
{
   uint8_t buf[0x10], score, ligne , colonne , res ;
   if( position > MAX_LAYOUTS || position < 1 ) return(0);
   memset( &buf[0x00] , 0x00 , sizeof(buf) );
   res = 0;
   //-- Chaque ligne contiens 16 positions
   ScoresRendPosition( position , &ligne , &colonne );
   if( MifCmdAuthAuto( ligne ) ){
         MifCmdReadTexte( ligne , &buf[0x00] );
         buf[colonne] = val ;
         res = MifCmdWriteData( ligne , &buf[0x00] );
   }
   return( res ); // 1 if ok and 0 for error
}
//-------------------------------------------------------------------
uint8_t HexaConvertDemiBit( uint8_t b )
{
   unsigned char x[2];
    x[1] = 0 ;
    if( b < 10 ) {
        x[0] =  b + '0' ;
    }else{
        x[0] = (b - 10) + 'A' ;
    }
    return(x);
}
//-------------------------------------------------------------------
void HexaConvert( uint8_t *src , uint8_t *dest , uint8_t len )
{
    while( len > 0 ){
        *dest = HexaConvertDemiBit((*src & 0xF0 ) >> 4);
        dest++; src++;
        *dest = HexaConvertDemiBit( *src & 0x0F );
        dest++; src++;
        len--;
    }
    *dest = 0;
}

/************************************************************************
* ScoresCounterGetAllScores
* -----------------------------------------------------------------------
* Overview:
* Input: structure
* Output: 1 if Ok or zero = error
************************************************************************/
#include "USB_DSC.h"
uint8_t ScoresCounterGetAllScores( str_Scores *AllScores )
{
    uint16_t x , pos , tot , num , tmp;
    uint8_t buf[0x11], buf2[0x11], score, ligne , colonne , res ;
    //-------------------
    for( x=0 ; x < 0x08 ; x++ ){
           ByteToHex( UUID2[x] , &buf2[0]);
           USB_PrintStr( &buf2[0] );
    }
    USB_Print_Char( ';' );
    //-------------------
    num = ScoresCounterGetBibNumber();
    tot  = 0 ;
    res = 1;  pos = 1;
    while( pos < MAX_LAYOUTS ){
        ScoresRendPosition( pos , &ligne , &colonne );
        if( !MifCmdAuthAuto( ligne ) ){ return(0x00); }
        MifCmdReadTexte( ligne , &buf[0x00] );
        for( x=0 ; x < 0x10 ; x++ ){
             tmp = buf[x];
             tot += tmp;
             USB_PrintNum8( buf[x] );
             USB_Print_Char( ';' );
        }
        Pos += 16 ;
    }
    USB_PrintNum16(num);
    USB_Print_Char( ';' );
    USB_PrintNum16(tot);
    USB_Print_Char( ';' );
    USB_Print_Char( '\n' );
    return( res ); // 1 if ok and 0 for error
}
//-----------------------------------------------------------------------
/************************************************************************
* ScoresCounterGetBibNumber
* -----------------------------------------------------------------------
* Overview:  Only 2 octets used for now on index 0x08
* Input:
* Output: Bib Number or 0
************************************************************************/
uint16_t ScoresCounterGetBibNumber()
{
   uint16_t bib;
   uint8_t buf[0x10];
   bib = 0;
   if( MifCmdAuthAuto( 0x08 ) ){
         MifCmdReadTexte( 0x08 , &buf[0x00] );
         Lo(bib) = buf[0x00];
         Hi(bib) = buf[0x01];
   }else{
        CLS();
        Print("ERR AUTH read !");
        PrintFlush();
        Pause( 3000 );
   }
   return( bib );
}
//-----------------------------------------------------------------------------
uint8_t ScoresCounterSetBibNumber( uint16_t bib  )
{
   uint8_t res ;
   uint8_t buf[0x10];
   res = 0;
   if( MifCmdAuthAuto( 0x08 ) ){
         MifCmdReadTexte( 0x08 , &buf[0x00] );
         buf[0x00] = Lo(bib) ;
         buf[0x01] = Hi(bib) ;
         res = MifCmdWriteData( 0x08 , &buf[0x00] );
   }else{
        CLS();
        Print("ERR AUTH WRITE !");
        PrintFlush();
        Pause( 3000 );
   }
   ScoresCounterResetAllScores();
   return( res ); // 1 if ok and 0 for error
}
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------

