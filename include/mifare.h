/*
 * mifare.h
 *
 *  Created on: 22 Mar 2017
 *      Author: ian
 */

#ifndef MIFARE_H_
#define MIFARE_H_

#include <stdint.h>
//-----------------------------------------------------------------------------
typedef struct{
   uint16_t numero ;      //N° du stand      0=interdit
   uint8_t codesand ;     //Code de sécurité modifiable
   uint8_t caisse ;       //0=jetonniere - 1=caisse - 2=formatage
   uint8_t increment ;    //Nombre a mouvementer
   uint8_t NumCompteur ;  //Compteur a utiliser: de 0 a 2 = 3
   uint8_t TypeLecteur ;  //SLE  MIFARE  GOLD  RIEN
   uint8_t TypeRadio  ;   //Type de transmission radio AM ou FM +++
   //uint8_t PasUtilise;  //Pour multiple de 2
} str_InfoStand ;
//-----------------------------------------------------------------------------
//----- Possible Card Types ----
// iHm does not correspond to SL reader types - would be easier if it did?
#define TYPELECTEUR_NULL   0X00
#define TYPELECTEUR_SLE    0X01
#define TYPELECTEUR_GOLD   0X02
#define TYPELECTEUR_MIFARE 0X03
#define TYPELECTEUR_PROM   0X04
#define TYPELECTEUR_PROM_X 0X05
#define TYPELECTEUR_MAX    0X05     	// For the Choice menu
//-----------------------------------------------------------------------------
//----- Card management constants  ----
#define TYPECARTE_CLIENT   0x00
#define TYPECARTE_GROUPE   0x02
#define TYPECARTE_PATRON   0x04
#define TYPECARTE_TRAINING 0x05
#define TYPECARTE_SCORES   0x06
#define TYPECARTE_JPB      0x07
#define TYPECARTE_YESCARD  0x08
#define TYPECARTE_PARCOUR  0x09          // Pas utilisé ici (DATEC SEUL)
#define TYPECARTE_PURGE    0x0A
#define TYPECARTE_STAF     0X0A          // Ouvre la caisse UNIQUEMENT
#define TYPECARTE_MASTER   0X0B          // Met le N° de stand et code
#define TYPECARTE_MASTER_X 0X0C          // Met le N° de stand et code + choix
#define TYPECARTE_SERIAL   0X0E          // Usine uniquement pour Num. Série
#define TYPECARTE_FORMATAG 0x55          //
#define TYPECARTE_PROMATIC 0x60          // Older Promatic cards
#define TYPECARTE_PROM_ATI 0x70          // New ( Extreme ) Promatic cards
//-----------------------------------------------------------------------------
//---- Values returned by CARTEretLASTERROR();
// lo returns a value according to the reader: see doc. reader
#define ERROK               0X00
#define ERRTYPECARTE        0X10
#define ERRNUMSTAND         0X20
#define ERRCODE             0X30
#define ERRNEUVE            0X40
#define ERRAUTHENTIFICATION 0X50
#define ERRLECTURE          0X60
#define ERRECRITURE         0X70
#define ERRpromaticCARD     0X80
#define ERRPROTECTIONCLES   0X90
#define ERRDEBORDEMENT      0XA0
#define ERRMORTE            0XB0
#define ERRABSENTE          0XFF

//-----------------------------------------------------------------------------
//#include "cartes.h"
//extern uint8_t MifResTypeDeCarte();//Retourne la valeur du type en eeprom

//--- Gestion de l'alimentation du circuit de lecture---
void mifI2CInit();       //Initialise les ports materiels et active le lecteur
void mifWAKEUP();
uint8_t MifCartePresente();
void mifHALT();          //Arréte l'antenne du lecteur

//--- actions de gestion standard ---
void MifInfosStandCharge( str_InfoStand * sta ); //Envoie la structure de base
unsigned int   MifStandGetATR();         //Lit et Initialise les structures
uint8_t MifStandRetrait();        //Enléve une série si possible (AUTO.)
uint8_t MifStandRetraitNbre( unsigned int Nbre );
uint8_t MifStandAjout();          //Ajoute une série (AUTO.)
uint8_t MifStandAjoutNbre( unsigned int Nbre );

//--- Reserved at checkout ---
uint8_t MifStandPurge();          //Mise a blanc complet des compteurs
uint8_t MifStandModifieCode();    //Change le code de securité
uint8_t MifStandModifieType( uint8_t type );

//--- Reserved for super boss ---
uint8_t MifStandFormatageBlanc();
uint8_t MifStandFormatageComplet();

//--- Lecture des informations lues ---
uint8_t  MifResType();             //Retourne le type de carte
uint8_t  MifResCode();
uint8_t  MifResNumCtand() ;
uint16_t MifResCompteurActif();
uint16_t MifResCompteur( uint8_t cpt );   //de 0 a 2
uint8_t *MifResTexte();            //Le texte mémorisé
uint8_t  MifGetLastError();
uint16_t MifResNumCarte();
uint8_t  MifResTypeDeCarteLue();

//--- Test Functions ---
uint8_t  * MifResBuffer();
uint8_t  * MifTEST();
uint8_t  MifTEST_Presence();

//--- Fonction de lecture par bloc ----
//indiquer le N° de bloc pas la ligne dans le bloc
uint8_t MifReadBlocComplet( uint8_t LigneBlocDepart );
//On récupére la chaine dans ==>  MifResTexte()

//--- Fonction de copie par bloc ----
//indiquer le N° de bloc pas la ligne dans le bloc
//Fournir une chaine de 3 * 16 octets
uint8_t MifWriteBlocComplet( uint8_t LigneBlocDepart , uint8_t * str);

//------------------------------------------------------------
#define MAX_LAYOUTS  323
typedef struct{
   uint8_t  uuid[0x11] ;             	//8 octets = 16 en hexa ASCII
   uint16_t numero ;                 	//BibNumber     0=interdit = New card
   uint16_t total ;                  	//Total of all scores
   uint8_t  score[MAX_LAYOUTS] ; 		//Result for each layout
} str_Scores ;

uint16_t ScoresCounterGetBibNumber();

uint8_t  ScoresCounterSetBibNumber( uint16_t bib );
uint8_t  ScoresCounterGetValue( uint16_t position );

uint8_t  ScoresCounterSetValue( uint16_t position , uint8_t val );
uint8_t  ScoresCounterGetAllScores( str_Scores *AllScores );
uint8_t  ScoresCounterResetAllScores();

#endif /* MIFARE_H_ */
