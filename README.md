# CBT432
Converted to GitHub via [cbt2git](https://github.com/wizardofzos/cbt2git)

This is still a work in progress. 
Due to amazing work by Alison Zhang and Jake Choi repos are no longer deleted.

```
//***FILE 432 is from Thierry Falissard of Paris, France, and       *   FILE 432
//*           it contains a selection from things he has written    *   FILE 432
//*           over many years.  We hope you enjoy it.               *   FILE 432
//*                                                                 *   FILE 432
//*       THE AUTHOR'S NOTE                                         *   FILE 432
//*       =================                                         *   FILE 432
//*                                                                 *   FILE 432
//*       I HAVE TRIED NOT TO DROWN YOU WITH OBSOLETE, OLD OR       *   FILE 432
//*       USELESS MATERIAL.  SO HERE YOU HAVE A (HOPEFULLY)         *   FILE 432
//*       CLEVER SELECTION OF ALL THE STUFF I HAVE WRITTEN.         *   FILE 432
//*                                                                 *   FILE 432
//*       THESE ARE PC-DOS OR WINDOWS UTILITIES : MGDOS MGWIN       *   FILE 432
//*       PTKT.                                                     *   FILE 432
//*                                                                 *   FILE 432
//*       I WOULD BE INTERESTED TO HEAR OF SIGNIFICANT              *   FILE 432
//*       ENHANCEMENTS OR INSTANCES WHERE THESE PROGRAMS HAVE       *   FILE 432
//*       BEEN OF MAJOR BENEFIT (OR OTHERWISE), CONTACT :           *   FILE 432
//*                                                                 *   FILE 432
//*        Thierry Falissard                                        *   FILE 432
//*        tfalissard@compuserve.com                                *   FILE 432
//*        http://os390-mvs.hypermart.net                           *   FILE 432
//*        or                                                       *   FILE 432
//*        http://ourworld.compuserve.com/homepages/tfalissard      *   FILE 432
//*                                                                 *   FILE 432
//*       STANDARD DISCLAIMER                                       *   FILE 432
//*       ===================                                       *   FILE 432
//*                                                                 *   FILE 432
//*       NEITHER THIERRY FALISSARD NOR ANY COMPANY ASSOCIATED      *   FILE 432
//*       WITH HIM EXPRESS OR IMPLY ANY WARRANTY AS TO THE          *   FILE 432
//*       FITNESS OF THESE COMPUTER PROGRAMS FOR ANY FUNCTION.      *   FILE 432
//*       THE USE OF THESE PROGRAMS OR THE RESULTS THEREOF IS       *   FILE 432
//*       ENTIRELY AT THE RISK OF THE USER.                         *   FILE 432
//*                                                                 *   FILE 432
//*       THESE PROGRAMS ARE DONATED TO THE PUBLIC DOMAIN AND       *   FILE 432
//*       MAY BE FREELY COPIED.  THEY MAY BE FREELY DISTRIBUTED     *   FILE 432
//*       TO ANY OTHER PARTY ON CONDITION THAT NO INDUCEMENT        *   FILE 432
//*       BEYOND REASONABLE HANDLING COSTS BE OFFERED OR            *   FILE 432
//*       ACCEPTED FOR SUCH DISTRIBUTION.                           *   FILE 432
//*                                                                 *   FILE 432
//*       SOME PROGRAMS WERE PUBLISHED IN XEPHON'S MVS UPDATE       *   FILE 432
//*       OR RACF UPDATE.  SINCE XEPHON OFFERS THEM FOR FREE ON     *   FILE 432
//*       THEIR WEBSITE (WWW.XEPHON.COM), I CONSIDER THEM AS        *   FILE 432
//*       PUBLIC.                                                   *   FILE 432
//*                                                                 *   FILE 432
//*       Note:  Xephon programs are now supported here, at         *   FILE 432
//*              www.cbttape.org, ever since Xephon, transferred    *   FILE 432
//*              to Thomas Publishing, stopped publishing their     *   FILE 432
//*              journals.  So Thierry's stuff certainly belongs    *   FILE 432
//*              here.  (S.Golob - 12/2009)                         *   FILE 432
//*                                                                 *   FILE 432
//*              The CBT Tape website is now the support location   *   FILE 432
//*              for almost all Xephon materials.                   *   FILE 432
//*                                                                 *   FILE 432
//*       THESE PROGRAMS MAY BE MODIFIED IN ANY WAY THE USER        *   FILE 432
//*       THINKS FIT BECAUSE USE OF THESE PROGRAMS IS ENTIRELY      *   FILE 432
//*       AT THE RISK OF THE USER ANYWAY.                           *   FILE 432
//*                                                                 *   FILE 432
//*       LANGUAGE PROBLEMS                                         *   FILE 432
//*       =================                                         *   FILE 432
//*                                                                 *   FILE 432
//*      THE PROGRAMS ARE DELIVERED WITH COMMENTS IN EITHER ONE     *   FILE 432
//*      OF 3 LANGUAGES :  ENGLISH, FRENCH AND FRENGLISH (BAD       *   FILE 432
//*      ENGLISH SPOKEN BY A FRENCHIE).  SO... "EXCUSE MY           *   FILE 432
//*      FRENCH"...                                                 *   FILE 432
//*                                                                 *   FILE 432
//*     December 2000 Update                                        *   FILE 432
//*                                                                 *   FILE 432
//*     New members :                                               *   FILE 432
//*                                                                 *   FILE 432
//*     ANALJCL  : JCL TO ANALYZE JCL LIBRARIES                     *   FILE 432
//*     ANALJCLR : REXX TO ANALYZE JCL LIBRARIES                    *   FILE 432
//*     LISTVT   : REXX exec to analyze a DCOLLECT output           *   FILE 432
//*     LISTVTOC : JCL to list VTOCs from a DCOLLECT output         *   FILE 432
//*     MINIFRAN : rename of MINISYST                               *   FILE 432
//*     PADS     : REXX exec to initialize RACF PADS mode           *   FILE 432
//*     RACFCHCK : assembler subroutine to RACHECK a resource       *   FILE 432
//*     RACFMOVE : JCL to move the RACF database from a disk to     *   FILE 432
//*                another.                                         *   FILE 432
//*                                                                 *   FILE 432
//*     Updated members :                                           *   FILE 432
//*                                                                 *   FILE 432
//*     ALLSTOP    Added 3 new members from Gilbert Saint-flour     *   FILE 432
//*                to help run this utility better.                 *   FILE 432
//*     ASCBS    - REXX TO LIST ALL ADDRESS-SPACES (FRENCH          *   FILE 432
//*     MINISYST : new JCL to create a mini-system. Comments in     *   FILE 432
//*                English.                                         *   FILE 432
//*     SUSEC                                                       *   FILE 432
//*                                                                 *   FILE 432
//*                                                                 *   FILE 432
//*       CONTENTS                                                  *   FILE 432
//*       ========                                                  *   FILE 432
//*                                                                 *   FILE 432
//*     ALLSTOP  - A TOOL TO STOP ALL RUNNING ADDRESS-SPACES        *   FILE 432
//*                Added 3 new members from Gilbert Saint-flour     *   FILE 432
//*                to help run this utility better.                 *   FILE 432
//*     ASCBS    - REXX TO LIST ALL ADDRESS-SPACES (FRENCH          *   FILE 432
//*                COMMENTS)                                        *   FILE 432
//*     CONSOLE  - BRINGING THE MVS MASTER CONSOLE UNDER ISPF       *   FILE 432
//*                (USES SVC 235 ; "LAST COMMAND" INFORMATION       *   FILE 432
//*                PROBABLY FALSE ; DON'T CALL THE LOAD             *   FILE 432
//*                "CONSOLE"                                        *   FILE 432
//*     CONSOLEP - ISPF PANEL FOR "CONSOLE" PROGRAM                 *   FILE 432
//*     CONVERT  - MACRO - CONVERTS FROM PACKED/DECIMAL/BINARY      *   FILE 432
//*                TO PACKED/DECIMAL/BINARY                         *   FILE 432
//*     CONVRTP  - REXX TO CONVERT CATALOG ENTRIES FROM 3480 TO     *   FILE 432
//*                3490  - FRENCH COMMENTS                          *   FILE 432
//*     ERASETP  - PROGRAM TO ERASE TAPE DATA (FOR SECURITY OR      *   FILE 432
//*                TO EVAL. TAPE CAPACITY)                          *   FILE 432
//*     EXP      - REXX TO COMPUTE EXPONENTIAL FUNCTION             *   FILE 432
//*                (FRENGLISH COMMENTS)                             *   FILE 432
//*     EXTEND   - MACRO - EXTENDS A BINARY ZONE TO DECIMAL         *   FILE 432
//*     EXEMPLES - EXAMPLES OF ASSEMBLER CODING (EDUCATIONAL        *   FILE 432
//*                PURPOSE) - FRENCH COMMENTS                       *   FILE 432
//*     ICHPWX01 - RACF NEW PASSWORD EXIT - FRENCH COMMENTS         *   FILE 432
//*     IGGPRE00 - DADSM PRE-PROCESSING EXIT, CONTROLS ACCESS       *   FILE 432
//*                TO VOLUME VIA A DEDICATED "ALLOC" RACF CLASS     *   FILE 432
//*                - FRENCH COMMENTS                                *   FILE 432
//*     INTERCPT - MPF EXIT - USED TO REPLY TO MESSAGES, TO         *   FILE 432
//*                ISSUE MVS COMMANDS OR TO SEND MESSAGES  -        *   FILE 432
//*                FRENCH COMMENTS                                  *   FILE 432
//*     IRA200E  - THIS MEMORY ZAP ALLOWS YOU TO CHANGE THE 70%     *   FILE 432
//*                AND 85 % THRESHOLDS                              *   FILE 432
//*     JESLESS  - JESLESS IN A NUTSHELL (HOW TO HAVE A LOGON       *   FILE 432
//*                TSO WITHOUT JES).                                *   FILE 432
//*     LISTSMS  - LISTING THE SMS CONFIGURATION                    *   FILE 432
//*     MGDOS    - SHAREWARE "MEGACRYPT/DOS" - COPY IT TO PC        *   FILE 432
//*                AND RENAME IT MGDOS.ZIP                          *   FILE 432
//*     MGWIN    - SHAREWARE "MEGACRYPT/WINDOWS" - COPY IT TO       *   FILE 432
//*                PC AND RENAME IT MGWIN.ZIP                       *   FILE 432
//*         NOTE : MGDOS AND MGWIN ARE FREE PARTS OF A LICENSED     *   FILE 432
//*         PRODUCT : MEGACRYPT/MVS                                 *   FILE 432
//*     MINISYST - THE JCL I USE FOR CREATING AN MVS MINI           *   FILE 432
//*                SYSTEM (OS/390 V2R5)                             *   FILE 432
//*     MVSCMD   - PROGRAM TO ISSUE ANY MVS OR JES2 IN BATCH -      *   FILE 432
//*                A CLASSICAL - FRENCH                             *   FILE 432
//*     PREMIER  - PRIME NUMBER TESTING (EDUCATIONAL PURPOSE) -     *   FILE 432
//*                FRENCH COMMENTS                                  *   FILE 432
//*     PRINTHX  - MACRO FOR CONVERSION TO HEX - FRENCH COMMENTS    *   FILE 432
//*     PROLOG   - MACRO TO ENTER THE PROGRAM - NOT CLEVER, BUT     *   FILE 432
//*                UNAVOIDABLE - FRENCH                             *   FILE 432
//*     PTKT     - SHAREWARE "PTKTGEN" - COPY IT TO PC AND          *   FILE 432
//*                RENAME IT PTKT.ZIP (IT IS A RACF PASSTICKET      *   FILE 432
//*                GENERATOR FOR PC/DOS)                            *   FILE 432
//*     SHOWLPAR - DISPLAYS THE CURRENT PR/SM CONFIGURATION         *   FILE 432
//*                (SEE "A BIT OF HISTORY")                         *   FILE 432
//*     SHOWMVS  - JCL : MY WAY TO RUN SHOWMVS IN BATCH -           *   FILE 432
//*                SHOWMVS R623D IN OBJ FORMAT                      *   FILE 432
//*     SMFJOBS  - LIST ALL JOBS (BASED ON SMF TYPE 30 RECORDS)     *   FILE 432
//*                - FRENCH COMMENTS                                *   FILE 432
//*     SRMSHOW  - DISPLAYS CURRENT AND THRESHOLD VALUES OF         *   FILE 432
//*                MAJOR SRM PARAMETERS  MVS/XA                     *   FILE 432
//*     SUSEC    - LISTING PROCESSORS IN THE COMPLEX AND THE        *   FILE 432
//*                MIPS (MSU) AVAILABLE - REXX                      *   FILE 432
//*     SVC235   - YES, A MAGIC SVC | BUT WITH SOME BASIC           *   FILE 432
//*                CONTROLS...                                      *   FILE 432
//*     TPUTXMAS - FOR THE FUN - XMAS TREE DISPLAY ON TSO FOR       *   FILE 432
//*                THE YEAR'S END...                                *   FILE 432
//*     VTOCR1   - PANEL USED BY VTOCREAD (SEE VTOCZAP)             *   FILE 432
//*     VTOCZAP  - JCL TO INSTALL "VTOCREAD". ENABLES YOU TO        *   FILE 432
//*                ZAP THE VTOC THRU ISPF (NOT DIRECTLY, AN         *   FILE 432
//*                AMASPZAP JCL IS GENERATED). SOURCE OF            *   FILE 432
//*                VTOCREAD LOST                                    *   FILE 432
//*     WEAKPASS - DISPLAYING RACF USERIDS WITH WEAK D.E.S.         *   FILE 432
//*                PASSWORD (XEPHON)                                *   FILE 432
//*     WTOPUT   - MACRO - ISSUES A WTO WITH MIXED LITTERALS        *   FILE 432
//*                AND DATA ZONES                                   *   FILE 432
//*     XTOD     - MACRO - CONVERTS HUNDREDTHS OF SECOND            *   FILE 432
//*                INTO 'HH:MM'                                     *   FILE 432
//*                                                                 *   FILE 432
```
