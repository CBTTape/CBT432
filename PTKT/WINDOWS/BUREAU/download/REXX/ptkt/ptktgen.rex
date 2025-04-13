/*               REXX                                                     */
/*  The RACF PassTicket generator algorithm                               */
/*  Doc reference :                                                       */
/*  OS/390 Security Server (RACF) - Macros and Interfaces                 */
/*  Document Number SC28-1914-05                                          */
/*                                                                        */
/*  External dependencies :                                               */
/*  - MEGACRYPT/DOS must be available (DOS program CIPHR.EXE)             */
/*  - a REXX interpreter must be installed on the PC to execute PTKTGEN   */


/* variables */

   FILE0 = 'C:\WINDOWS\TEMP\PTKT.TXT'  /* file receiving the gened passticket */
   FILE1 = 'C:\WINDOWS\TEMP\PTKTTEMP.TMP'   /* temporary file for encryption */
   FILE2 = 'C:\WINDOWS\TEMP\PTKTTEMP.MCR'   /* temporary file for encryption */
   megacrypt = 'CIPHR.EXE'    /* path for megacrypt DOS pgm */
   trace = 'n'               /* 'Y' if trace required                      */
   itrace = 0                /* trace entries index                        */
   gmt = 0                   /* GMT shift (may be overriden by userid.INI) */

                             /* Path where userid.INI is stored            */
   path_for_keys = 'a:\'     /* userid.INI is on disquette : 'a:\'         */
   path_for_keys = '.\'      /* userid.INI is in the current Path          */  

   if 1 = 1 then do     /* general info on PTKT RACF implementation */

      say '** Welcome to PTKTGEN, the passticket generator for Windows **'
      say '      Copyright (C) Thierry Falissard, 1999'
      say
      say 'Passticket support on MVS is easy to set up :'
      say
      say '  - activate the passticket class :'
      say '     SETROPTS CLASSACT(PTKTDATA) ; SETROPTS RACLIST(PTKTDATA)'
      say
      say '  - define a profile for the userid + application :'
      say '     RDEFINE PTKTDATA appl.group.userid -'
      say '        SSIGNON(KEYMASKED(0123456789abcdef))'
      say '  where appl is to be replaced by the application name (CICS, TSO+SMFID, etc.)'
      say '        group and userid are the RACF group & userid.'
      say '        and 0123456789abcdef should be replaced by a valid 16-digit secret key'
      say
      say '  - refresh the class : SETR REFRESH RACLIST(PTKTDATA)'
      say
      say 'On the PC, create a file userid.INI where userid must be'
      say 'replaced by your RACF userid. In this .INI file, enter :'
      say ' sskey_CICS = ''0123456789abcdef''x '
      say 'to specify the secret key for this userid + appl (CICS here for example).'
      say
      say 'Press ENTER to go on or END to terminate'
      pull answer
      if translate(answer) = 'END' then exit
      end


   IF STREAM(megacrypt, "C", "QUERY EXISTS") = "" THEN do
      say 'Error, file' megacrypt ' (DOS encryption pgm) not found'
      exit
      end

/* Getting RACF userid                 */

   userid = ''
   do while userid = ''
   say 'Enter your RACF userid (or END) :'
   pull userid
   userid = translate(userid)   /* uppercase */
   if userid = 'END' then exit

   FILEINI = path_for_keys || ,
             userid||'.INI'    /* session key parameters for userid */

   IF STREAM(fileini, "C", "QUERY EXISTS") = "" THEN do
      say 'Error, file' fileini ' (containing values for session keys) not found'
      userid = ''
      end

   end

   say 'RACF userid is' userid


/* Reading parameters from userid.INI             */



   allappl = ' anomaly, file' fileini 'variable allappl= not updated' ,
   'with all application names'

   CALL STREAM FILEINI, "C", "OPEN READ"    /* OPEN INPUT-FILE */

   do while lines(fileini) > 0
   line=linein(fileini)     /* read next line          */
   interpret(line)
   end

   CALL STREAM FILEINI, "C", "CLOSE"     /* CLOSE INPUT FILE */

/* Displaying GMT shift */

   if gmt > 0 then gmtc = 'PLUS'
              else gmtc = 'MINUS'
   say
   say '** IMPORTANT **         ' 
   say 'Local time on the mainframe is supposed to be GMT' gmtc abs(gmt) 'hour(s)'
   say 'If the passticket is refused by RACF, then perhaps local times on MVS'
   say ' and on PC differ too much. Time on the PC is' time()
   say

/* Asking for the application */

   verif_appl = 'SSKEY'

    do while left(verif_appl,5) = 'SSKEY'
    say 'Recognized applications are :' allappl

      applic = ''
      do while applic = ''
      say 'Enter the name of the application you are to access (or END) :'
      pull applic
      if applic = 'END' then exit
      end

    interpret ('verif_appl = sskey_'||applic)
    if left(verif_appl,5) = 'SSKEY' then say applic 'not recognized'
    end


/* The RACF secured signon application key :
   - Must match the key value used when defining the application
     to the PTKTDATA class to RACF
   - Contains only the characters 0 through 9 and A through F            */

    sskey = verif_appl


/* The RACF user ID :
   - Identifies the user ID on the system on which the target application runs
   - Is represented in EBCDIC
   - Is left-justified and padded with blanks on the right to a length of 8 bytes
                                                                          */

    userid = substr(userid,1,8)

/* The application name as defined for a particular application. You can use
   it to associate a secured signon key with a particular host application.*/



    applic = substr(applic,1,8)



   IF STREAM(file0, "C", "QUERY EXISTS") <> "" THEN ,
     address cmd "DEL " file0      /* delete file */

/*  Step 0. ASCII to EBCDIC translation for character fields              */

    /* conversion tables */

E1 = '5c4b40617c7a4fc1c2c3c4c5c6c7c8c9d1d2d3d4d5d6d7d8d9' /*EBCDIC*/
A1 = '2a2e202f613a214142434445464748494a4b4c4d4e4f505152' /* ASCII*/
E2 = 'e2e3e4e5e6e7e8e9818283848586878889919293949596979899' /*EBCDIC*/
A2 = '535455565758595a6162636465666768696a6b6c6d6e6f707172' /*ASCII*/
E3 = 'a2a3a4a5a6a7a8a9c0f0f1f2f3f4f5f6f7f8f9605b7b'     /* EBCDIC */
A3 = '737475767778797a65303132333435363738392d249c'     /*  ASCII */
E4 = '4d5d4c6e6b5e6c6f7d7e4e7f'                         /* EBCDIC */
A4 = '28293c3e2c3b253f273d2b22'                         /*  ASCII */
table_ascii  = X2C(A1||A2||A3||A4)
table_ebcdic = X2C(E1||E2||E3||E4)

userid_stripped = TRANSLATE(strip(userid),table_ebcdic,table_ascii)
if trace = 'Y' then do	
      msg = 'Userid stripped' userid c2x(userid_stripped) ,
      'length=' length(userid_stripped)
      call trc(msg)
      end

userid = TRANSLATE(userid,table_ebcdic,table_ascii)
if trace = 'Y' then do	
      msg = 'Userid ' c2x(userid) ,
      'length=' length(userid)
      call trc(msg)
      end

applic = TRANSLATE(applic,table_ebcdic,table_ascii)
if trace = 'Y' then do	
      msg = 'Applic ' c2x(applic) ,
      'length=' length(applic)
      call trc(msg)
      end

/*  Step 1.  The RACF user ID is encrypted using the RACF secured signon   */
/*  application key as the encryption key to produce Result-1.             */

    call trc('step1 : userid encrypted using sskey')
    zone = userid    /* zone to be encrypted */
    call cipher
    result1 = zone   /* zone is encrypted */

    call trc('step1 done, result1=' c2x(result1))

/*  Step 2.  Result-1 from the first encryption is XORed with the application
    name. The result (Result-2A) is encrypted using the application key value
    as the encryption key to produce Result-2.                              */

    call trc('step2 : result1 XORed with applic, then encrypted using sskey')
    result2 = bitxor(result1,applic)

    zone = result2    /* zone to be encrypted */
    call cipher
    result2 = zone   /* zone is encrypted */

    call trc('step2 done, result2=' c2x(result2) )

/*  Step 3.  The left 4 bytes from Result-2 of the second encryption are
    selected as input to the next step. The rest are discarded.             */

    call trc('step3 : left 4 bytes from Result-2 selcted')
    result3 = left(result2,4)
    call trc('step3 done, result3=' c2x(result3)  )

/*  Step 4.  The resulting 4 bytes (Result-3) are XORed with the time and date
    information. The time and date is in the form of a 4-byte field that
    contains the number of seconds that have elapsed since January 1, 1970
    at 0000 GMT in the form of a binary integer.                            */

    /* number of days since 1-1-1970                                     */
    datesec = DATE('B') - DATE('B','01 Jan 1970')

    datesec = datesec*3600*24 +    /* converted into seconds             */ ,
              time('S')  -   /* number of seconds since midnight         */ ,
              gmt*3600       /* GMT shift on the mainframe               */

    msg = 'step4 : datesec=' datesec 'seconds since 01_01_1970 GMT'
    call trc(msg)

    dats    = d2c(datesec,4) /*              internal hexadecimal format */

    call trc('step4 : datesec=' c2x(dats) 'hex' )

    result4 = bitxor(result3,dats)
    call trc('step4 : result3 XORed with datesec')
    call trc('step4 done, result4=' c2x(result4))

/*  Step 5.  The result (Result-4) is passed to the time-coder routine.     */

  /* result5 = time_coder(result4,userid_stripped,sskey,trace) */
    resultA = result4
    call time_coder
    result5 = R

    call trc('step5 done, result5=' c2x(result5) )

/*  Step 6.  The result (Result-5) of the time-coder routine is translated,
    using a translation table, to an 8-character string called the PassTicket.
    It is used in the user's host application signon request instead
    of the user's regular RACF password.                                    */

    /* passtkt = translat(result5,trace) */
    zone = result5
    call translat
    passtkt = pt

    say
    say 'PASSTICKET generated=' passtkt ', copied in' file0

/* Copying the passticket in a .txt file */

  CALL STREAM FILE0, "C", "OPEN WRITE"  /* OPEN OUTPUT-FILE */
  CALL CHAROUT FILE0, passtkt
  CALL STREAM FILE0, "C", "CLOSE"    /* CLOSE OUTPUT FILE */

/* Delete temporary files                       */
   address cmd "DEL " file1      /* delete file */
   address cmd "DEL " file2      /* delete file */

/* Displaying the trace if applicable */
    call showtrc
    EXIT

/*------------------------------------------------------------------------*/
/* REXX - DES encryption subroutine (Megacrypt/DOS)                       */
/* Uses zone, sskey, trace                                                */
/*------------------------------------------------------------------------*/

cipher:

/*  arg zone , key, trace   */



    call trc('Cipher - Encryption key :' c2x(sskey)  )
    call trc('Cipher - Before enciphering :' c2x(zone))

   IF STREAM(file1, "C", "QUERY EXISTS") <> "" THEN ,
     address cmd "DEL " file1      /* delete file */

  CALL STREAM FILE1, "C", "OPEN WRITE"  /* OPEN OUTPUT-FILE */
  CALL CHAROUT FILE1, zone
  CALL STREAM FILE1, "C", "CLOSE"    /* CLOSE OUTPUT FILE */

  command = FILE1 FILE2 "-k"||c2x(sskey) "-o "    /* prepare DOS command   */
  msg ='Cipher - DOS call to Megacrypt :' megacrypt command
  call trc(msg)
  ADDRESS CMD megacrypt command                   /* call Megacrypt */

  CALL STREAM FILE2, "C", "OPEN READ"    /* OPEN INPUT-FILE */
  zone = CHARIN(FILE2, , 8)
  CALL STREAM FILE2, "C", "CLOSE"     /* CLOSE INPUT FILE */

    call trc('Cipher - After enciphering :' c2x(zone) )
  return zone
  exit

/*------------------------------------------------------------------------*/
/*  The Time-Coder Algorithm                                              */
/*  Uses resultA, userid, sskey, trace  (userid must be stripped)         */
/*------------------------------------------------------------------------*/

/*  How the Time-Coder Algorithm Works

    The RACF PassTicket time-coder algorithm uses the result of Step 4
    of the generator algorithm. It creates the time-coder information
    and passes it back to step 6 of that algorithm.                       */

time_coder:


    call trc('      ----------- Time Coder algorithm')
/* Step A  Separate the 4-byte time-coder input (Result-4) into
    two portions, L2B (the left side), and R2B (the right side)
    to produce Result-A.                                                  */

    call trc('      stepA done, resultA=' c2x(resultA) )

    l2b = left(resultA,2)
    r2b = right(resultA,2)
    call trc('      stepA done, l2b=' c2x(l2b) 'r2b=' c2x(r2b))

    /* Evaluating PAD zones for step B                  */
    PAD = left(userid_stripped||'555555555555555555555555'x,12)
    PAD1 = left(PAD,6)
    PAD2 = right(PAD,6)

    call trc('      PAD1=' c2x(pad1) 'PAD2=' c2x(pad2) )

    DO round = 1 to 6               /* loop */
    call trc('------Beginning of round' round )

/* Step B  Concatenate R2B (the right 2 bytes from Result-A) with 6 bytes
    of padding bits to form Result-B. In the resulting 8-byte string,
    the 2 bytes of R2B occupy the leftmost 2 byte positions.

    The padding bits consist of two separate 6 byte strings: PAD1 and PAD2.
    PAD1 is the left half and PAD2 is the right half of a 12 byte string
    consisting of the user ID (from Step 1) left justified and padded to
    the right with hexadecimal '55's. For example, if the user ID is "TOM,"
    PAD1 is 'E3D6D4555555' and PAD2 is '555555555555'. If the user ID is
    "IBMUSER," PAD1 is 'C9C2D4E4D2C5' and PAD2 is 'D95555555555'.
    PAD1 is used for time coder loop rounds 1, 3, and 5.
    PAD2 is used for time coder loop rounds 2, 4, and 6.                  */

    if round = 1 | round = 3 | round = 5 then resultB = r2b||PAD1
    if round = 2 | round = 4 | round = 6 then resultB = r2b||PAD2
    call trc('      stepB : concatenating r2b and PAD1/2')
    call trc('      stepB done, resultB=' c2x(resultB) )

/* Step C  Result-B is encrypted using the RACF secured signon application
    key as the encryption key to produce Result-C.                        */

    zone = resultB    /* zone to be encrypted */
    call cipher
    resultC = zone   /* zone is encrypted */

    call trc('      stepC : encrypting resultB using sskey')
    call trc('      stepC done, resultC=' c2x(resultC) )

/* Step D  The left 2 bytes from the Result-C are isolated and
    the rest of the value is discarded, producing Result-D.               */

    resultD = left(resultC,2)
    call trc('      stepD : left 2 bytes from Result-C are isolated')
    call trc('      stepD done, resultD=' c2x(resultD) )

/* Step E  Result-D is XORed with L2B (from Result-A) to produce Result-E.*/

    resultE = bitxor(resultD,l2b)
    call trc('      stepE : Result-D is XORed with L2B')
    call trc('      stepE done, resultE=' c2x(resultE) )

/* Step F  The values of L2B and R2B are redefined:
           1.  L2B is set equal to R2B.
           2.  R2B is set equal to Result-E.                              */

    l2b = r2b
    r2b = resultE
    call trc('      stepF : l2b=r2b and r2b=resultE')
    call trc('      stepF done, l2b=' c2x(l2b) ,
                            ' r2b=' c2x(r2b)    )

/* Step G  R2B is permuted using the permutation tables , where the table
    used reflects the number of the round. For example, for the first time
    through, R2B is permuted using table 1.                               */

    call trc('      stepG : r2b permuted using one of 6 perm tb')
    call trc('r2b before perm' c2x(r2b))
    /* r2b = Permut(r2b,round,trace)       */

    call Permut                  /* Uses r2b,round,trace  */
    r2b = R

    call trc('      stepG done, r2b=' c2x(r2b)   )

/* Step H  This step counts the number of time-coder rounds that have been
    completed.  If the value is less than 6, the time-coder returns to
    Step b for another round. If 6 rounds have been completed, processing
    continues with the next step.                                         */

    end         /*   end of "DO round = 1 to 6" loop                      */

/* Step I  L2B (left 2 bytes) and R2B (right 2 bytes) are recombined
    into a 32-bit string. This completes the time-coder processing and
    produces Result-5. This result is passed back to the generator algorithm
    as input to Step 6 for translation.                                   */

    call trc('      stepI done, result=' c2x(l2b)||c2x(r2b))

    R = l2b||r2b
   return
   exit

/*------------------------------------------------------------------------*/
/*                  16-bit permutation subroutine                         */
/* parameters : r2b, round, trace                                         */
/*------------------------------------------------------------------------*/

Permut:

    call trc('r2b in Permut' c2x(r2b))
   bitv.1  = '1000000000000000'b
   bitv.2  = '0100000000000000'b
   bitv.3  = '0010000000000000'b
   bitv.4  = '0001000000000000'b
   bitv.5  = '0000100000000000'b
   bitv.6  = '0000010000000000'b
   bitv.7  = '0000001000000000'b
   bitv.8  = '0000000100000000'b
   bitv.9  = '0000000010000000'b
   bitv.10 = '0000000001000000'b
   bitv.11 = '0000000000100000'b
   bitv.12 = '0000000000010000'b
   bitv.13 = '0000000000001000'b
   bitv.14 = '0000000000000100'b
   bitv.15 = '0000000000000010'b
   bitv.16 = '0000000000000001'b

   R = '0000'x       /* permutation result = 0 initially */

   /* Permutation number 1 */
   if round = 1 then do
      if bitand(bitv.10,r2b) <> '0000'x then R = bitor(R,bitv.1)
      if bitand(bitv.2,r2b)   <> '0000'x then R = bitor(R,bitv.2)
      if bitand(bitv.12,r2b) <> '0000'x then R = bitor(R,bitv.3)
      if bitand(bitv.4,r2b)   <> '0000'x then R = bitor(R,bitv.4)
      if bitand(bitv.14,r2b) <> '0000'x then R = bitor(R,bitv.5)
      if bitand(bitv.6,r2b)   <> '0000'x then R = bitor(R,bitv.6)
      if bitand(bitv.16,r2b) <> '0000'x then R = bitor(R,bitv.7)
      if bitand(bitv.8,r2b)   <> '0000'x then R = bitor(R,bitv.8)
      if bitand(bitv.9,r2b)   <> '0000'x then R = bitor(R,bitv.9)
      if bitand(bitv.1,r2b)   <> '0000'x then R = bitor(R,bitv.10)
      if bitand(bitv.11,r2b) <> '0000'x then R = bitor(R,bitv.11)
      if bitand(bitv.3,r2b)   <> '0000'x then R = bitor(R,bitv.12)
      if bitand(bitv.13,r2b) <> '0000'x then R = bitor(R,bitv.13)
      if bitand(bitv.5,r2b)   <> '0000'x then R = bitor(R,bitv.14)
      if bitand(bitv.15,r2b) <> '0000'x then R = bitor(R,bitv.15)
      if bitand(bitv.7,r2b)   <> '0000'x then R = bitor(R,bitv.16)
      end

   /* Permutation number 2 */
   if round = 2 then do
      if bitand(bitv.1,r2b)   <> '0000'x then R = bitor(R,bitv.1)
      if bitand(bitv.10,r2b) <> '0000'x then R = bitor(R,bitv.2)
      if bitand(bitv.3,r2b)   <> '0000'x then R = bitor(R,bitv.3)
      if bitand(bitv.12,r2b) <> '0000'x then R = bitor(R,bitv.4)
      if bitand(bitv.13,r2b) <> '0000'x then R = bitor(R,bitv.5)
      if bitand(bitv.16,r2b) <> '0000'x then R = bitor(R,bitv.6)
      if bitand(bitv.7,r2b)   <> '0000'x then R = bitor(R,bitv.7)
      if bitand(bitv.15,r2b) <> '0000'x then R = bitor(R,bitv.8)
      if bitand(bitv.9,r2b)   <> '0000'x then R = bitor(R,bitv.9)
      if bitand(bitv.2,r2b)   <> '0000'x then R = bitor(R,bitv.10)
      if bitand(bitv.11,r2b) <> '0000'x then R = bitor(R,bitv.11)
      if bitand(bitv.4,r2b)   <> '0000'x then R = bitor(R,bitv.12)
      if bitand(bitv.5,r2b)   <> '0000'x then R = bitor(R,bitv.13)
      if bitand(bitv.14,r2b) <> '0000'x then R = bitor(R,bitv.14)
      if bitand(bitv.8,r2b)   <> '0000'x then R = bitor(R,bitv.15)
      if bitand(bitv.6,r2b)   <> '0000'x then R = bitor(R,bitv.16)
      end

   /* Permutation number 3 */
   if round = 3 then do
      if bitand(bitv.3,r2b)   <> '0000'x then R = bitor(R,bitv.1)
      if bitand(bitv.10,r2b) <> '0000'x then R = bitor(R,bitv.2)
      if bitand(bitv.1,r2b)   <> '0000'x then R = bitor(R,bitv.3)
      if bitand(bitv.12,r2b) <> '0000'x then R = bitor(R,bitv.4)
      if bitand(bitv.13,r2b) <> '0000'x then R = bitor(R,bitv.5)
      if bitand(bitv.16,r2b) <> '0000'x then R = bitor(R,bitv.6)
      if bitand(bitv.9,r2b)   <> '0000'x then R = bitor(R,bitv.7)
      if bitand(bitv.15,r2b) <> '0000'x then R = bitor(R,bitv.8)
      if bitand(bitv.7,r2b)   <> '0000'x then R = bitor(R,bitv.9)
      if bitand(bitv.2,r2b)   <> '0000'x then R = bitor(R,bitv.10)
      if bitand(bitv.14,r2b) <> '0000'x then R = bitor(R,bitv.11)
      if bitand(bitv.4,r2b)   <> '0000'x then R = bitor(R,bitv.12)
      if bitand(bitv.5,r2b)   <> '0000'x then R = bitor(R,bitv.13)
      if bitand(bitv.11,r2b) <> '0000'x then R = bitor(R,bitv.14)
      if bitand(bitv.8,r2b)   <> '0000'x then R = bitor(R,bitv.15)
      if bitand(bitv.6,r2b)   <> '0000'x then R = bitor(R,bitv.16)
      end

   /* Permutation number 4 */
   if round = 4 then do
      if bitand(bitv.10,r2b) <> '0000'x then R = bitor(R,bitv.1)
      if bitand(bitv.4,r2b)   <> '0000'x then R = bitor(R,bitv.2)
      if bitand(bitv.12,r2b) <> '0000'x then R = bitor(R,bitv.3)
      if bitand(bitv.2,r2b)   <> '0000'x then R = bitor(R,bitv.4)
      if bitand(bitv.14,r2b) <> '0000'x then R = bitor(R,bitv.5)
      if bitand(bitv.8,r2b)   <> '0000'x then R = bitor(R,bitv.6)
      if bitand(bitv.16,r2b) <> '0000'x then R = bitor(R,bitv.7)
      if bitand(bitv.6,r2b)   <> '0000'x then R = bitor(R,bitv.8)
      if bitand(bitv.9,r2b)   <> '0000'x then R = bitor(R,bitv.9)
      if bitand(bitv.1,r2b)   <> '0000'x then R = bitor(R,bitv.10)
      if bitand(bitv.13,r2b) <> '0000'x then R = bitor(R,bitv.11)
      if bitand(bitv.3,r2b)   <> '0000'x then R = bitor(R,bitv.12)
      if bitand(bitv.11,r2b) <> '0000'x then R = bitor(R,bitv.13)
      if bitand(bitv.5,r2b)   <> '0000'x then R = bitor(R,bitv.14)
      if bitand(bitv.15,r2b) <> '0000'x then R = bitor(R,bitv.15)
      if bitand(bitv.7,r2b)   <> '0000'x then R = bitor(R,bitv.16)
      end

   /* Permutation number 5 */
   if round = 5 then do
      if bitand(bitv.4,r2b)   <> '0000'x then R = bitor(R,bitv.1)
      if bitand(bitv.10,r2b) <> '0000'x then R = bitor(R,bitv.2)
      if bitand(bitv.12,r2b) <> '0000'x then R = bitor(R,bitv.3)
      if bitand(bitv.1,r2b)   <> '0000'x then R = bitor(R,bitv.4)
      if bitand(bitv.8,r2b)   <> '0000'x then R = bitor(R,bitv.5)
      if bitand(bitv.16,r2b) <> '0000'x then R = bitor(R,bitv.6)
      if bitand(bitv.14,r2b) <> '0000'x then R = bitor(R,bitv.7)
      if bitand(bitv.5,r2b)   <> '0000'x then R = bitor(R,bitv.8)
      if bitand(bitv.9,r2b)   <> '0000'x then R = bitor(R,bitv.9)
      if bitand(bitv.2,r2b)   <> '0000'x then R = bitor(R,bitv.10)
      if bitand(bitv.13,r2b) <> '0000'x then R = bitor(R,bitv.11)
      if bitand(bitv.3,r2b)   <> '0000'x then R = bitor(R,bitv.12)
      if bitand(bitv.11,r2b) <> '0000'x then R = bitor(R,bitv.13)
      if bitand(bitv.7,r2b)   <> '0000'x then R = bitor(R,bitv.14)
      if bitand(bitv.15,r2b) <> '0000'x then R = bitor(R,bitv.15)
      if bitand(bitv.6,r2b)   <> '0000'x then R = bitor(R,bitv.16)
      end

   /* Permutation number 6 */
   if round = 6 then do
      if bitand(bitv.1,r2b)   <> '0000'x then R = bitor(R,bitv.1)
      if bitand(bitv.16,r2b) <> '0000'x then R = bitor(R,bitv.2)
      if bitand(bitv.15,r2b) <> '0000'x then R = bitor(R,bitv.3)
      if bitand(bitv.14,r2b) <> '0000'x then R = bitor(R,bitv.4)
      if bitand(bitv.13,r2b) <> '0000'x then R = bitor(R,bitv.5)
      if bitand(bitv.12,r2b) <> '0000'x then R = bitor(R,bitv.6)
      if bitand(bitv.11,r2b) <> '0000'x then R = bitor(R,bitv.7)
      if bitand(bitv.10,r2b) <> '0000'x then R = bitor(R,bitv.8)
      if bitand(bitv.9,r2b)   <> '0000'x then R = bitor(R,bitv.9)
      if bitand(bitv.8,r2b)   <> '0000'x then R = bitor(R,bitv.10)
      if bitand(bitv.7,r2b)   <> '0000'x then R = bitor(R,bitv.11)
      if bitand(bitv.6,r2b)   <> '0000'x then R = bitor(R,bitv.12)
      if bitand(bitv.5,r2b)   <> '0000'x then R = bitor(R,bitv.13)
      if bitand(bitv.4,r2b)   <> '0000'x then R = bitor(R,bitv.14)
      if bitand(bitv.3,r2b)   <> '0000'x then R = bitor(R,bitv.15)
      if bitand(bitv.2,r2b)   <> '0000'x then R = bitor(R,bitv.16)
      end
    msg =  ' result of permutation ' round ,
      'on' c2x(r2b) 'is' c2x(R)
    call trc(msg)

   return
   exit

/* rexx */

/*------------------------------------------------------------------------*/
/*               Final translation subroutine                             */
/*  Generates the pass-ticket from the 32-bit input                       */
/*------------------------------------------------------------------------*/

translat:


/* The translation table consists of 36 slots.
   The first 26 slots are occupied by the letters of the alphabet: A-Z.
   The last ten slots are occupied by the numerics 0-9.                  */

transtb = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

   bitv.1  = '10000000000000000000000000000000'b
   bitv.2  = '01000000000000000000000000000000'b
   bitv.3  = '00100000000000000000000000000000'b
   bitv.4  = '00010000000000000000000000000000'b
   bitv.5  = '00001000000000000000000000000000'b
   bitv.6  = '00000100000000000000000000000000'b
   bitv.7  = '00000010000000000000000000000000'b
   bitv.8  = '00000001000000000000000000000000'b
   bitv.9  = '00000000100000000000000000000000'b
   bitv.10 = '00000000010000000000000000000000'b
   bitv.11 = '00000000001000000000000000000000'b
   bitv.12 = '00000000000100000000000000000000'b
   bitv.13 = '00000000000010000000000000000000'b
   bitv.14 = '00000000000001000000000000000000'b
   bitv.15 = '00000000000000100000000000000000'b
   bitv.16 = '00000000000000010000000000000000'b
   bitv.17 = '00000000000000001000000000000000'b
   bitv.18 = '00000000000000000100000000000000'b
   bitv.19 = '00000000000000000010000000000000'b
   bitv.20 = '00000000000000000001000000000000'b
   bitv.21 = '00000000000000000000100000000000'b
   bitv.22 = '00000000000000000000010000000000'b
   bitv.23 = '00000000000000000000001000000000'b
   bitv.24 = '00000000000000000000000100000000'b
   bitv.25 = '00000000000000000000000010000000'b
   bitv.26 = '00000000000000000000000001000000'b
   bitv.27 = '00000000000000000000000000100000'b
   bitv.28 = '00000000000000000000000000010000'b
   bitv.29 = '00000000000000000000000000001000'b
   bitv.30 = '00000000000000000000000000000100'b
   bitv.31 = '00000000000000000000000000000010'b
   bitv.32 = '00000000000000000000000000000001'b
   zero32  = '00000000000000000000000000000000'b         /* 32 bits = 0  */

/* 1.  Bits 31, 32, 1, 2, 3, and 4 are translated to PassTicket character
       position 1, which is the leftmost position in the 8-byte
       alphanumeric PassTicket field.

    To produce this character:

    - The binary number, represented by the six bits, is divided by decimal 36.

    - The remainder is used as an index into the translation table.    */

  r = '00000000'b                               /* 8 bits = 0  */
  if bitand(bitv.31,zone)  <> zero32 then r = bitor(r,'00100000'b)
  if bitand(bitv.32,zone)  <> zero32 then r = bitor(r,'00010000'b)
  if bitand(bitv.1,zone)   <> zero32 then r = bitor(r,'00001000'b)
  if bitand(bitv.2,zone)   <> zero32 then r = bitor(r,'00000100'b)
  if bitand(bitv.3,zone)   <> zero32 then r = bitor(r,'00000010'b)
  if bitand(bitv.4,zone)   <> zero32 then r = bitor(r,'00000001'b)
  remainder = c2d(r)//36
  pt = substr(transtb,remainder+1,1)

/* 2.  The process is repeated with the rest of the bit string:

    -  Bits 3 through 8 are translated to PassTicket character position 2. */

  r = '00000000'b                               /* 8 bits = 0  */
  if bitand(bitv.3,zone)   <> zero32 then r = bitor(r,'00100000'b)
  if bitand(bitv.4,zone)   <> zero32 then r = bitor(r,'00010000'b)
  if bitand(bitv.5,zone)   <> zero32 then r = bitor(r,'00001000'b)
  if bitand(bitv.6,zone)   <> zero32 then r = bitor(r,'00000100'b)
  if bitand(bitv.7,zone)   <> zero32 then r = bitor(r,'00000010'b)
  if bitand(bitv.8,zone)   <> zero32 then r = bitor(r,'00000001'b)
  remainder = c2d(r)//36
  pt = pt||substr(transtb,remainder+1,1)


/*  - Bits 7 through 12 are translated to PassTicket character position 3. */

  r = '00000000'b                               /* 8 bits = 0  */
  if bitand(bitv.7,zone)   <> zero32 then r = bitor(r,'00100000'b)
  if bitand(bitv.8,zone)   <> zero32 then r = bitor(r,'00010000'b)
  if bitand(bitv.9,zone)   <> zero32 then r = bitor(r,'00001000'b)
  if bitand(bitv.10,zone)  <> zero32 then r = bitor(r,'00000100'b)
  if bitand(bitv.11,zone)  <> zero32 then r = bitor(r,'00000010'b)
  if bitand(bitv.12,zone)  <> zero32 then r = bitor(r,'00000001'b)
  remainder = c2d(r)//36
  pt = pt||substr(transtb,remainder+1,1)

/*  - Bits 11 through 16 are translated to PassTicket character position 4. */


  r = '00000000'b                               /* 8 bits = 0  */
  if bitand(bitv.11,zone)  <> zero32 then r = bitor(r,'00100000'b)
  if bitand(bitv.12,zone)  <> zero32 then r = bitor(r,'00010000'b)
  if bitand(bitv.13,zone)  <> zero32 then r = bitor(r,'00001000'b)
  if bitand(bitv.14,zone)  <> zero32 then r = bitor(r,'00000100'b)
  if bitand(bitv.15,zone)  <> zero32 then r = bitor(r,'00000010'b)
  if bitand(bitv.16,zone)  <> zero32 then r = bitor(r,'00000001'b)
  remainder = c2d(r)//36
  pt = pt||substr(transtb,remainder+1,1)

/*  - Bits 15 through 20 are translated to PassTicket character position 5. */

  r = '00000000'b                               /* 8 bits = 0  */
  if bitand(bitv.15,zone)  <> zero32 then r = bitor(r,'00100000'b)
  if bitand(bitv.16,zone)  <> zero32 then r = bitor(r,'00010000'b)
  if bitand(bitv.17,zone)  <> zero32 then r = bitor(r,'00001000'b)
  if bitand(bitv.18,zone)  <> zero32 then r = bitor(r,'00000100'b)
  if bitand(bitv.19,zone)  <> zero32 then r = bitor(r,'00000010'b)
  if bitand(bitv.20,zone)  <> zero32 then r = bitor(r,'00000001'b)
  remainder = c2d(r)//36
  pt = pt||substr(transtb,remainder+1,1)


/*  - Bits 19 through 24 are translated to PassTicket character position 6. */

  r = '00000000'b                               /* 8 bits = 0  */
  if bitand(bitv.19,zone)  <> zero32 then r = bitor(r,'00100000'b)
  if bitand(bitv.20,zone)  <> zero32 then r = bitor(r,'00010000'b)
  if bitand(bitv.21,zone)  <> zero32 then r = bitor(r,'00001000'b)
  if bitand(bitv.22,zone)  <> zero32 then r = bitor(r,'00000100'b)
  if bitand(bitv.23,zone)  <> zero32 then r = bitor(r,'00000010'b)
  if bitand(bitv.24,zone)  <> zero32 then r = bitor(r,'00000001'b)
  remainder = c2d(r)//36
  pt = pt||substr(transtb,remainder+1,1)

/*  - Bits 23 through 28 are translated to PassTicket character position 7. */

  r = '00000000'b                               /* 8 bits = 0  */
  if bitand(bitv.23,zone)  <> zero32 then r = bitor(r,'00100000'b)
  if bitand(bitv.24,zone)  <> zero32 then r = bitor(r,'00010000'b)
  if bitand(bitv.25,zone)  <> zero32 then r = bitor(r,'00001000'b)
  if bitand(bitv.26,zone)  <> zero32 then r = bitor(r,'00000100'b)
  if bitand(bitv.27,zone)  <> zero32 then r = bitor(r,'00000010'b)
  if bitand(bitv.28,zone)  <> zero32 then r = bitor(r,'00000001'b)
  remainder = c2d(r)//36
  pt = pt||substr(transtb,remainder+1,1)

/*  - Bits 27 through 32 are translated to PassTicket character position 8. */

  r = '00000000'b                               /* 8 bits = 0  */
  if bitand(bitv.27,zone)  <> zero32 then r = bitor(r,'00100000'b)
  if bitand(bitv.28,zone)  <> zero32 then r = bitor(r,'00010000'b)
  if bitand(bitv.29,zone)  <> zero32 then r = bitor(r,'00001000'b)
  if bitand(bitv.30,zone)  <> zero32 then r = bitor(r,'00000100'b)
  if bitand(bitv.31,zone)  <> zero32 then r = bitor(r,'00000010'b)
  if bitand(bitv.32,zone)  <> zero32 then r = bitor(r,'00000001'b)
  remainder = c2d(r)//36
  pt = pt||substr(transtb,remainder+1,1)


    call trc('        passticket=' pt              )

  return

/*------------------------------------------------------------------------*/
/*                          Trace routine                                 */
/*------------------------------------------------------------------------*/

trc:

if trace = 'Y' then do
                    itrace = itrace+1
                    /* say arg(1) */
                    t.itrace = arg(1)
                    end
return

showtrc:
  if itrace > 0 then ,
  say '************** trace display ************************'
  do i = 1 to itrace
  say t.i
  if i//20 = 0 then pull response
  end
  return

  exit
