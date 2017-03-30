/*
  md4sum.c  --  generate or check MD4 message digests
  Copyright (C) 2002-2004 Steffen Solyga <solyga@absinth.net>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/*
  This program uses the md4 ("RSA Data Security Inc. MD4 Message-Digest
  Algorithm") reference implementation published with RFC 1320.
  For global.h, md4.h and md4c.c:
  Copyright (C) 1990-2, RSA Data Security, Inc. All rights reserved
*/

/*
 *	$Id: md4sum.c,v 1.14 2007-04-11 21:22:38 solyga Exp $
 */

#include	"md4sum.h"


int
display_help( char* pn ) {
  fprintf( HELP_CHANNEL, "%s v%s (%s): ", pn, VERSION_NUMBER, DATE_OF_LAST_MOD );
  fprintf( HELP_CHANNEL, "Generate or check MD4 message digests.\n" );
  fprintf( HELP_CHANNEL, "Flowers & bug reports to %s.\n", MY_EMAIL_ADDRESS );
  fprintf( HELP_CHANNEL, "Usage: %s [options] [file(s)]\n", pn );
  fprintf( HELP_CHANNEL, "switches:\n" );
  fprintf( HELP_CHANNEL, "  -c\t check message digest(s)\n" );
  fprintf( HELP_CHANNEL, "  -e\t print ed2k link instead of MD4 sum\n" );
  fprintf( HELP_CHANNEL, "  -h\t write this info to %s and exit sucessfully\n", HELP_CHANNEL==stdout?"stdout":"stderr" );
  fprintf( HELP_CHANNEL, "  -n\t %sprint filename(s) with message digest(s)\n", DEFAULT_NAMES!=0?"don't ":"" );
  fprintf( HELP_CHANNEL, "  -v\t raise verbosity level on %s (max %d)\n", VERBOSE_CHANNEL==stdout?"stdout":"stderr", VERBOSE_LEVEL_MAX );
  fprintf( HELP_CHANNEL, "  -V\t print version and compilation info to %s and exit sucessfully\n", VERSION_CHANNEL==stdout?"stdout":"stderr" );
  return( 0 );
}


int
display_version( char* pn ) {
  fprintf( VERSION_CHANNEL, "%s v%s (%s)\n", pn, VERSION_NUMBER, DATE_OF_LAST_MOD );
  fprintf( VERSION_CHANNEL, "compilation settings:\n" );
  fprintf( VERSION_CHANNEL, "  DEFAULT_NAMES:  %d\n", DEFAULT_NAMES );
  fprintf( VERSION_CHANNEL, "  LINE_LENGTH  :  %d\n", LINE_LENGTH );
  return( 0 );
}


ssize_t
my_read( int fd, void* buf, size_t count ) {
/*
 * (attempts to) read exactly count bytes from fd into buf
 * returns number of bytes read or -1 on error
 * retval < count indicates EOF (or EAGAIN when non-blocking)
 * started 1998-01-01
 */
  unsigned char* p= buf;
  ssize_t nbr;
  ssize_t tnbr= 0;
  size_t rem= count;
  do {
    if( (nbr=read(fd,p+tnbr,rem)) == -1 ) {
      if( errno == EAGAIN ) return( tnbr );
      else                  return( -1 );
    }
    tnbr+= nbr;
    rem-= nbr;
  } while( nbr>0 && rem>0 );
  return( tnbr );
}


ssize_t
my_readline( int fd, void* buf, size_t count ) {
/*
 * read one line from fd into buf, but at most count bytes
 * returns number of bytes read or -1 on error
 * retval == 0 indicates EOF
 */
  unsigned char* p= buf;
  ssize_t nbr= 1;
  ssize_t tnbr= 0;
  while( nbr == 1  &&  tnbr < count ) {
    if( (nbr=read(fd,p+tnbr,1)) == -1 ) return( -1 );
    tnbr+= nbr;
    if( p[tnbr-1] == '\n' ) {
      p[tnbr-1]= '\0';
      break;
    }
  }
  return( tnbr );
}


char*
str_dsc( char* str1, char* str2) {
/*
returns pointer to first char of str1 not contained in str2
started 1997-02-09
*/
  char *p1, *p2;
  for ( p1=str1; ; p1++ ) {
    if ( *p1 == '\0' ) return( p1 );
    for ( p2=str2; ; p2++ ) {
      if ( *p2 == '\0' ) return( p1 );
      if ( *p2 == *p1 ) break;
    }
  }
}


char*
digest2str( unsigned char* digest ) {
  int i;
  static char s[33];
  for( i=0; i<16; i++ ) sprintf( &s[2*i], "%02x", digest[i] );
  s[33]= '\0';
  return( s );
}


char*
basename( char* name ) {
/*
 * strip directory from name
 * returns pointer to stripped name
 * hint: basename("/usr/bin/") == ""
 *   basename(1) would return "bin" !!
 */
  char* p= name;
  while( *p != '\0' ) p++;
  while( p > name ) {
    if( *(p-1) == '/' ) break;
    else p--;
  }
  return( p );
}



int
main( int argc, char** argv ) {
/*
 * main() md4sum
 * started Tue Oct 22 02:31:33 CEST 2002 @beast
 */
  char* fpn= *argv;
  char* pn= basename( fpn );		/* prg_name is Makefile constant */
  int retval= RETVAL_OK;
  int c;
  int verbose= 0;			/* verbosity level */
  int check= 0;				/* flag: check or generate digest(s) */
  int names= DEFAULT_NAMES;		/* flag: print filename(s) */
  int ed2k= 0;
  char* dig_fn = NULL;
  int dig_fd= -1;
  char* in_fn;
  int in_fd= -1;
  char stdin_fn[]= "-";
  int fi= 0;				/* file index */
  int nbr;				/* number of bytes read (in_fd) */
  off_t tnbr;			/* total number of bytes read (in_fd) */
  int dig_nbr;				/* number of bytes read (dig_fd) */
  long int dig_tnbr= 0;			/* total n.o. bytes read (dig_fd) */
  unsigned char buf[BUF_SIZE];		/* file buffer */
  unsigned char digest[16];		/* binary md4 digest */
  unsigned char* pdigest= NULL;		/* binary md4 partial digests */
  int npd= 0;				/* number of partial digests */
  ctx_t context;
  char sdigest[33];			/* digest string (generated) */
  char fdigest[33];			/* digest string (dig_fd) */
  char line[LINE_LENGTH];		/* input line (dig_fd) */


/* process options */
  *argv= pn;				/* give getop() the cut name */
  while( (c=getopt(argc,argv,"cehnvV")) != EOF ) {
    switch( c ) {
      case 'c':	/* check digests taken from file */
        check= 1;
        break;
      case 'e':	/* generate ed2k link string instead of MD4 sum */
        ed2k= 1;
        break;
      case 'h': /* display help and exit sucessfully */
        display_help( pn );
        retval= RETVAL_OK; goto DIE_NOW;
      case 'n':	/* change printing of filename(s) */
        FLIP(names);
        break;
      case 'v': /* raise verbosity level */
        verbose++;
        break;
      case 'V': /* display version to VERSION_CHANNEL and exit sucessfully */
        display_version( pn );
        retval= RETVAL_OK; goto DIE_NOW;
      case '?': /* refer to -h and exit unsucessfully */
        fprintf( ERROR_CHANNEL, "%s: Try '%s -h' for more information.\n",
                 pn, pn );
        retval= RETVAL_ERROR; goto DIE_NOW;
      default : /* program error */
        fprintf( ERROR_CHANNEL, "%s: Options bug! E-mail me at %s.\n",
                 pn, MY_EMAIL_ADDRESS );
        retval= RETVAL_BUG; goto DIE_NOW;
    }
  }

/* some test(s) */

  if( sizeof(unsigned int) != 4 ) {
    fprintf( ERROR_CHANNEL,
             "%s: sizeof(unsigned int)= %d (!=4). E-mail me at %s.\n",
             pn, sizeof(unsigned int), MY_EMAIL_ADDRESS );
    retval= RETVAL_BUG; goto DIE_NOW;
  }

/* open digest file (checking) */
  if( check ) {
    dig_fd= STDIN_FILENO;
    if( (argc > optind)  &&  (*argv[optind] != '-') ) {
      dig_fn= argv[optind];
      if( (dig_fd=open(dig_fn,O_RDONLY)) == -1 ) {
        fprintf( ERROR_CHANNEL, "%s: Cannot open digest file '%s'. %s.\n",
                 pn, dig_fn, strerror(errno) );
        retval= RETVAL_ERROR; goto DIE_NOW;
      }
    }
    if( verbose ) {
      fprintf( VERBOSE_CHANNEL, "%s: Reading digest(s) from ", pn );
      if( dig_fd == STDIN_FILENO ) fprintf( VERBOSE_CHANNEL, "stdin.\n" );
      else fprintf( VERBOSE_CHANNEL, "file '%s'.\n", dig_fn );
    }
  }

/* do the work */
  while( 1 ) {
    /* set in_fn or break */
    if( check ) { /* read in_fn from digest file dig_fd */
      in_fn= NULL;
      while( in_fn == NULL ) {
        if( (dig_nbr=my_readline(dig_fd,line,LINE_LENGTH)) == -1 ) {
          fprintf( ERROR_CHANNEL, "%s: Cannot read '%s'. %s.\n",
                   pn, dig_fn, strerror(errno) );
          retval= RETVAL_ERROR; goto DIE_NOW;
        }
        dig_tnbr+= dig_nbr;
        if( dig_nbr == LINE_LENGTH ) {
          fprintf( ERROR_CHANNEL, "%s: Increase LINE_LENGTH and recompile.\n",
                   pn );
          retval= RETVAL_BUG; goto DIE_NOW;
        }
        if( dig_nbr == 0 ) break;
        if( *str_dsc(line," \t") == '#' ) continue;
        in_fn= str_dsc( line, " \t" );
        if( strlen(in_fn) < 32 ) {
          fprintf( ERROR_CHANNEL, "%s: Not an MD4 message digest '%s'.\n",
                   pn, in_fn );
          retval= RETVAL_ERROR; goto DIE_NOW;
        }
        strncpy(fdigest,in_fn,32); fdigest[32]= '\0';
        if( strlen(in_fn=str_dsc(in_fn+32," \t")) == 0 ) {
          fprintf( ERROR_CHANNEL, "%s: Invalid filename '%s'.\n", pn, in_fn );
          retval= RETVAL_ERROR; goto DIE_NOW;
        }
      }
      if( in_fn == NULL ) break;
    }
    else { /* use in_fn from command line argument(s) */
      if( argc > optind+fi ) {
        in_fn= argv[optind+fi];
      }
      else {
        in_fn= stdin_fn;
        if( fi )  break;
      }
      fi++;
    }
    /* open input file */
    in_fd= STDIN_FILENO;
    if( *in_fn != '-' ) {
      if( (in_fd=open(in_fn,O_RDONLY)) == -1 ) {
        fprintf( ERROR_CHANNEL, "%s: Cannot open input file '%s'. %s.\n",
                 pn, in_fn, strerror(errno) );
        retval= RETVAL_ERROR; goto DIE_NOW;
      }
    }
    if( dig_fd == STDIN_FILENO  &&  in_fd == STDIN_FILENO ) {
      fprintf( ERROR_CHANNEL, "%s: Cannot read data AND digest from stdin!\n",
               pn );
      retval= RETVAL_ERROR; goto DIE_NOW;
    }
    if( verbose ) {
      fprintf( VERBOSE_CHANNEL, "%s: Generating %s for ",
               pn, ed2k?"ed2k link":"MD4 digest" );
      if( in_fd == STDIN_FILENO ) fprintf( VERBOSE_CHANNEL, "stdin.\n" );
      else fprintf( VERBOSE_CHANNEL, "file '%s'.\n", in_fn );
    }
    /* generate md4 digest and digest string */
    tnbr= 0;
    if( ! ed2k ) {	/* simple digest */
      MD4Init( &context );
      while( 1 ) {
        if( (nbr=my_read(in_fd,buf,BUF_SIZE)) == -1 ) {
          fprintf( ERROR_CHANNEL, "%s: Cannot read '%s'. %s.\n",
                   pn, in_fn, strerror(errno) );
          retval= RETVAL_ERROR; goto DIE_NOW;
        }
        tnbr+= nbr;
        MD4Update( &context, buf, nbr );
        if( nbr == 0 ) break;
      }
      MD4Final( digest, &context );
    }
    else {	/* digest of partial digests (special ed2k algorithm) */
      MD4Init( &context );
      while( 1 ) {
        if( (nbr=my_read(in_fd,buf,BUF_SIZE)) == -1 ) {
          fprintf( ERROR_CHANNEL, "%s: Cannot read '%s'. %s.\n",
                   pn, in_fn, strerror(errno) );
          retval= RETVAL_ERROR; goto DIE_NOW;
        }
        tnbr+= nbr;
        MD4Update( &context, buf, nbr );
        if( nbr == 0  ||  tnbr%DONKEY_BLOCK_SIZE == 0  ) {
          if( nbr == 0  &&  tnbr%DONKEY_BLOCK_SIZE == 0 ) break;
          npd++;
          if( (pdigest=realloc(pdigest,npd*16)) == NULL ) {
            fprintf( ERROR_CHANNEL, "%s: Out of memory.\n", pn );
            retval= RETVAL_ERROR; goto DIE_NOW;
          }
          MD4Final( pdigest+(npd-1)*16, &context );
          if( verbose >= 2 ) {
            fprintf( VERBOSE_CHANNEL, "%s: ed2k-block %2d: %s\n",
                     pn, npd-1, digest2str(pdigest+(npd-1)*16) );
          }
          MD4Init( &context );
        }
        if( nbr == 0 ) break;
      }
      if( npd > 1 ) {
        MD4Init( &context );
        MD4Update( &context, pdigest, npd*16 );
        MD4Final( digest, &context );
      }
      else {
        memcpy( digest, pdigest, 16 );
      }
      free( pdigest );
      pdigest= NULL; npd= 0;
    } 
    strncpy( sdigest, digest2str(digest), 33 );
    /* close input file */
    if( in_fd != STDIN_FILENO ) close( in_fd );
    /* process md4 digest string */
    if( check ) {
      if( strcmp(sdigest,fdigest) == 0 ) {
          fprintf( VERBOSE_CHANNEL, "%s: MD4 check succeeded for '%s'.\n",
                   pn, in_fn );
      }
      else {
          fprintf( VERBOSE_CHANNEL, "%s: MD4 check failed for '%s'.\n",
                   pn, in_fn );
          retval= RETVAL_FAILED;
      }
    }
    else if( ed2k ) {
      printf( "ed2k://|file|%s|%lld|%s|\n", basename(in_fn), tnbr, sdigest );
    }
    else {
      printf( "%s", sdigest );
      if( names ) printf( "  %s", in_fn );
      printf( "\n" );
    }
  }

/* close digest file (checking) */
  if( check  &&  (dig_fd != STDIN_FILENO) ) {
    close( dig_fd );
  }


DIE_NOW:
  if( pdigest ) free( pdigest );
  close( in_fd );
  close( dig_fd );
  exit( retval );
}
