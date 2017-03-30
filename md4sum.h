/*
 *	$Id: md4sum.h,v 1.11 2007-04-11 21:23:31 solyga Exp $
 */

#define	DEBUG
#undef	DEBUG

#define	_LARGEFILE64_SOURCE
#define	_FILE_OFFSET_BITS	64

#include	<stdio.h>
#include	<stdlib.h>	/* strtol(), malloc() */
#include	<sys/types.h>	/* open(), socket(), connect(), ulong */
#include	<sys/stat.h>	/* open() */
#include	<fcntl.h>	/* open(), O_RDONLY */
#include	<unistd.h>	/* getopt(), read(), write(), close(), FILENO */
#include	<errno.h>
#include	<string.h>	/* str*() */
#include	<limits.h>	/* INT_MAX, INT_MIN */


#define	HELP_CHANNEL	stdout
#define	VERSION_CHANNEL	stdout
#define	ERROR_CHANNEL	stderr
#define	VERBOSE_CHANNEL	stderr
#define	DEBUG_CHANNEL	stderr

#define	RETVAL_OK	 0
#define	RETVAL_FAILED	 1		/* check failed at least once */
#define	RETVAL_BUG	 2
#define	RETVAL_ERROR	 3

#define	VERBOSE_LEVEL_MAX	2	/* check this, may have changed */
#define	DEFAULT_NAMES		0	/* print filenames with md4-sums? */
#define	LINE_LENGTH		512	/* for digest file */
#define	BUF_SIZE		50*1024	/* for digest generation */
#define	DONKEY_BLOCKS		190
#define DONKEY_BLOCK_SIZE	(DONKEY_BLOCKS*BUF_SIZE)	/* 9728000 ! */

#define	FLIP(a)		( (a) = (a) ? 0 : 1 )

#define	VERSION_NUMBER		"0.02.03"
#define	DATE_OF_LAST_MOD	"2007-04-11"
#define	MY_EMAIL_ADDRESS	"Steffen Solyga <solyga@absinth.net>"

/* rfc1320 stuff */
#include	"md4.c"
