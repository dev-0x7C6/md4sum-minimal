/* This code is "derived from the RSA Data Security, Inc.
   MD4 Message-Digest Algorithm" published in rfc1320
*/


typedef struct {
  unsigned int st[4];		/* state (A,B,C,D) */
  unsigned long long cnt;	/* processed bits */
  unsigned char buf[64];	/* input buffer */
  unsigned int idx;
} ctx_t;

/* Constants for MD4Transform routine.
 */
#define S11 3
#define S12 7
#define S13 11
#define S14 19
#define S21 3
#define S22 5
#define S23 9
#define S24 13
#define S31 3
#define S32 9
#define S33 11
#define S34 15

static unsigned char PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
this 4-ops-functions is equivalent to the following 3-ops-function:
*/
#define F( x, y, z )	( (((y) ^ (z)) & (x)) ^ (z) )
#define G( x, y, z )	( ((x) & (y)) | ((x) & (z)) | ((y) & (z)) )
#define H( x, y, z )	( (x) ^ (y) ^ (z) )

#define ROTL( x, n )	( ((x) << (n)) | ((x) >> (32-(n))) )

/* Rotation is separate from addition to prevent recomputation */
#define FF( a, b, c, d, x, s ) { \
    (a) += F( (b), (c), (d) ) + (x); \
    (a) = ROTL( (a), (s) ); \
  }
#define GG( a, b, c, d, x, s ) { \
    (a) += G( (b), (c), (d) ) + (x) + (unsigned int)0x5a827999; \
    (a) = ROTL( (a), (s) ); \
  }
#define HH( a, b, c, d, x, s ) { \
    (a) += H( (b), (c), (d) ) + (x) + (unsigned int)0x6ed9eba1; \
    (a) = ROTL( (a), (s) ); \
  }


static void Transform( unsigned int *state, void *blk ) {
  unsigned int a = state[0];
  unsigned int b = state[1];
  unsigned int c = state[2];
  unsigned int d = state[3];
  unsigned int *x = blk;

  /* Round 1 */
  FF( a, b, c, d, x[ 0], S11 ); /* 1 */
  FF( d, a, b, c, x[ 1], S12 ); /* 2 */
  FF( c, d, a, b, x[ 2], S13 ); /* 3 */
  FF( b, c, d, a, x[ 3], S14 ); /* 4 */
  FF( a, b, c, d, x[ 4], S11 ); /* 5 */
  FF( d, a, b, c, x[ 5], S12 ); /* 6 */
  FF( c, d, a, b, x[ 6], S13 ); /* 7 */
  FF( b, c, d, a, x[ 7], S14 ); /* 8 */
  FF( a, b, c, d, x[ 8], S11 ); /* 9 */
  FF( d, a, b, c, x[ 9], S12 ); /* 10 */
  FF( c, d, a, b, x[10], S13 ); /* 11 */
  FF( b, c, d, a, x[11], S14 ); /* 12 */
  FF( a, b, c, d, x[12], S11 ); /* 13 */
  FF( d, a, b, c, x[13], S12 ); /* 14 */
  FF( c, d, a, b, x[14], S13 ); /* 15 */
  FF( b, c, d, a, x[15], S14 ); /* 16 */

  /* Round 2 */
  GG( a, b, c, d, x[ 0], S21 ); /* 17 */
  GG( d, a, b, c, x[ 4], S22 ); /* 18 */
  GG( c, d, a, b, x[ 8], S23 ); /* 19 */
  GG( b, c, d, a, x[12], S24 ); /* 20 */
  GG( a, b, c, d, x[ 1], S21 ); /* 21 */
  GG( d, a, b, c, x[ 5], S22 ); /* 22 */
  GG( c, d, a, b, x[ 9], S23 ); /* 23 */
  GG( b, c, d, a, x[13], S24 ); /* 24 */
  GG( a, b, c, d, x[ 2], S21 ); /* 25 */
  GG( d, a, b, c, x[ 6], S22 ); /* 26 */
  GG( c, d, a, b, x[10], S23 ); /* 27 */
  GG( b, c, d, a, x[14], S24 ); /* 28 */
  GG( a, b, c, d, x[ 3], S21 ); /* 29 */
  GG( d, a, b, c, x[ 7], S22 ); /* 30 */
  GG( c, d, a, b, x[11], S23 ); /* 31 */
  GG( b, c, d, a, x[15], S24 ); /* 32 */

  /* Round 3 */
  HH( a, b, c, d, x[ 0], S31 ); /* 33 */
  HH( d, a, b, c, x[ 8], S32 ); /* 34 */
  HH( c, d, a, b, x[ 4], S33 ); /* 35 */
  HH( b, c, d, a, x[12], S34 ); /* 36 */
  HH( a, b, c, d, x[ 2], S31 ); /* 37 */
  HH( d, a, b, c, x[10], S32 ); /* 38 */
  HH( c, d, a, b, x[ 6], S33 ); /* 39 */
  HH( b, c, d, a, x[14], S34 ); /* 40 */
  HH( a, b, c, d, x[ 1], S31 ); /* 41 */
  HH( d, a, b, c, x[ 9], S32 ); /* 42 */
  HH( c, d, a, b, x[ 5], S33 ); /* 43 */
  HH( b, c, d, a, x[13], S34 ); /* 44 */
  HH( a, b, c, d, x[ 3], S31 ); /* 45 */
  HH( d, a, b, c, x[11], S32 ); /* 46 */
  HH( c, d, a, b, x[ 7], S33 ); /* 47 */
  HH( b, c, d, a, x[15], S34 ); /* 48 */

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
}


void MD4Init( ctx_t *ctx ) {
  ctx->cnt = 0;

  ctx->st[0] = 0x67452301;
  ctx->st[1] = 0xefcdab89;
  ctx->st[2] = 0x98badcfe;
  ctx->st[3] = 0x10325476;

  ctx-> idx = 0;
}


void MD4Update( ctx_t *ctx, unsigned char *in, unsigned int len ) {
  unsigned int i, idx, free;

  ctx->cnt += 8 * len;
  idx = ctx->idx;
  free = 64 - idx;

  if ( len >= free ) {
    memcpy( &ctx->buf[idx], in, free );
    Transform( ctx->st, ctx->buf );
    for ( i = free; i + 63 < len; i += 64 ) Transform( ctx->st, &in[i] );
    idx = 0;
  } else {
    i = 0;
  };

  memcpy( &ctx->buf[idx], &in[i], len-i );
  ctx->idx = idx + len - i;
}


void MD4Final( unsigned char *digest, ctx_t *ctx ) {
  unsigned char bits[8];
  unsigned int idx, len;

  memcpy( bits, &ctx->cnt, 8 );
  idx = ctx->idx;

  if( idx < 56 ) {
    len =  56 - idx;
  } else {
    len = 120 - idx;
  }
  MD4Update( ctx, PADDING, len );
  MD4Update( ctx, bits, 8 );
  memcpy( digest, ctx->st, 16 );
}
