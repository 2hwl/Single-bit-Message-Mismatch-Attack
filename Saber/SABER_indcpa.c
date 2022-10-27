#include <string.h>
#include <stdint.h>
#include "SABER_indcpa.h"
#include "poly.h"
#include "pack_unpack.h"
#include "poly_mul.c"
#include "rng.h"
#include "fips202.h"
#include "SABER_params.h"

#define h1 (1 << (SABER_EQ - SABER_EP - 1))
#define h2 ((1 << (SABER_EP - 2)) - (1 << (SABER_EP - SABER_ET - 1)) + (1 << (SABER_EQ - SABER_EP - 1)))

void indcpa_kem_keypair(uint8_t pk[SABER_INDCPA_PUBLICKEYBYTES], uint8_t sk[SABER_INDCPA_SECRETKEYBYTES])
{
	uint16_t A[SABER_L][SABER_L][SABER_N];
	uint16_t s[SABER_L][SABER_N];
	uint16_t b[SABER_L][SABER_N] = {0};

	uint8_t seed_A[SABER_SEEDBYTES];
	uint8_t seed_s[SABER_NOISE_SEEDBYTES];
	int i, j;

	randombytes(seed_A, SABER_SEEDBYTES);
	shake128(seed_A, SABER_SEEDBYTES, seed_A, SABER_SEEDBYTES); // for not revealing system RNG state
	randombytes(seed_s, SABER_NOISE_SEEDBYTES);

	GenMatrix(A, seed_A);
	GenSecret(s, seed_s);
	MatrixVectorMul(A, s, b, 1);

	for (i = 0; i < SABER_L; i++)
	{
		for (j = 0; j < SABER_N; j++)
		{
			b[i][j] = (b[i][j] + h1) >> (SABER_EQ - SABER_EP);
		}
	}

	POLVECq2BS(sk, s);
	POLVECp2BS(pk, b);
	memcpy(pk + SABER_POLYVECCOMPRESSEDBYTES, seed_A, sizeof(seed_A));
}

void indcpa_kem_enc(const uint8_t m[SABER_KEYBYTES], const uint8_t seed_sp[SABER_NOISE_SEEDBYTES], const uint8_t pk[SABER_INDCPA_PUBLICKEYBYTES], uint8_t ciphertext[SABER_BYTES_CCA_DEC])
{
	uint16_t A[SABER_L][SABER_L][SABER_N];
	uint16_t sp[SABER_L][SABER_N];
	uint16_t bp[SABER_L][SABER_N] = {0};
	uint16_t vp[SABER_N] = {0};
	uint16_t mp[SABER_N];
	uint16_t b[SABER_L][SABER_N];
	int i, j;
	const uint8_t *seed_A = pk + SABER_POLYVECCOMPRESSEDBYTES;

	GenMatrix(A, seed_A);
	GenSecret(sp, seed_sp);
	MatrixVectorMul(A, sp, bp, 0);

	for (i = 0; i < SABER_L; i++)
	{
		for (j = 0; j < SABER_N; j++)
		{
			bp[i][j] = (bp[i][j] + h1) >> (SABER_EQ - SABER_EP);
		}
	}

	POLVECp2BS(ciphertext, bp);
	BS2POLVECp(pk, b);
	InnerProd(b, sp, vp);

	BS2POLmsg(m, mp);
	
	

	for (j = 0; j < SABER_N; j++)
	{
		vp[j] = ((vp[j] - (mp[j] << (SABER_EP - 1)) + h1)%1024) >> (SABER_EP - SABER_ET);
	}
	
	printf("Vp_enc = \n");
	for(int kk=0;kk<SABER_N;kk++){
		printf("%d ",vp[kk]);
	}
	printf("\n");

	POLT2BS(ciphertext + SABER_POLYVECCOMPRESSEDBYTES, vp);
}

void indcpa_kem_dec(const uint8_t sk[SABER_INDCPA_SECRETKEYBYTES], const uint8_t ciphertext[SABER_BYTES_CCA_DEC], uint8_t m[SABER_KEYBYTES])
{

	uint16_t s[SABER_L][SABER_N];
	uint16_t b[SABER_L][SABER_N];
	uint16_t v[SABER_N] = {0};
	uint16_t cm[SABER_N];
	int i;

	BS2POLVECq(sk, s);
	
	printf("sk = \n");
	for(int kk=0;kk<SABER_L;kk++){
		for(int jj=0;jj<SABER_N;jj++){
			printf("%d ",	s[kk][jj]);	
		}
		printf("\n");
	}
	BS2POLVECp(ciphertext, b);
	InnerProd(b, s, v);
	BS2POLT(ciphertext + SABER_POLYVECCOMPRESSEDBYTES, cm);

	printf("Vp_dec = \n");
	for(int kk=0;kk<SABER_N;kk++){
		printf("%d ",cm[kk]);
	}
	printf("\n");



	for (i = 0; i < SABER_N; i++)
	{
		v[i] = ((v[i] + h2 - (cm[i] << (SABER_EP - SABER_ET))) % 1024) >> (SABER_EP - 1);
	}
	
	
	POLmsg2BS(m, v);
}
int oracle(const uint8_t ciphertext[SABER_BYTES_CCA_DEC], const uint8_t sk[SABER_INDCPA_SECRETKEYBYTES],int i,int k)
{
	uint16_t s[SABER_L][SABER_N];
	uint16_t b[SABER_L][SABER_N];
	// uint16_t v[SABER_N] = { 0 };
	uint16_t cm[SABER_N];
	BS2POLVECq(sk, s);
	/*printf("Sk = ");
	
//s[0][0] = -1;
	printf("Sk2 = ");
	for(int i=0;i<SABER_L;i++){
		for(int j=0;j<SABER_N;j++){
			if(s[i][j]>8000) s[i][j] -= 8192;
			printf("%d ",s[i][j]);
		}
	}
	printf("\n\n");*/
	BS2POLVECp(ciphertext, b);
//printf("B = ");
	/*for(int i=0;i<SABER_L;i++){
		for(int j=0;j<SABER_N;j++){
			printf("%d ",b[i][j]);
		}
printf("\n");
	}*/
	if(k!=0) b[i][(256-k)%256] = 1024 - b[i][(256-k)%256];
	//printf("%d ",b[i][(256-k)%256]);
	//printf("\n\n");
	//InnerProd(b, s, v);
	int SKK = s[i][k];
	if(SKK > 8000) SKK -= 8192;
	int v0 = b[i][(256-k)%256]*SKK;
//printf("sk = %d ,b = %d ,v0 = %d \n",SKK, b[i][(256-k)%256], v0);
	BS2POLT(ciphertext + SABER_POLYVECCOMPRESSEDBYTES, cm);
	/*if(v[0] > 10000){
		v[0] -= 65536;	
	}*/
	//printf("V[0] = %d\n",v[0]);
	int m = ((v0 + 2048 + h2 - (cm[0] << (SABER_EP - SABER_ET))) % 1024) >> (SABER_EP - 1);
	if (m == 1) return 1;
	else return 0;

}
