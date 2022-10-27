#include "../api.h"
#include "../poly.h"
#include "../rng.h"
#include "../SABER_indcpa.h"
#include "../verify.h"
#include "../pack_unpack.h"
#include<stdio.h>
#include<stdint.h>
#include<string.h>
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>


static int test_pke_cpa()
{
    //key mismatch attack on Firesaber
    // parameters: res: b'
    //          vprime: cm
    //            ss_a: message
    //	         query: count the total queries
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];	
    uint8_t ss_a[CRYPTO_BYTES];
    uint16_t res[SABER_L][SABER_N];
    int sk_hat[SABER_L][SABER_N];
    uint16_t vprime[SABER_N];
    uint16_t sksv[SABER_L][SABER_N]; //secret key of the server
    int query=0;
    unsigned char entropy_input[48];
    int i,j,k;
    for (i=0; i<48; i++){
	srand((unsigned)time(NULL));
    	entropy_input[i] = rand()%256;
        //entropy_input[i] = i;
    }
    randombytes_init(entropy_input, NULL, 256);
    //Generation of secret key sk and public key pk pair
	crypto_kem_keypair(pk, sk);
    BS2POLVECq(sk, sksv); //sksv is the secret-key

    //printf("num = %d %d %d %d %d %d %d\n",num0,num1,num2,num3,num_1,num_2,num_3);
    for(i=0;i<SABER_L;i++){
    	memset(ss_a,0,sizeof(ss_a));
    	ss_a[0] = 1;
    	memset(vprime,0,sizeof(vprime));
    	for(k=0;k<SABER_N;k++){
    		memset(res,0,sizeof(res));
    		if(k == 0){
    			res[i][k] = 115;
    		}
    		else{
    			res[i][SABER_N-k] = -115;
    		}
    		POLVECp2BS(ct, res);
    		vprime[0]=1;
    		POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
    		if(oracle(ct,sk,i,k) == 0){
			query ++;
    			if(k == 0){
	    			res[i][k] = 80;
	    		}
	    		else{
	    			res[i][SABER_N-k] = -80;
	    		}
	    		POLVECp2BS(ct, res);
	    		vprime[0]=6;
	    		POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
			if(oracle(ct,sk,i,k) == 0){
				query ++;
				sk_hat[i][k] = 0;
			}
			else {
				query ++;
				if(k == 0){
		    			res[i][k] = 50;
		    		}
		    		else{
		    			res[i][SABER_N-k] = -50;
		    		}
		    		POLVECp2BS(ct, res);
		    		vprime[0]=6;
		    		POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
				if(oracle(ct,sk,i,k) == 0){
					query ++;
					sk_hat[i][k] = 1;
				}
				else {
					query ++;
					if(k == 0){
			    			res[i][k] = 20;
			    		}
			    		else{
			    			res[i][SABER_N-k] = -20;
			    		}
			    		POLVECp2BS(ct, res);
			    		vprime[0]=6;
			    		POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
					if(oracle(ct,sk,i,k) == 0){
						query ++;
						sk_hat[i][k] = 2;
					}
					else {
						query ++;
						sk_hat[i][k] = 3;
					}
				}
			}
    		}
    		else {
    			query ++;
			if(k == 0){
	    			res[i][k] = 100;
	    		}
	    		else{
	    			res[i][SABER_N-k] = -100;
	    		}
	    		POLVECp2BS(ct, res);
	    		vprime[0]=0;
	    		POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
			if(oracle(ct,sk,i,k) == 0){
				query ++;
				sk_hat[i][k] = -1;
			}
			else {
				query ++;
				if(k == 0){
		    			res[i][k] = 110;
		    		}
		    		else{
		    			res[i][SABER_N-k] = -110;
		    		}
		    		POLVECp2BS(ct, res);
		    		vprime[0]=7;
		    		POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
				if(oracle(ct,sk,i,k) == 0){
					query ++;
					sk_hat[i][k] = -2;
				}
				else {
					query ++;
					if(k == 0){
			    			res[i][k] = 90;
			    		}
			    		else{
			    			res[i][SABER_N-k] = -90;
			    		}
			    		POLVECp2BS(ct, res);
			    		vprime[0]=7;
			    		POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
					if(oracle(ct,sk,i,k) == 0){
						query ++;
						sk_hat[i][k] = -3;
					}
					else {
						query ++;
						if(k == 0){
				    			res[i][k] = 190;
				    		}
				    		else{
				    			res[i][SABER_N-k] = -190;
				    		}
				    		POLVECp2BS(ct, res);
				    		vprime[0]=4;
				    		POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
						if(oracle(ct,sk,i,k) == 0){
							query ++;
							sk_hat[i][k] = 4;
						}
						else {
							query ++;
							if(k == 0){
					    			res[i][k] = 70;
					    		}
					    		else{
					    			res[i][SABER_N-k] = -70;
					    		}
					    		POLVECp2BS(ct, res);
					    		vprime[0]=7;
					    		POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
							if(oracle(ct,sk,i,k) == 0){
								query ++;
								sk_hat[i][k] = -4;					
							}
							else {
								query ++;
								if(k == 0){
						    			res[i][k] = 20;
						    		}
						    		else{
						    			res[i][SABER_N-k] = -20;
						    		}
						    		POLVECp2BS(ct, res);
						    		vprime[0]=1;
						    		POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
								if(oracle(ct,sk,i,k) == 0){
									query ++;
									sk_hat[i][k] = 5;
								}
								else {
									query ++;
									sk_hat[i][k] = -5;
								}
							}
						}
					}
				}
			}
    		}
    	}
    }
   int sum = 0;
   for(i=0;i<SABER_L;i++)
   {
	for(j=0;j<SABER_N;j++)
	{
		//printf("sk[%d][%d]:%d sk_hat[%d][%d]:%d\n",i,j,sksv[i][j],i,j,sk_hat[i][j]);
        	if(sksv[i][j]!=sk_hat[i][j] && sksv[i][j]-sk_hat[i][j] != 8192)
		{
			//printf("sk[%d][%d]:%d sk_hat[%d][%d]:%d\n",i,j,sksv[i][j],i,j,sk_hat[i][j]);
			sum ++;
		}
	}
   }
   if(sum != 0)
   printf("Sum = %d \n",sum);
   return query;
}

int main()
{
    // calculate the average time and average queries of 10000 times  
    int count,query=0;
    for(count=0;count<10000;count++)
	{ 
		query+=test_pke_cpa();
	}
    printf("Query = %lf\n",query/10000.0);
	return 0;
} 


