#include <iostream>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <OpenSSL/aes.h>
#include <openssl/rand.h>

std::string testkey = "-----BEGIN PRIVATE KEY-----\n\
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAL+MHIYm2eWYZ0eS\n\
I0xsPCzKLAxNQ5QfzQNG1+zHOSRo2EwJWk/faXwJz/r8+EXiqC7m8MVW7ptlh6mV\n\
Mn3G0fBmgwJHyjNEwEytn8QlVLTcEF3KFUml/dwPJ4JJXGORtxKsiS7GJKotLvzt\n\
zg0blXfaVPR7+tOFIZunX5dd1o3LAgMBAAECgYBLObFyFgv5GVNmTkRCnTc8t+F4\n\
q1dg8uRG5ymhudP9MpfPtNSdDbaVmhzuCy9N8ufuE5B3T97BdKxEs21y7ARCYDoE\n\
wHH5dxFGdzO9DPf5w6WuN7C+TSeaCanU+sWQOXXB3xGDHBkSJiLGOTFUsvfmLDlJ\n\
0kQfu8k4br7z793yEQJBAPk136gzjcG7ks5AeQ6sQXdXGuLPFWmqm9oWxzngdUBs\n\
LjQmm9ShLwlDLckLsIcXrl2mIiQEXpk5d6lTLx1rt30CQQDExBB6APlou5XDLqIS\n\
kd18PhEZIsZtuEtQlA5s0MiXNz68Q+rfkYrxbJJKvSuzVs5HrI2tnxuLUWQbapKi\n\
jKznAkEAp3ZbR8T04hVwriZG8uQvzcj7qSOs6OebeS7LS4oYYGURmzvChVyWpeu9\n\
rZasVetE4WtND9Tb2Kz0SxU52NRUZQJBAJIsTUk1XBMv96vOAtzku7NGsJEJwntU\n\
A69SrfyshbfAdLyLf/qiNqPvUiZvrf1GqWuZho7Kuj2fM00iuNhExVUCQD9DdkqF\n\
o1Yt4k8TOn4EEQMqWhs9w2fte3dzU6hUyZDvLwLkdTSC9+4rnUUadh23SLu538gq\n\
AKyo2tUiASVge5g=\n\
-----END PRIVATE KEY-----";

void print(const ASN1_INTEGER* str, const char* item)
{
	printf( "uint8_t key_%s[] = \r\n", item);
	for (int i = 0; i < str->length; ++i) {
		if(i%16 == 0 && i != 0)
			printf("\r\n");
		if(i==0)
			printf("{ 0x%02X, ", str->data[i]);
		else if(i+1 == str->length)
			printf("0x%02X };", str->data[i]);
		else
			printf("0x%02X, ", str->data[i]);
	}
	printf( "\r\n");
}
int PrintRSAKey(std::string prikey)
{
	BIO* in = BIO_new_mem_buf((void*)prikey.c_str(), -1);
	if (in == NULL) {
		std::cout << "BIO_new_mem_buf failed" << std::endl;
		return -1;
	}

	RSA* rsa = PEM_read_bio_RSAPrivateKey(in, NULL, NULL, NULL);
	BIO_free(in);
	if (rsa == NULL) {
		std::cout << "PEM_read_bio_RSAPrivateKey failed" << std::endl;
		return -1;
	}
	int nlen = RSA_size(rsa);

	ASN1_INTEGER* n = BN_to_ASN1_INTEGER(RSA_get0_n(rsa), nullptr); // modulus
	ASN1_INTEGER* e = BN_to_ASN1_INTEGER(RSA_get0_e(rsa), nullptr); // public exponent
	ASN1_INTEGER* d = BN_to_ASN1_INTEGER(RSA_get0_d(rsa), nullptr); // private exponent
	ASN1_INTEGER* p = BN_to_ASN1_INTEGER(RSA_get0_p(rsa), nullptr); // prime 1
	ASN1_INTEGER* q = BN_to_ASN1_INTEGER(RSA_get0_q(rsa), nullptr); // prime 2
	ASN1_INTEGER* dmp1 = BN_to_ASN1_INTEGER(RSA_get0_dmp1(rsa), nullptr); // exponent 1
	ASN1_INTEGER* dmq1 = BN_to_ASN1_INTEGER(RSA_get0_dmq1(rsa), nullptr); // exponent 2
	ASN1_INTEGER* iqmp = BN_to_ASN1_INTEGER(RSA_get0_iqmp(rsa), nullptr); // coefficient
	if (!n || !e || !d || !p || !q || !dmp1 || !dmq1 || !iqmp) {
		fprintf(stderr, "fail to BN_to_ASN1_INTEGER\n");
		return -1;
	}
	print(n, "m");
	print(e, "e");
	print(d, "pe");
	print(p, "p1");
	print(q, "p2");
	print(dmp1, "e1");
	print(dmq1, "e2");
	print(iqmp, "c");

	ASN1_INTEGER_free(n);
	ASN1_INTEGER_free(e);
	ASN1_INTEGER_free(d);
	ASN1_INTEGER_free(p);
	ASN1_INTEGER_free(q);
	ASN1_INTEGER_free(dmp1);
	ASN1_INTEGER_free(dmq1);
	ASN1_INTEGER_free(iqmp);
	RSA_free(rsa);
	
	return nlen;
}
int main( )
{
	PrintRSAKey(testkey);
	system("pause");

   // std::cout << "Hello World!\n";
}
