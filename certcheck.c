#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
int validate(char test_cert_example[],char test_url[]);


int validate(char test_cert[],char test_url[])
{
    BIO *certificate_bio = NULL;
    X509 *cert = NULL;
    X509_NAME *cert_subject = NULL;
    X509_CINF *cert_inf = NULL;
	ASN1_TIME *cert_notbefore = NULL;
	ASN1_TIME *cert_notafter = NULL;
	EVP_PKEY *cert_key = NULL;
	RSA *cert_rsa = NULL;
	int day, sec, length;
    STACK_OF(X509_EXTENSION) * ext_list;
	int name_flag = 0;
	
    //initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    //create BIO object to read certificate
    certificate_bio = BIO_new(BIO_s_file());

    //Read certificate into BIO
    if (!(BIO_read_filename(certificate_bio, test_cert)))
    {
        fprintf(stderr, "Error in reading cert BIO filename");
        exit(EXIT_FAILURE);
    }
    if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL)))
    {
        fprintf(stderr, "Error in loading certificate");
        exit(EXIT_FAILURE);
    }

    //cert contains the x509 certificate and can be used to analyse the certificate

	//check comman name
    cert_subject = X509_get_subject_name(cert);
    char subject_cn[256] = "Subject CN NOT FOUND";
    X509_NAME_get_text_by_NID(cert_subject, NID_commonName, subject_cn, 256);
	if(subject_cn[0]=='*'){
		if(strstr(test_url,subject_cn+1)!=NULL){
			name_flag = 1;
		}
	}
	else{
		if(strcmp(test_url,subject_cn)==0){
			name_flag = 1;
		}
	}
	
	//validation of dates
	cert_notbefore = X509_get_notBefore(cert);
	cert_notafter = X509_get_notAfter(cert);
	ASN1_TIME_diff(&day, &sec, cert_notbefore, NULL);
	if(day+sec<0){
		X509_free(cert);
		BIO_free_all(certificate_bio);
		return(0);
	}
	ASN1_TIME_diff(&day, &sec, NULL, cert_notafter);
	if(day+sec<0){
		X509_free(cert);
		BIO_free_all(certificate_bio);
		return(0);
	}
	
	//check minimum RSA key length
	cert_key = X509_get_pubkey(cert);
	cert_rsa = EVP_PKEY_get1_RSA(cert_key);
	length = RSA_size(cert_rsa);
	if(length*8<2048){
		RSA_free(cert_rsa);
		X509_free(cert);
		BIO_free_all(certificate_bio);
		return(0);
	}
	RSA_free(cert_rsa);

    //check Enhanced Key Usage
    X509_EXTENSION *ex = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_ext_key_usage, -1));
	if(ex){
    BUF_MEM *bptr = NULL;
    char *buf = NULL;
    BIO *bio = BIO_new(BIO_s_mem());
    if (!X509V3_EXT_print(bio, ex, 0, 0))
    {
        fprintf(stderr, "Error in reading extensions");
    }
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);
    buf = (char *)malloc((bptr->length + 1) * sizeof(char));
    memcpy(buf, bptr->data, bptr->length);
    buf[bptr->length] = '\0';
	if(strstr(buf,"TLS Web Server Authentication")==NULL) {
		free(buf);
		BIO_free_all(bio);
		X509_free(cert);
		BIO_free_all(certificate_bio);
		return(0);
	}
	free(buf);
	BIO_free_all(bio);
	}
	
	//check Basic Constraints
	X509_EXTENSION *ex_two = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_basic_constraints, -1));
	if(ex_two){
	BUF_MEM *bptr_two = NULL;
    char *buf_two = NULL;
    BIO *bio_two = BIO_new(BIO_s_mem());
    if (!X509V3_EXT_print(bio_two, ex_two, 0, 0))
    {
        fprintf(stderr, "Error in reading extensions");
    }
	BIO_flush(bio_two);
    BIO_get_mem_ptr(bio_two, &bptr_two);
    buf_two = (char *)malloc((bptr_two->length + 1) * sizeof(char));
    memcpy(buf_two, bptr_two->data, bptr_two->length);
    buf_two[bptr_two->length] = '\0';
	if(strstr(buf_two,"CA:FALSE")==NULL) {
		free(buf_two);
		BIO_free_all(bio_two);
		X509_free(cert);
		BIO_free_all(certificate_bio);
		return(0);
	}
	free(buf_two);
	BIO_free_all(bio_two);
	}
	
	//check Subject Alternative Name
	X509_EXTENSION *ex_three = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_subject_alt_name, -1));
	if(ex_three){
	BUF_MEM *bptr_three = NULL;
    char *buf_three = NULL;
	char* dns = NULL;
    BIO *bio_three = BIO_new(BIO_s_mem());
    if (!X509V3_EXT_print(bio_three, ex_three, 0, 0))
    {
        fprintf(stderr, "Error in reading extensions");
    }
	BIO_flush(bio_three);
    BIO_get_mem_ptr(bio_three, &bptr_three);
    buf_three = (char *)malloc((bptr_three->length + 1) * sizeof(char));
    memcpy(buf_three, bptr_three->data, bptr_three->length);
    buf_three[bptr_three->length] = '\0';
	char *bufcopy = (char*) calloc(strlen(buf_three)+1, sizeof(char));
	strncpy(bufcopy, buf_three, strlen(buf_three));
	dns = strtok(bufcopy,", DNS:");
	while(dns != NULL){
		if(dns[0]=='*'){
			if(strstr(test_url,dns+1)!=NULL){
				name_flag = 1;
			}
		}
		else{
			if(strcmp(test_url,dns)==0){
				name_flag = 1;
			}
		}
        dns = strtok(NULL,", DNS:");
	}
	free(bufcopy);
	free(buf_three);
	BIO_free_all(bio_three);
	}
    X509_free(cert);
    BIO_free_all(certificate_bio);
	return(name_flag);
}

int main( int argc, char *argv[] ){
	if(argc==2){
		FILE* stream = fopen(argv[1], "r");
		FILE* fp=fopen("output.csv","w");
		char filename[1024];
		char path[1024];
		while(!feof(stream)){
			fscanf(stream,"%[^,],%s\n",filename,path);
			fprintf(fp,"%s,%s,%d\n",filename,path,validate(filename,path));
		}
		fclose(stream);
		fclose(fp);
	}
	return(0);
}