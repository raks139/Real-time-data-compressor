
/*********************************************************/
/***************** Program flow ****************/

/*
    This prgram first reads a text file in main().
    This text file is stored in an unsigned char buffer which is sent as an argument to top_function().
    The top_function() calls cdc().
    cdc() reads te file, and calculates a rolling hash over the data.
    It checks during hashing if a specific condition is matched.
    When the condition is matched, it defines chunk boundary.
    SHA256 hash of the chunk is calculated and is checked with the past hash values.
    If the exact same hash value is found previously, then the index of that chunk is written into a 32 bit header.
    If the chunk is never seen before, it is sent to lzw_encoding algorithm.
*/


/*********************************************************/


/*********************************************************/
/***************** DEFINITIONS AND MACROS ****************/


#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <iostream>
#include <stdint.h>
#include <math.h>
#include <functional>
#include <map>
#include <unordered_map>

#include <thread>
#include <fstream>

#include "encoder.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include "server.h"
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "stopwatch.h"

#define CDC_WIN_SIZE 16
#define CDC_PRIME 3
#define CDC_MODULUS 256
#define CDC_TARGET 0

#define CODE_LENGTH 13

#define MIN_CHUNK_SIZE 2048
#define uchar unsigned char
#define uint unsigned int

#define DBL_INT_ADD(a,b,c) if (a > 0xffffffff - (c)) ++b; a += c;
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))
/*********************************************************/

#define NUM_PACKETS 8
#define pipe_depth 4
#define DONE_BIT_L (1 << 7)
#define DONE_BIT_H (1 << 15)

/********************************************************* /
/***************** FUNCTION DECLARATIONS ****************/

void top_function_packet(unsigned char* buf, int buf_len);
void top_function_pp(unsigned char* buff, unsigned int buff_size, int core_num);
uint64_t hash_func(unsigned char* input, unsigned int pos, int core_num);
void print_chunk(unsigned char* data, int len);
void pin_thread_to_cpu(std::thread& t, int cpu_num);
void SHA256(unsigned char* data, int len, std::string &str); 
void to_code_len(uint16_t num, unsigned char* op, int core_num);
void print_chunk(unsigned char* data, int len);
void HadHash_Val(std::string hash, int &status );
void encoding(unsigned char* ip, int len, int core_num);
void cdc_pp(unsigned char* buff, int start, unsigned int buff_size, int core_num, int* chunk_bound,int* num);
void sha( int start,int end,int *chunk_bound_1,unsigned char* buff,unsigned int buff_size,int core_num);
void lzw(int start,int end,int *chunk_bound_1,std::vector<std::string>hash_vec,unsigned char* buff,unsigned int buff_size,int core_num);    
void pipeline_lzw(int status,unsigned char* buff,int prev_val,std::string ss, int len, int core_num);
void core_1_process(int prev_val,unsigned char* buff,int len,std::string &ss,int &status);
void core_0_process(int chunk_no, int num_chunks, int prev_val,unsigned char* buff,int len, int core_num);
/*********************************************************/

/*********************************************************/
/***************** STRUCT DECLARATIONS ****************/

typedef struct {
    uint chunk_start_idx;
    uint chunk_len;
    std::string chunk_hash;
} chunk;

typedef struct {
    uchar data[64];
    uint datalen;
    uint bitlen[2];
    uint state[8];
} SHA256_CTX;

/*********************************************************/

/*********************************************************/
/***************** GLOBAL VARIABLES ****************/

uint64_t hash_val[4]={0};
std::unordered_map<std::string, int> hash_map;
int hash_map_count = 0;

uint16_t to_cl_written[4];  //={0}; // = 0;
uint16_t to_cl_to_be_written[4];   // = CODE_LENGTH;
uint16_t to_cl_capacity[4];  //={8,8,8,8}; // = 8;
uint16_t to_cl_idx[4];  //={0};// = 0;  //initializing the index to 4 as the 1st 4 bytes will be used to write the header
int chunk_number = 0;

std::ofstream outfile;

int offset = 0;
unsigned char* file;
stopwatch cdc_timer;
stopwatch sha_timer;
stopwatch lzw_timer;
stopwatch dedup_timer;
stopwatch sha_init_timer;
stopwatch sha_update_timer;
stopwatch sha_final_timer;
/*********************************************************/

void pin_thread_to_cpu(std::thread& t, int cpu_num)
{
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__) || defined(__APPLE__)
    return;
#else
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_num, &cpuset);
    int rc =
        pthread_setaffinity_np(t.native_handle(), sizeof(cpu_set_t), &cpuset);
    if (rc != 0)
    {
        std::cerr << "Error calling pthread_setaffinity_np: " << rc << "\n";
    }
#endif
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void top_function_packet(unsigned char* buf, int buf_len) {
    top_function_pp(buf, buf_len,0);
}


void to_code_len(uint16_t num, unsigned char* op, int core_num) {

    to_cl_to_be_written[core_num] = CODE_LENGTH;
    unsigned char temp;

    while (to_cl_to_be_written[core_num] != 0) {

        if (to_cl_to_be_written[core_num] >= 8) {

            temp = num >> (to_cl_to_be_written[core_num] - to_cl_capacity[core_num]);
            op[to_cl_idx[core_num]] |= temp;

            to_cl_written[core_num] = to_cl_capacity[core_num];
            to_cl_to_be_written[core_num] = to_cl_to_be_written[core_num] - to_cl_written[core_num];
            to_cl_capacity[core_num] = to_cl_capacity[core_num] - to_cl_written[core_num];

            if (to_cl_capacity[core_num] <= 0) { to_cl_idx[core_num]++; to_cl_capacity[core_num] = 8; }

        }

        if (to_cl_to_be_written[core_num] < 8) {

            temp = num << (8 - to_cl_to_be_written[core_num]);
            op[to_cl_idx[core_num]] |= temp;

            to_cl_written[core_num] = to_cl_to_be_written[core_num];
            to_cl_capacity[core_num] = 8 - to_cl_written[core_num];
            to_cl_to_be_written[core_num] = 0;

            if (to_cl_capacity[core_num] <= 0) { to_cl_idx[core_num]++; to_cl_capacity[core_num] = 8; }

        }

    }

}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void add_header_and_write(unsigned int flag, uint32_t idx, unsigned char* op, unsigned int len) {

    // if flag = 1; it means that the chunk is duplicate
    // idx is the index where the chunk was seen before

    //otherwise the flag = 0 and char *op is the buffer from where the data is to be written to the file
    //and len is the length of the data in the buffer

    if (flag == 1) {
        //is a duplicate chunk
        // write 1 to bit 0
        //bit 31-0 are used for index

        if (idx >= pow(2, 31)) {
            std::perror("Index bigger than 2^31 and cant be fit in 31 bits.");
        }

        else {
            uint32_t head = 1;
            uint32_t index = idx << 1;
            uint32_t final = head | index;

            unsigned char send_1 = final >> 24;
            unsigned char send_2 = final >> 16;
            unsigned char send_3 = final >> 8;
            unsigned char send_4 = final;

            outfile << send_4;
            outfile << send_3;
            outfile << send_2;
            outfile << send_1;
        }


    }

    else if (flag == 0) {

        unsigned int times; // = unsigned int(ceil((CODE_LENGTH * len) / 8)) + 1;

        if (CODE_LENGTH * len % 8 == 0) {
            times = CODE_LENGTH * len / 8;
        }
        else {
            times = CODE_LENGTH * len / 8 + 1;
        }

        unsigned char* tempp = (unsigned char*)malloc(times * sizeof(unsigned char));

        for (unsigned int i = 0; i < (times);i++) {
            tempp[i] = op[i];
        }

        uint32_t head = 0;
        uint32_t length = times << 1;
        uint32_t final = head | length;

        unsigned char send_1 = final >> 24;
        unsigned char send_2 = final >> 16;
        unsigned char send_3 = final >> 8;
        unsigned char send_4 = final;

        outfile << send_4;
        outfile << send_3;
        outfile << send_2;
        outfile << send_1;
    

        for (int idx = 0; idx < times;idx++) {
            outfile << tempp[idx];
        }

        free(tempp);
    }
    return;

}


void encoding(unsigned char* ip, int len, int core_num) {
    lzw_timer.start();

    std::unordered_map<std::string, int> lzw_table;
    int code = 256;

    for (int i = 0; i <= 255; i++) {
        std::string ch = "";
        ch += char(i);
        lzw_table[ch] = i;
    }

    to_cl_written[core_num] = 0;
    to_cl_capacity[core_num] = 8;
    to_cl_idx[core_num] = 0;
    int how_much_written = 0;

    uint32_t size_required; 

    if (CODE_LENGTH * len % 8 == 0) {
        size_required = CODE_LENGTH * len / 8;
    }
    else {
        size_required = (CODE_LENGTH * len / 8) + 1;
    }

    unsigned char* op = (unsigned char*)calloc((size_required), sizeof(unsigned char));

    std::string p = "", c = "";
    p += ip[0];
    int i = 0;

    while (i < len) {


        if (i != len - 1) {
            c += ip[i + 1];
        }

        if (lzw_table.find(p + c) != lzw_table.end()) {
            p = p + c;
        }
        else {
            to_code_len(lzw_table[p], op, core_num);
            how_much_written++;
            lzw_table[p + c] = code;
            code++;
            p = c;
        }
        c = "";
        i++;
    }
    to_code_len(lzw_table[p], op,core_num);
    how_much_written++;
    lzw_timer.stop();
    add_header_and_write(0, 0, op, how_much_written);

    free(op);

    return;

}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

uint64_t hash_func(unsigned char* input, unsigned int pos, int core_num)
{

    // put your hash function implementation here
    if (hash_val[core_num] == 0)
        for (int i = 0;i < CDC_WIN_SIZE;i++)
            hash_val[core_num] += (int)input[pos + CDC_WIN_SIZE - 1 - i] * (pow(CDC_PRIME, i + 1));
    else

        hash_val[core_num] = hash_val[core_num] * CDC_PRIME - input[pos - 1] * pow(CDC_PRIME, CDC_WIN_SIZE + 1) + input[pos - 1 + CDC_WIN_SIZE] * CDC_PRIME;

    return hash_val[core_num];
}


void cdc_pp(unsigned char* buff, int start, unsigned int buff_size, int core_num, int* chunk_bound,int* num)
{
    int ind=0;

    for (int i = start;i < buff_size;i++) {
       if (((hash_func(buff, i, core_num) % CDC_MODULUS)) == CDC_TARGET) 
	    {
            chunk_bound[ind]=i;
            ind++;
        }
    }
    if (chunk_bound[ind-1]!=(buff_size-1)){
	  chunk_bound[ind]=(buff_size-1);
	  ind++;
	}

num[core_num]=ind;
hash_val[core_num]=0;
}

void pipeline_lzw(int status,unsigned char* buff,int prev_val,std::string ss, int len, int core_num)
{
           if (status != -1)
            {
                uint32_t u_status = uint32_t(status); 
                add_header_and_write(1, u_status, NULL, 0);

            }
            else {
                
                hash_map[ss] = hash_map_count;
                hash_map_count++;
                encoding(&buff[prev_val], len, core_num);

            }

}

void core_1_process(int prev_val,unsigned char* buff,int len,std::string &ss,int &status)
{ 
    SHA256(&buff[prev_val], len, ss);
    dedup_timer.start();
    HadHash_Val(ss, status);
    dedup_timer.stop();
}

void core_0_process(int chunk_no, int num_chunks, int prev_val,unsigned char* buff,int len, int core_num)
{ int status;
  static int status_in;
  static int prev_val_in;
  static int len_in;
  std::string ss = "";
  static std::string ss_in; 
  std::thread core_1_thread;
  if (chunk_no < num_chunks)
  {
    core_1_thread = std::thread(&core_1_process,prev_val,buff,len,std::ref(ss),std::ref(status));
    pin_thread_to_cpu(core_1_thread, 1);
  }

  if (chunk_no > 0) // skips Frame==0
  {
    pipeline_lzw(status_in,buff,prev_val_in,ss_in,len_in,core_num);
  }

  if (chunk_no < num_chunks)
  {
    core_1_thread.join();
  }

  int temp_stat = status;
  status = status_in;
  status_in = temp_stat;

  int temp_prev_val = prev_val;
  prev_val = prev_val_in;
  prev_val_in = temp_prev_val;

  int temp_len = len;
  len = len_in;
  len_in = temp_len;
  
  std::string temp_ss = ss;
  ss = ss_in;
  ss_in = temp_ss;
}


void sha_plus_lzw( int start,int end,int *chunk_bound_1,unsigned char* buff,unsigned int buff_size,int core_num)
{
    
    int prev_val=0;
    uint32_t len;
    int status;
    for (int i=start;i<=end+1;i++)
    {
            if (i==0)
                len=chunk_bound_1[i];
            else if (i==end)
		        len=chunk_bound_1[i] - chunk_bound_1[i-1]+1;
            else if (i==end+1)
		        len=1;
	        else
                len=chunk_bound_1[i]-chunk_bound_1[i-1];
            
            std::string ss = "";
    	    core_0_process(i,end+1,prev_val,buff,len,core_num);

            prev_val = chunk_bound_1[i];
    }

   hash_val[core_num]=0;
}


void top_function_pp(unsigned char* buff, unsigned int buff_size, int core_num)
{
    outfile.open("output_file.bin", std::ios_base::binary | std::ios_base::app);
    unsigned int prev_val = 0;
    int num_chunks;
    int chunk_bound_1[PAYLOAD_SIZE]; 
    cdc_timer.start();
    cdc_pp(buff,0,(unsigned int)buff_size,core_num,chunk_bound_1,&num_chunks);
    cdc_timer.stop();
    sha_plus_lzw(0,num_chunks-1,chunk_bound_1,buff,buff_size,core_num);
    outfile.close();
}

/***************************************************************************************************/


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


void print_chunk(unsigned char* data, int len) {
    for (int i = 0; i < len; i++) { 
        std::cout << data[i];
    }
}

void HadHash_Val(std::string hash, int &status) {
    if (hash_map.find(hash) != hash_map.end()) {
        status=hash_map[hash];
    }
    else status = -1;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

uint k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void SHA256Transform(SHA256_CTX* ctx, uchar data[])
{
    uint a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for (; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void SHA256Init(SHA256_CTX* ctx)
{
    ctx->datalen = 0;
    ctx->bitlen[0] = 0;
    ctx->bitlen[1] = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

void SHA256Update(SHA256_CTX* ctx, uchar data[], uint len)
{
    for (uint i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            SHA256Transform(ctx, ctx->data);
            DBL_INT_ADD(ctx->bitlen[0], ctx->bitlen[1], 512);
            ctx->datalen = 0;
        }
    }
}

void SHA256Final(SHA256_CTX* ctx, uchar hash[])
{
    uint i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;

        while (i < 56)
            ctx->data[i++] = 0x00;
    }
    else {
        ctx->data[i++] = 0x80;

        while (i < 64)
            ctx->data[i++] = 0x00;

        SHA256Transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    DBL_INT_ADD(ctx->bitlen[0], ctx->bitlen[1], ctx->datalen * 8);
    ctx->data[63] = ctx->bitlen[0];
    ctx->data[62] = ctx->bitlen[0] >> 8;
    ctx->data[61] = ctx->bitlen[0] >> 16;
    ctx->data[60] = ctx->bitlen[0] >> 24;
    ctx->data[59] = ctx->bitlen[1];
    ctx->data[58] = ctx->bitlen[1] >> 8;
    ctx->data[57] = ctx->bitlen[1] >> 16;
    ctx->data[56] = ctx->bitlen[1] >> 24;
    SHA256Transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
}

void SHA256(unsigned char* data, int len, std::string &str) {
	int strLen = len;
	SHA256_CTX ctx;
	unsigned char hash[32];
    char s[3];

    sha_init_timer.start();
	SHA256Init(&ctx);
	sha_init_timer.stop();

    sha_update_timer.start();
    SHA256Update(&ctx, (unsigned char*)data, strLen);
    sha_update_timer.stop();
    
    sha_final_timer.start();
	SHA256Final(&ctx, hash);
    sha_final_timer.stop();
	
	for (int i = 0; i < 32; i++) {
		sprintf(s, "%02x", hash[i]);
		str += s;
	}
}

void handle_input(int argc, char* argv[], int* payload_size) {
    int x;
    extern char* optarg;

    while ((x = getopt(argc, argv, ":c:")) != -1) {
        switch (x) {
        case 'c':
            *payload_size = atoi(optarg);
            break;
        case ':':
            break;
        }
    }
}

int main(int argc, char* argv[]) {
    stopwatch ethernet_timer;

    unsigned char* input[NUM_PACKETS];
    int writer = 0;
    int done = 0;
    int length = 0;
    int count = 0;
    ESE532_Server server;

    // default is 2k
    int payload_size = PAYLOAD_SIZE;

    // set payload_size if decalred through command line
    handle_input(argc, argv, &payload_size);

    file = (unsigned char*)malloc(sizeof(unsigned char) * 70000000);
    if (file == NULL) {
        //printf("help\n");
    }

    for (int i = 0; i < NUM_PACKETS; i++) {
        input[i] = (unsigned char*)malloc(
            sizeof(unsigned char) * (NUM_ELEMENTS + HEADER));
        if (input[i] == NULL) {
            //std::cout << "aborting " << std::endl;
            return 1;
        }
    }

    server.setup_server(payload_size);

    writer = pipe_depth;
    server.get_packet(input[writer]);

    count++;

    // get packet
    unsigned char* buffer = input[writer];

    // decode
    done = buffer[1] & DONE_BIT_L;
    length = buffer[0] | (buffer[1] << 8);
    length &= ~DONE_BIT_H;

    ethernet_timer.start();
    top_function_packet(&buffer[HEADER], length);
    ethernet_timer.stop();
    offset += length;
    writer++;

    //last message
    while (!done) {
        // reset ring buffer
        if (writer == NUM_PACKETS) {
            writer = 0;
        }

        ethernet_timer.start();
        server.get_packet(input[writer]);
        ethernet_timer.stop();

        count++;

        // get packet
        unsigned char* buffer = input[writer];

        // decode
        done = buffer[1] & DONE_BIT_L;
        length = buffer[0] | (buffer[1] << 8);
        length &= ~DONE_BIT_H;
        ethernet_timer.start();
        top_function_packet(&buffer[HEADER], length);
        ethernet_timer.stop();
        offset += length;
        writer++;
    }

    FILE* outfd = fopen("output_cpu.bin", "wb");
    int bytes_written = fwrite(&file[0], 1, offset, outfd);
    fclose(outfd);

    for (int i = 0; i < NUM_PACKETS; i++) {
        free(input[i]);
    }

    free(file);
    std::cout << "--------------- Key Throughputs ---------------" << std::endl;
    float ethernet_latency = ethernet_timer.latency() / 1000.0;
    float cdc_latency = cdc_timer.latency() / 1000.0;
    float lzw_latency = lzw_timer.latency() / 1000.0;
    float dedup_latency = dedup_timer.latency() / 1000.0;
    float sha_latency = sha_timer.latency() / 1000.0;
    float sha_init_latency = sha_init_timer.latency() / 1000.0;
    float sha_update_latency = sha_update_timer.latency() / 1000.0;
    float sha_final_latency = sha_final_timer.latency() / 1000.0;
    
    float input_throughput = (bytes_written * 8 / 1000000.0) / ethernet_latency; // Mb/s
    float calc_latency = cdc_latency + lzw_latency + dedup_latency + sha_init_latency + sha_update_latency + sha_final_latency ;
    float calc_throughput = (bytes_written * 8 / 1000000.0) / calc_latency; 
    std::cout << "Input Throughput to Encoder: " << input_throughput << " Mb/s."<< " (Latency: " << ethernet_latency << "s)." << std::endl;
    std::cout << "calc Throughput to Encoder: " << calc_throughput << " Mb/s."<< " (Latency: " << calc_latency << "s)." << std::endl;
    std::cout << " CDC Latency: " << cdc_latency << " s" << std::endl;
    std::cout << " sha Latency: " << sha_latency << " s" << std::endl;
    std::cout << " dedup Latency: " << dedup_latency << " s" << std::endl;
    std::cout << " lzw Latency: " << lzw_latency << " s" << std::endl;
    
    std::cout << " sha_init: " << sha_init_latency << " s" << std::endl;
    std::cout << " sha_update: " << sha_update_latency << " s" << std::endl;
    std::cout << "sha_final Latency: " << sha_final_latency << " s" << std::endl;

    return 0;
}






