#include <iostream>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include "ap_int.h"
#include "murmur.h"
#include <time.h>
#include <stdio.h>
#include <bitset>

#define CODE_LENGTH 13

uint16_t to_cl_written; // = 0;
uint16_t to_cl_to_be_written; // = CODE_LENGTH;
uint16_t to_cl_capacity; // = 8;
uint16_t to_cl_idx;

void to_code_len(uint16_t num, unsigned char* op) {
    to_cl_to_be_written = CODE_LENGTH;
    unsigned char temp;

    while (to_cl_to_be_written != 0) {

        if (to_cl_to_be_written >= 8) {

            temp = num >> (to_cl_to_be_written - to_cl_capacity);
            op[to_cl_idx] |= temp;

            to_cl_written = to_cl_capacity;
            to_cl_to_be_written = to_cl_to_be_written - to_cl_written;
            to_cl_capacity = to_cl_capacity - to_cl_written;

            if (to_cl_capacity <= 0) { to_cl_idx++; to_cl_capacity = 8; }

        }

        if (to_cl_to_be_written < 8) {

            temp = num << (8 - to_cl_to_be_written);
            op[to_cl_idx] |= temp;

            to_cl_written = to_cl_to_be_written;
            to_cl_capacity = 8 - to_cl_written;
            to_cl_to_be_written = 0;

            if (to_cl_capacity <= 0) { to_cl_idx++; to_cl_capacity = 8; }

        }

    }

}

uint16_t in_the_table(ap_uint<96> *brute_lzw_table, int table_len, ap_uint<96> ip, uint8_t ip_len) {

    for (int j = 0; j < table_len; j++) {
        ap_uint<120> b_data = brute_lzw_table[j];
        if ((b_data >> 24) == ip) {
            //is in the table
            uint16_t b_code = b_data;
            return b_code;
        }
    }
    return 65535;
}

void encoding(unsigned char* ip, int len, unsigned char* op, int &how_much_written) {

    to_cl_written = 0;
    to_cl_capacity = 8;
    to_cl_idx = 0;

    uint16_t code = 256;
    int tar_pos;
    int tar_ind;
    int brute_table_written = 0;
    int i = 0;
    int c_counter = 0;
    uint32_t p_len = 0, p_plus_c_len = 0; // the largest p or p_plus_c can grow is 15
    
    ap_uint<96> p = 0;
    ap_uint<96> p_plus_c = 0;
    ap_uint<8> c = 0;
    ap_uint<96> brute_lzw_table[4096] = {0};
    ap_uint<96> hash_lzw_table[65536] = {0};

    p = ip[0];
    p_len++;

    while(i < len) {

        p_plus_c = p; // writing p to p+c
        p_plus_c_len = p_len;

        //adding c to p
        if ( (i != len - 1) && (p_plus_c_len < 12) ) {
            c = ip[i + 1];
            p_plus_c = p_plus_c << 8; //making space to add c
            p_plus_c |= c; //adding c to p+c;
            p_plus_c_len++;
        }

        unsigned char p_plus_c_string[12] = { 0 };
        for (int idxxx = 0; idxxx < p_plus_c_len; idxxx++) {
            p_plus_c_string[idxxx] = (p_plus_c >> idxxx*8);
        }

        void *ptr_to_pc = &p_plus_c;
        uint32_t hash = MurmurHash2(ptr_to_pc, p_plus_c_len, 1);
        uint32_t str_hash = MurmurHash2(p_plus_c_string, p_plus_c_len, 1);

        ap_uint<13> hash_b13 = hash;
        ap_uint<16> hash_b16 = hash;
        ap_uint<14> hash_b14 = hash;
        ap_uint<15> hash_b15 = hash;
        ap_uint<96> t_data = hash_lzw_table[hash_b16];

        if(p_plus_c_len > 1){
			if (t_data != 0) {
				ap_uint<96> t_data_string = t_data >> 24;
				if (t_data_string != p_plus_c) { 
					c_counter++;
					uint16_t result = in_the_table(brute_lzw_table, brute_table_written, p_plus_c, p_plus_c_len);
					if(result != 65535){
						p = 0; p = p_plus_c;
						p_len = p_plus_c_len;

					}
					else {
						if (p_len == 1) {
							to_code_len(uint16_t(p), op);
							how_much_written++;
						}
						else {
							uint16_t data_code = 0;
							data_code = t_data;
							to_code_len(data_code, op);
							how_much_written++;
						}
						ap_uint<96> data_to_add = (p_plus_c << 24) | (p_plus_c_len << 16) | (code);
						brute_lzw_table[brute_table_written] = data_to_add;
						brute_table_written++;
						code++;
						p = 0; p = c;
						p_len = 1;
					}

				}
				else {
					p = 0; p = p_plus_c;
					p_len = p_plus_c_len;
				}

			}
			else {
				if (p_len == 1) {
					to_code_len(uint16_t(p), op);
					how_much_written++;
				}
				else {
					uint16_t data_code = 0;
					void *ptr_to_p = &p;
					uint32_t hash = MurmurHash2(ptr_to_p, p_len, 1);
					uint16_t hash_o16 = hash;

					ap_uint<96> h_data = hash_lzw_table[hash_o16];
					data_code = h_data;
					to_code_len(data_code,op);
					how_much_written++;
				}

				ap_uint<96> data_to_add = (p_plus_c << 24) | (p_plus_c_len << 16) | (code);
				hash_lzw_table[hash_b16] = data_to_add;
				code++;
				p = 0; p = c;
				p_len = 1;
			}
    	}
        else{
        	to_code_len(uint16_t(p), op);
        	how_much_written++;
        }
        c = 0;
        i++;
    }
    std::cout << "Collision counter: " << c_counter << std::endl;
    std::cout << "Brute table written = " << brute_table_written << std::endl;
}



